"""Independent local regression checks for ae5fec94, using actual Guard and ArchivedGuard.
Run from repository root: python tests/reviewer_worker_core.py (PYTHONPATH=. if needed).
Only classical AES-GCM file reads are tested. In the review environment, the missing
MLKEM import is shimmed to fail on use, never emulating crypto or counting PQ tests.
"""
import base64
from contextlib import closing
import importlib.util
import json
import multiprocessing as mp
from pathlib import Path
import secrets
import signal
import sqlite3
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

# Explicit review-only import accommodation. No PQ operation is emulated.
if importlib.util.find_spec('cryptography.hazmat.primitives.asymmetric.mlkem') is None:
    mod = types.ModuleType('cryptography.hazmat.primitives.asymmetric.mlkem')
    class UnavailableMLKEM:
        @classmethod
        def from_public_bytes(cls, *args, **kwargs):
            raise AssertionError('ML-KEM unavailable: PQ test must not run')
    mod.MLKEM768PublicKey = UnavailableMLKEM
    sys.modules[mod.__name__] = mod
    print('REVIEW ENVIRONMENT: ML-KEM import shim fails on use; no PQ tests executed', flush=True)

from kig_core.archive import ArchiveUnavailable
from kig_core.guard import Guard
from kig_core.witness import RevocationWitness
from kig_core.worker_archive import ArchivedGuard, provision_archive, open_archive


def copydb(source, target):
    with closing(sqlite3.connect(source)) as a, closing(sqlite3.connect(target)) as b:
        a.backup(b)


def killed_rotation(state, keys, token, approval, phase, pipe):
    def checkpoint(name):
        if name == phase:
            pipe.send(name)
            while True:
                signal.pause()
    witness = RevocationWitness(state/'witness.sqlite', keys[0])
    guard = Guard(state/'demo.sqlite', *keys, witness=witness, checkpoint=checkpoint, bootstrap=False)
    ArchivedGuard(guard, state, 'A').execute(token, 'rotate', 'brief', version=1,
                                           approval=approval, idempotency_key='rotate-1')


class ReviewWorkerCore(unittest.TestCase):
    def setUp(self):
        self.state = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.keys = [secrets.token_bytes(32) for _ in range(3)]
        self.witness = RevocationWitness(self.state/'witness.sqlite', self.keys[0])
        self.witness.provision()
        self.path = self.state/'demo.sqlite'
        self.guard = Guard(self.path, *self.keys, witness=self.witness)
        self.admin = self.guard.enroll('admin', 'admin')
        self.reader = self.guard.enroll('reader')
        self.laptop = self.guard.enroll('laptop')
        self.guard.seed_file('brief', b'reviewer synthetic protected content', 'reader', 'laptop')
        self.approval = self.guard.approve_rotation('admin', 'brief', 1, time.time()+120)
        self.credentials = provision_archive(self.state, self.guard)
        self.a = ArchivedGuard(self.guard, self.state, 'A')
        self.b = ArchivedGuard(self.guard, self.state, 'B')
        self.archive = open_archive(self.state)

    def read(self, worker, version=1, token=None, target='brief'):
        return worker.execute(token or self.reader, 'read', target, version=version)

    def revoke(self):
        return self.a.execute(self.admin, 'revoke', self.guard.digest(self.laptop), idempotency_key='revoke-1')

    def pending(self):
        with self.archive.verified(write=False) as (_, records, _, _):
            return records[-1]

    def snapshot(self, name):
        out=self.state/name; copydb(self.path,out); return out

    def stale_fixture(self):
        self.assertTrue(self.revoke()['allowed'])
        old=self.snapshot('old.sqlite')
        later=self.b.execute(self.reader,'rotate','brief',version=1,idempotency_key='denied-rotation')
        self.assertFalse(later['allowed'])
        current=self.snapshot('current.sqlite')
        copydb(old,self.path)
        return later,current

    def test_postrevocation_restore_blocks_both_and_retains_exact_event(self):
        later,current=self.stale_fixture()
        for worker in (self.a,self.b):
            with self.assertRaises(ArchiveUnavailable): self.read(worker)
            with self.assertRaises(ArchiveUnavailable): worker.execute(self.admin,'evidence',later['request_id'])
        ev=self.archive.retrieve(self.credentials['investigator'],'worker-B',later['request_id'])
        self.assertEqual(json.loads(ev['event_bytes'])['reason'],later['reason'])
        self.assertEqual(ev['lifecycle'],'CONFIRMED')
        self.b.restore_verified(current)
        for worker in (self.a,self.b):
            self.assertEqual(base64.b64decode(self.read(worker)['body']),b'reviewer synthetic protected content')
            self.assertEqual(self.read(worker,token=self.laptop)['reason'],'revoked_device')

    def test_actual_state_tamper_with_genuine_receipts_blocks(self):
        self.assertTrue(self.read(self.a)['allowed'])
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("DELETE FROM grants WHERE actor='reader' AND file='brief'")
        for worker in (self.a,self.b):
            with self.assertRaises(ArchiveUnavailable): self.read(worker)

    def test_mixed_mode_cannot_bypass_stale_archive(self):
        self.stale_fixture()
        with self.assertRaises(ArchiveUnavailable): self.read(self.a)
        # Same underlying service's legacy path, not an HTTP route test.
        baseline = Guard(self.path,*self.keys,witness=self.witness)
        try:
            result=baseline.execute('B',self.reader,'read','brief',version=1)
        except (ArchiveUnavailable,ValueError,sqlite3.Error):
            return
        self.assertFalse(result['allowed'],'legacy worker mode allowed a read against a stale archive-provisioned store')
        self.assertNotIn('body',result)

    def test_retained_revoked_denial_preserves_actual_reason(self):
        self.revoke()
        response=self.read(self.a,token=self.laptop,target='nonexistent')
        self.assertEqual(response['reason'],'revoked_device')
        retained=self.archive.retrieve(self.credentials['investigator'],'worker-A',response['request_id'])
        event=json.loads(retained['event_bytes'])
        self.assertEqual(event['reason'],response['reason'],'archive rewrote actual revoked-device decision')

    def test_known_live_rollback_does_not_permanently_quarantine(self):
        # Fault is injected before Guard.record writes any audit data; the live
        # transaction rolls back under the coordinator lock. No SIGKILL ambiguity.
        with patch.object(self.guard,'record',side_effect=sqlite3.OperationalError('review: known precommit fault')):
            with self.assertRaises((sqlite3.Error,ArchiveUnavailable)):
                self.read(self.a)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM audit').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT count(*) FROM archive_markers').fetchone()[0],0)
        terminal=self.pending()
        if terminal['state']=='PENDING':
            blocked=[]
            for worker in (self.a,self.b):
                try: self.read(worker)
                except ArchiveUnavailable: blocked.append(worker.node)
            print('OBSERVED live rollback:',terminal['state'],'blocked nodes:',blocked,flush=True)
        self.assertEqual(terminal['state'],'ABORTED','verified live rollback left an unresolved global pending record')
        self.assertTrue(self.read(self.b)['allowed'])

    def crash(self,phase):
        self.revoke()
        ctx=mp.get_context('fork'); parent,child=ctx.Pipe(duplex=False)
        process=ctx.Process(target=killed_rotation,args=(self.state,self.keys,self.admin,self.approval,phase,child))
        process.start(); child.close()
        try:
            self.assertTrue(parent.poll(8),f'child did not reach {phase}')
            self.assertEqual(parent.recv(),phase)
            process.kill(); process.join(5)
            self.assertEqual(process.exitcode,-signal.SIGKILL)
        finally:
            if process.is_alive():process.kill();process.join(5)
            parent.close()

    def test_precommit_sigkill_quarantine_and_no_noncommit_recovery(self):
        self.crash('pre')
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT version FROM files WHERE id='brief'").fetchone(),(1,))
        pending=self.pending();self.assertEqual(pending['state'],'PENDING')
        for worker in (self.a,self.b):
            with self.assertRaises(ArchiveUnavailable):self.read(worker)
        with self.assertRaises(ArchiveUnavailable):
            self.b.authorize_recovery('review-recovery',pending['tag'],secrets.token_urlsafe(32),expires_ms=self.archive.now()+10000)

    def test_postcommit_sigkill_recovery_and_revocation_continuity(self):
        self.crash('committed')
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT version FROM files WHERE id='brief'").fetchone(),(2,))
        pending=self.pending();self.assertEqual(pending['state'],'PENDING')
        for worker in (self.a,self.b):
            with self.assertRaises(ArchiveUnavailable):self.read(worker,2)
        recovery=secrets.token_urlsafe(32)
        self.b.authorize_recovery('review-recovery',pending['tag'],recovery,expires_ms=self.archive.now()+10000)
        terminal=self.b.recover(recovery,pending['tag'])
        self.assertEqual(terminal['recovery_actor'],'review-recovery')
        self.assertEqual(terminal['producer'],'worker-A')
        for worker in (self.a,self.b):
            self.assertTrue(self.read(worker,2)['allowed'])
            self.assertEqual(self.read(worker,2,token=self.laptop)['reason'],'revoked_device')
        replay=self.b.execute(self.admin,'rotate','brief',version=1,approval=self.approval,idempotency_key='rotate-1')
        self.assertEqual(replay['version'],2)
        self.assertEqual(replay['request_id'],pending['operation_id'])

if __name__=='__main__':unittest.main(verbosity=2)
