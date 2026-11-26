"""Offline archive provisioning, verified restore, and scoped recovery."""
import argparse
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat

from kig_core.archive import ArchiveConflict, ArchiveDenied, ArchiveUnavailable
from kig_core.guard import Guard
from kig_core.witness import RevocationWitness
from kig_core.worker_archive import ArchivedGuard, open_archive, private_write, provision_archive


def read_credential(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "r", encoding="ascii") as handle:
        mode = os.fstat(handle.fileno()).st_mode
        if not stat.S_ISREG(mode) or mode & 0o077:
            raise ValueError("credential must be a private regular file")
        return handle.read(257).strip()


def existing_guard(state):
    keys = [(state / f"{name}.key").read_bytes() for name in ("audit", "storage", "backup")]
    witness = RevocationWitness(state / "witness" / "checkpoint.sqlite", keys[0])
    return Guard(state / "demo.sqlite", *keys, witness=witness, bootstrap=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    commands = parser.add_subparsers(dest="action", required=True)
    provision = commands.add_parser("provision")
    provision.add_argument("investigator_credential", type=Path)
    commands.add_parser("status")
    restore = commands.add_parser("restore")
    restore.add_argument("snapshot", type=Path)
    authorize = commands.add_parser("authorize-recovery")
    authorize.add_argument("pending_tag")
    authorize.add_argument("principal")
    authorize.add_argument("recovery_credential", type=Path)
    recover = commands.add_parser("recover")
    recover.add_argument("pending_tag")
    recover.add_argument("recovery_credential", type=Path)
    args = parser.parse_args()

    try:
        if args.action == "status":
            archive = open_archive(args.state)
            with archive.verified(write=False) as (_, records, head, _):
                pending = records[-1] if records and records[-1]["state"] == "PENDING" else None
                output = {"head": head, "sequence": len(records),
                          "pending": pending["tag"] if pending else None}
        elif args.action == "provision":
            if args.investigator_credential.exists() or args.investigator_credential.is_symlink():
                raise ValueError("investigator credential file already exists")
            credentials = provision_archive(args.state, existing_guard(args.state))
            private_write(args.investigator_credential, credentials["investigator"].encode())
            output = {"status": "archive_provisioned"}
        else:
            coordinator = ArchivedGuard(existing_guard(args.state), args.state)
            if args.action == "restore":
                coordinator.restore_verified(args.snapshot)
                output = {"status": "verified_snapshot_restored"}
            elif args.action == "authorize-recovery":
                if args.recovery_credential.exists() or args.recovery_credential.is_symlink():
                    raise ValueError("recovery credential file already exists")
                credential = secrets.token_urlsafe(32)
                coordinator.authorize_recovery(
                    args.principal, args.pending_tag, credential,
                    expires_ms=coordinator.archive.now() + 300_000,
                )
                private_write(args.recovery_credential, credential.encode())
                output = {"status": "recovery_authorized", "pending_tag": args.pending_tag}
            else:
                receipt = coordinator.recover(read_credential(args.recovery_credential), args.pending_tag)
                output = {key: receipt[key] for key in ("state", "tag", "producer", "recovery_actor")
                          if key in receipt}
    except (ArchiveConflict, ArchiveDenied, ArchiveUnavailable, OSError, ValueError, sqlite3.Error) as error:
        parser.exit(1, f"Archive operation failed ({type(error).__name__})\n")
    print(json.dumps(output, sort_keys=True))


if __name__ == "__main__":
    main()
