"""Durable revocation checkpoint kept outside the file database's restore boundary."""
import hmac
from pathlib import Path
import sqlite3

from .db import transaction


class RevocationWitness:
    def __init__(self, path, key):
        self.uri = Path(path).resolve().as_uri()
        self.key = key

    def proof(self, sequence, tag):
        return hmac.digest(self.key, f"revocation-witness-v1:{sequence}:{tag}".encode(),
                           "sha256").hex()

    def provision(self):
        """Explicit provisioning for a new demo. Workers never initialize this store."""
        with transaction(self.uri + "?mode=rwc", uri=True) as db:
            db.execute("""CREATE TABLE checkpoint (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                sequence INTEGER NOT NULL, tag TEXT NOT NULL, proof TEXT NOT NULL
            )""")
            db.execute("INSERT INTO checkpoint VALUES (1,0,'',?)", (self.proof(0, ""),))

    def current(self, db):
        row = db.execute("SELECT sequence,tag,proof FROM checkpoint WHERE singleton=1").fetchone()
        if row is None or not hmac.compare_digest(row[2], self.proof(row[0], row[1])):
            raise ValueError("invalid revocation checkpoint")
        return row[:2]

    def check(self, audit_db):
        with transaction(self.uri + "?mode=ro", write=False, uri=True) as db:
            sequence, tag = self.current(db)
        if sequence and audit_db.execute("SELECT tag FROM audit WHERE id=?", (sequence,)).fetchone() != (tag,):
            raise ValueError("revocation checkpoint missing from audit database")

    def advance(self, sequence, tag):
        with transaction(self.uri + "?mode=rw", uri=True) as db:
            current, _ = self.current(db)
            if sequence <= current:
                raise sqlite3.IntegrityError("revocation checkpoint must advance")
            db.execute("UPDATE checkpoint SET sequence=?,tag=?,proof=? WHERE singleton=1",
                       (sequence, tag, self.proof(sequence, tag)))
