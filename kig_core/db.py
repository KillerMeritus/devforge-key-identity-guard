"""Shared SQLite connection and transaction policy."""
from contextlib import contextmanager
import sqlite3


@contextmanager
def transaction(path, *, write=True):
    db = sqlite3.connect(path, isolation_level=None, timeout=5)
    try:
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
        with db:
            yield db
    finally:
        db.close()


def enable_wal(path):
    db = sqlite3.connect(path, isolation_level=None, timeout=5)
    try:
        if db.execute("PRAGMA journal_mode").fetchone()[0] != "wal":
            db.execute("PRAGMA journal_mode=WAL")
    finally:
        db.close()
