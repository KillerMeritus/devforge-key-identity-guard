"""Shared SQLite connection and transaction policy."""
from contextlib import contextmanager
from contextvars import ContextVar
import sqlite3
import time


deadline = ContextVar("sqlite_deadline", default=None)


@contextmanager
def transaction(path, *, write=True, uri=False):
    end = deadline.get()
    remaining = 5 if end is None else end - time.monotonic()
    if remaining <= 0:
        raise sqlite3.OperationalError("transaction deadline exhausted")
    db = sqlite3.connect(path, isolation_level=None, timeout=remaining, uri=uri)
    try:
        if end is not None:
            db.set_progress_handler(lambda: time.monotonic() >= end, 1000)
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
