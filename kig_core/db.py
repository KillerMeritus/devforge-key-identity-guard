"""Shared SQLite connection and transaction policy."""
from contextlib import contextmanager
from contextvars import ContextVar
import sqlite3
import time


deadline = ContextVar("sqlite_deadline", default=None)


@contextmanager
def transaction(path, *, write=True, uri=False, on_rollback=None):
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
        try:
            yield db
        except BaseException as error:
            # Only an observed rollback of a still-open transaction proves
            # noncommit. A failed commit or an already-closed transaction does not.
            if db.in_transaction:
                try:
                    db.rollback()
                except sqlite3.Error as rollback_error:
                    error.add_note(f"SQLite rollback failed: {rollback_error}")
                else:
                    if on_rollback is not None and not db.in_transaction:
                        on_rollback()
            raise
        else:
            db.commit()
    finally:
        db.close()


def enable_wal(path):
    db = sqlite3.connect(path, isolation_level=None, timeout=5)
    try:
        if db.execute("PRAGMA journal_mode").fetchone()[0] != "wal":
            db.execute("PRAGMA journal_mode=WAL")
    finally:
        db.close()
