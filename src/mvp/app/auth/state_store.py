"""Owner-only durable identity metadata; stores no bearer credentials."""
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def transaction(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)
    connection = sqlite3.connect(path, timeout=5)
    try:
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("BEGIN IMMEDIATE")
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
