"""Persist action context, never credentials, for an explicit approval resume."""
import os
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path

from promptrail.agent.models import Checkpoint
from promptrail.agent.conversation import ConversationCheckpoint
from promptrail.agent.client import SecurityException


def save(path: Path, checkpoint: Checkpoint):
    data = checkpoint.__class__.model_validate_json(checkpoint.model_dump_json()).model_dump_json() + "\n"
    if len(data.encode()) > 4194304:
        raise ValueError("Checkpoint too large")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise ValueError("Checkpoint symlink is not allowed")
    descriptor, temporary = tempfile.mkstemp(prefix=".jev-checkpoint-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load(path: Path):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError("Checkpoint must be an owner-only regular file")
        data = stream.read(4194305)
    if len(data) > 4194304:
        raise ValueError("Checkpoint too large")
    import json
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError("Checkpoint must be an object")
    model = ConversationCheckpoint if value.get("kind") == "conversation" else Checkpoint
    return model.model_validate_json(data)


@contextmanager
def lease(path: Path):
    """One active CLI process per checkpoint; a crash releases its OS lock."""
    import fcntl
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_path = path.with_name(path.name + ".lock")
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError("Invalid checkpoint lock file")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SecurityException("CHECKPOINT_IN_USE") from None
        yield
    finally:
        os.close(descriptor)
