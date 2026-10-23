"""Read explicitly selected owner-only model settings without shell evaluation."""
import io
import os
import stat

from dotenv import dotenv_values


def model_values(path):
    if path is None:
        return {}
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError("Model environment file must be owner-only")
        data = stream.read(65537)
    if len(data) > 65536:
        raise ValueError("Model environment file too large")
    return dict(dotenv_values(stream=io.StringIO(data.decode()), interpolate=False))
