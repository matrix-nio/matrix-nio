from __future__ import annotations

import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from typing import TextIO


@contextmanager
def atomic_write(path: str | os.PathLike, overwrite: bool = False) -> Iterator[TextIO]:
    """Atomically write a file.

    The data is written to a temporary file in the same directory as
    ``path``, synced to disk, and then moved to ``path``, so a partially
    written file is never visible.

    :param path: Path of the destination file.
    :param overwrite: Whether to replace an existing file. If False, a
        ``FileExistsError`` is raised if the file already exists.

    :returns: Text file object to which data can be written.
    """
    directory = os.path.dirname(path) or "."
    fd, tmp_path = tempfile.mkstemp(dir=directory)
    os.close(fd)

    try:
        with open(tmp_path, "w") as f:
            yield f
            f.flush()
            os.fsync(f.fileno())

        if overwrite:
            os.replace(tmp_path, path)
        else:
            # link() fails if the target exists, making the check-and-move atomic.
            os.link(tmp_path, path)
            os.unlink(tmp_path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
