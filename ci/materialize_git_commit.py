"""Materialize strict loose Git commit evidence for the Docker consumer."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import sys
import tempfile
import zlib


_CANDIDATE_SHA = re.compile(r"[0-9a-f]{40}\Z")


def _require_directory(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_dir():
        raise ValueError(f"{label} must be a non-symlink directory")


def _require_detached_head(git_directory: Path, candidate: str) -> None:
    head = git_directory / "HEAD"
    if head.is_symlink() or not head.is_file() or head.read_bytes() != f"{candidate}\\n".encode("ascii"):
        raise ValueError("repository HEAD must be the exact detached candidate")


def _canonical_commit(payload: bytes) -> bytes:
    return b"commit " + str(len(payload)).encode("ascii") + b"\\0" + payload


def _verify_loose_object(path: Path, raw_object: bytes) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError("candidate loose object must be a regular file")
    try:
        observed = zlib.decompress(path.read_bytes())
    except zlib.error as error:
        raise ValueError("candidate loose object is not valid zlib data") from error
    if observed != raw_object:
        raise ValueError("candidate loose object does not match detached HEAD")


def materialize_loose_commit(repository: Path, candidate: str, payload: bytes) -> Path:
    """Write and verify the exact loose commit object needed by the image reader."""
    if not _CANDIDATE_SHA.fullmatch(candidate):
        raise ValueError("candidate must be a lowercase 40-hex SHA-1")
    _require_directory(repository, "repository")
    git_directory = repository / ".git"
    _require_directory(git_directory, "repository .git")
    _require_detached_head(git_directory, candidate)

    raw_object = _canonical_commit(payload)
    if hashlib.sha1(raw_object).hexdigest() != candidate:
        raise ValueError("commit payload does not match detached candidate")

    objects = git_directory / "objects"
    _require_directory(objects, "repository object database")
    object_directory = objects / candidate[:2]
    if object_directory.exists():
        _require_directory(object_directory, "candidate loose-object directory")
    else:
        object_directory.mkdir(mode=0o755)
    target = object_directory / candidate[2:]
    if target.exists():
        _verify_loose_object(target, raw_object)
        return target

    descriptor, temporary_name = tempfile.mkstemp(prefix=".roundwright-", dir=object_directory)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(zlib.compress(raw_object))
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()
    _verify_loose_object(target, raw_object)
    return target


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--candidate", required=True)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    materialize_loose_commit(arguments.repository, arguments.candidate, sys.stdin.buffer.read())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
