"""Materialize strict loose Git commit evidence for the Docker consumer."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import zlib


_CANDIDATE_SHA = re.compile(r"[0-9a-f]{40}\Z")
_CHECKOUT_MANIFEST = "roundwright-checkout.json"


def _require_directory(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_dir():
        raise ValueError(f"{label} must be a non-symlink directory")


def _require_detached_head(git_directory: Path, candidate: str) -> None:
    head = git_directory / "HEAD"
    if head.is_symlink() or not head.is_file() or head.read_bytes() != f"{candidate}\n".encode("ascii"):
        raise ValueError("repository HEAD must be the exact detached candidate")


def _canonical_commit(payload: bytes) -> bytes:
    return b"commit " + str(len(payload)).encode("ascii") + b"\0" + payload


def _verify_loose_object(path: Path, raw_object: bytes) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError("candidate loose object must be a regular file")
    try:
        observed = zlib.decompress(path.read_bytes())
    except zlib.error as error:
        raise ValueError("candidate loose object is not valid zlib data") from error
    if observed != raw_object:
        raise ValueError("candidate loose object does not match detached HEAD")


def _materialize_loose_object(git_directory: Path, object_sha: str, raw_object: bytes) -> Path:
    if not _CANDIDATE_SHA.fullmatch(object_sha) or hashlib.sha1(raw_object).hexdigest() != object_sha:
        raise ValueError("Git object does not match its exact SHA-1")
    objects = git_directory / "objects"
    _require_directory(objects, "repository object database")
    object_directory = objects / object_sha[:2]
    if object_directory.exists():
        _require_directory(object_directory, "candidate loose-object directory")
    else:
        object_directory.mkdir(mode=0o755)
    target = object_directory / object_sha[2:]
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


def materialize_loose_commit(repository: Path, candidate: str, payload: bytes) -> Path:
    """Write and verify the exact loose commit object needed by the image reader."""
    if not _CANDIDATE_SHA.fullmatch(candidate):
        raise ValueError("candidate must be a lowercase 40-hex SHA-1")
    _require_directory(repository, "repository")
    git_directory = repository / ".git"
    _require_directory(git_directory, "repository .git")
    _require_detached_head(git_directory, candidate)
    return _materialize_loose_object(git_directory, candidate, _canonical_commit(payload))


def _git(repository: Path, *arguments: str) -> bytes:
    try:
        return subprocess.run(
            ["git", "-C", os.fspath(repository), *arguments],
            check=True, capture_output=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise ValueError("repository Git evidence is unavailable") from error


def _tree_entries(repository: Path, candidate: str) -> tuple[str, list[dict[str, str]]]:
    tree_sha = _git(repository, "rev-parse", f"{candidate}^{{tree}}").decode("ascii", "strict").strip()
    if not _CANDIDATE_SHA.fullmatch(tree_sha):
        raise ValueError("candidate tree is invalid")
    entries: list[dict[str, str]] = []
    for record in _git(repository, "ls-tree", "-r", "-z", candidate).split(b"\0"):
        if not record:
            continue
        try:
            metadata, encoded_path = record.split(b"\t", 1)
            mode, object_type, object_sha = metadata.decode("ascii", "strict").split(" ")
            path = encoded_path.decode("utf-8", "strict")
        except (UnicodeDecodeError, ValueError) as error:
            raise ValueError("candidate tracked entry is invalid") from error
        if mode not in {"100644", "100755"} or object_type != "blob" or not _CANDIDATE_SHA.fullmatch(object_sha):
            raise ValueError("candidate tracked entry is unsupported")
        if not path or path.startswith("/") or "\\" in path or any(part in {"", ".", ".."} for part in path.split("/")):
            raise ValueError("candidate tracked path is invalid")
        entries.append({"path": path, "sha1": object_sha})
    if entries != sorted(entries, key=lambda value: value["path"]):
        raise ValueError("candidate tracked entries are not canonical")
    return tree_sha, entries


def _tree_objects(repository: Path, candidate: str, root_tree: str) -> tuple[str, ...]:
    """Return every tree needed by the Git-free recursive tree reader."""

    objects = {root_tree}
    for record in _git(repository, "ls-tree", "-r", "-t", "-z", candidate).split(b"\0"):
        if not record:
            continue
        try:
            metadata, _ = record.split(b"\t", 1)
            mode, object_type, object_sha = metadata.decode("ascii", "strict").split(" ")
        except (UnicodeDecodeError, ValueError) as error:
            raise ValueError("candidate tree entry is invalid") from error
        if object_type == "tree":
            if mode != "040000" or not _CANDIDATE_SHA.fullmatch(object_sha):
                raise ValueError("candidate tree entry is unsupported")
            objects.add(object_sha)
    return tuple(sorted(objects))


def materialize_checkout_evidence(repository: Path, candidate: str) -> Path:
    """Materialize Git-free checked-out tree and tracked-content evidence."""

    commit_payload = _git(repository, "cat-file", "commit", candidate)
    materialize_loose_commit(repository, candidate, commit_payload)
    tree_sha, entries = _tree_entries(repository, candidate)
    for object_sha in _tree_objects(repository, candidate, tree_sha):
        tree_payload = _git(repository, "cat-file", "tree", object_sha)
        raw_tree = b"tree " + str(len(tree_payload)).encode("ascii") + b"\0" + tree_payload
        _materialize_loose_object(repository / ".git", object_sha, raw_tree)
    manifest = repository / ".git" / _CHECKOUT_MANIFEST
    value = {"candidate_sha": candidate, "entries": entries, "tree_sha": tree_sha}
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8") + b"\n"
    descriptor, temporary_name = tempfile.mkstemp(prefix=".roundwright-checkout-", dir=manifest.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
        os.replace(temporary, manifest)
    finally:
        if temporary.exists():
            temporary.unlink()
    return manifest


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--candidate", required=True)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    materialize_checkout_evidence(arguments.repository, arguments.candidate)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
