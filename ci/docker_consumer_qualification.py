"""Bind the Docker consumer's hosted qualification to one uploaded wheel.

This helper performs no Docker, registry, provider, GitHub, or deployment
operation.  The hosted workflow supplies the successful Docker command steps;
this file validates their immutable inputs and writes an owner-safe receipt.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


_CANDIDATE = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FROM = re.compile(r"^FROM\s+(python:3\.12\.13-slim-bookworm@sha256:[0-9a-f]{64})$", re.MULTILINE)
_DOCKERFILE = Path("docker/Dockerfile")


def _wheel(dist: Path) -> tuple[str, str]:
    try:
        manifest = json.loads((dist / "package-digest.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("package digest manifest is unavailable") from error
    if type(manifest) is not dict or set(manifest) != {"wheel", "sha256"}:
        raise ValueError("package digest manifest is invalid")
    wheel, digest = manifest["wheel"], manifest["sha256"]
    if type(wheel) is not str or Path(wheel).name != wheel or type(digest) is not str or not _SHA256.fullmatch(digest):
        raise ValueError("package digest manifest is invalid")
    path = dist / wheel
    if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        raise ValueError("package artifact does not match its digest manifest")
    return wheel, digest


def docker_inputs(dist: Path, candidate_sha: str, *, dockerfile: Path | None = None) -> dict[str, str]:
    """Return only the candidate, wheel, and immutable Docker input digests."""

    if type(candidate_sha) is not str or not _CANDIDATE.fullmatch(candidate_sha):
        raise ValueError("candidate SHA is invalid")
    selected_dockerfile = _DOCKERFILE if dockerfile is None else dockerfile
    try:
        source = selected_dockerfile.read_text(encoding="utf-8")
    except OSError as error:
        raise ValueError("Dockerfile is unavailable") from error
    match = _FROM.search(source)
    if match is None or "pip install --no-index --no-deps" not in source or "COPY --chown=65532:65532 dist/${ROUNDWRIGHT_WHEEL}" not in source:
        raise ValueError("Dockerfile does not define the pinned offline consumer")
    wheel, digest = _wheel(dist)
    return {
        "candidate_sha": candidate_sha,
        "wheel": wheel,
        "wheel_sha256": digest,
        "base_image": match.group(1),
        "base_image_digest": match.group(1).split("@", 1)[1],
        "dockerfile_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
    }


def record_qualification(dist: Path, candidate_sha: str, base_image: str, output: Path) -> None:
    """Write a public-safe receipt only after the workflow's commands pass."""

    inputs = docker_inputs(dist, candidate_sha)
    if base_image != inputs["base_image"]:
        raise ValueError("Docker base image does not match the pinned Dockerfile")
    receipt = {
        "schema": "roundwright-docker-consumer-qualification/v1",
        **inputs,
        "checks": {
            "base_image_pull": "passed",
            "offline_build": "passed",
            "installed_doctor": "passed",
            "read_only_mode_preflight": "passed",
            "test_only_mode_preflight": "passed",
        },
    }
    output.write_text(json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("inputs", "record"):
        command = commands.add_parser(name)
        command.add_argument("dist", type=Path)
        command.add_argument("--candidate", required=True)
    commands.choices["inputs"].add_argument("--github-output", type=Path)
    commands.choices["record"].add_argument("--base-image", required=True)
    commands.choices["record"].add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    if arguments.command == "inputs":
        values = docker_inputs(arguments.dist, arguments.candidate)
        rendered = "\n".join(f"{key}={value}" for key, value in values.items()) + "\n"
        if arguments.github_output is None:
            print(rendered, end="")
        else:
            arguments.github_output.write_text(rendered, encoding="utf-8")
    else:
        record_qualification(arguments.dist, arguments.candidate, arguments.base_image, arguments.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
