"""Provision and execute the receipt-bound packaging validation toolchain."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

from validation_toolchain import (
    ToolchainError,
    ValidationToolchainLock,
    create_receipt,
    current_platform,
    file_sha256,
    load_lock,
    toolchain_root,
    verify_receipt,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCK = ROOT / "ci" / "validation-toolchain.lock.toml"
DEFAULT_CACHE = ROOT / ".roundlet" / "validation-tools"


def _run(command: list[str], *, environment: dict[str, str], cwd: Path) -> str:
    result = subprocess.run(command, cwd=cwd, env=environment, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "toolchain command failed").strip().splitlines()[-1]
        raise ToolchainError(f"toolchain provisioning command failed: {detail}")
    return result.stdout.strip()


def _download(url: str, destination: Path, expected_sha256: str) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "roundwright-validation-toolchain/v1"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response, destination.open("wb") as output:
            shutil.copyfileobj(response, output)
    except (OSError, urllib.error.URLError) as error:
        raise ToolchainError("uv artifact download failed") from error
    if file_sha256(destination) != expected_sha256:
        raise ToolchainError("uv artifact digest does not match")


def _safe_member(name: str) -> bool:
    member = PurePosixPath(name.replace("\\", "/"))
    return not member.is_absolute() and ".." not in member.parts and "." not in member.parts


def _extract_uv(archive: Path, archive_format: str, destination: Path) -> Path:
    destination.mkdir()
    if archive_format == "zip":
        with zipfile.ZipFile(archive) as bundle:
            if any(
                not _safe_member(item.filename)
                or stat.S_IFMT(item.external_attr >> 16) == stat.S_IFLNK
                for item in bundle.infolist()
            ):
                raise ToolchainError("uv archive contains an unsafe path")
            bundle.extractall(destination)
    elif archive_format == "tar.gz":
        with tarfile.open(archive, "r:gz") as bundle:
            members = bundle.getmembers()
            if any(not _safe_member(item.name) or not (item.isfile() or item.isdir()) for item in members):
                raise ToolchainError("uv archive contains an unsafe member")
            bundle.extractall(destination, members=members, filter="data")
    else:
        raise ToolchainError("uv archive format is unsupported")
    name = "uv.exe" if os.name == "nt" else "uv"
    candidates = tuple(item for item in destination.rglob(name) if item.is_file())
    if len(candidates) != 1:
        raise ToolchainError("uv archive executable is ambiguous")
    return candidates[0]


def _executable(environment: Path, name: str) -> Path:
    scripts = environment / ("Scripts" if os.name == "nt" else "bin")
    return scripts / (f"{name}.exe" if os.name == "nt" else name)


def _toolchain_environment(root: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "UV_CACHE_DIR": str(root / "uv-cache"),
            "UV_PYTHON_INSTALL_DIR": str(root / "python"),
            "UV_PYTHON_BIN_DIR": str(root / "python-bin"),
            "UV_PYTHON_INSTALL_BIN": "false",
            "UV_PYTHON_INSTALL_REGISTRY": "false",
            "UV_PYTHON_NO_REGISTRY": "1",
            "UV_PYTHON_PREFERENCE": "only-managed",
            "UV_TOOL_DIR": str(root / "uv-tools"),
            "UV_TOOL_BIN_DIR": str(root / "bin"),
        }
    )
    return environment


def _provision(root: Path, lock: ValidationToolchainLock) -> Path:
    identity = current_platform(lock)
    artifact = lock.uv_artifacts[identity.artifact_key]
    root.mkdir(parents=True)
    marker = root / ".provisioning"
    marker.write_text("receipt pending\n", encoding="utf-8")
    environment = _toolchain_environment(root)

    with tempfile.TemporaryDirectory(prefix="download-", dir=root) as temporary:
        work = Path(temporary)
        archive = work / artifact.filename
        _download(artifact.url, archive, artifact.sha256)
        extracted = _extract_uv(archive, artifact.archive_format, work / "extracted")
        uv_directory = root / "uv"
        uv_directory.mkdir()
        uv = uv_directory / ("uv.exe" if os.name == "nt" else "uv")
        shutil.copy2(extracted, uv)
        uv.chmod(uv.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    if _run([str(uv), "--version"], environment=environment, cwd=root).split()[:2] != ["uv", lock.uv_version]:
        raise ToolchainError("provisioned uv version does not match")
    _run(
        [str(uv), "python", "install", lock.python_version, "--no-config"],
        environment=environment,
        cwd=root,
    )
    managed_python_text = _run(
        [str(uv), "python", "find", lock.python_version, "--no-config"],
        environment=environment,
        cwd=root,
    ).splitlines()[-1]
    try:
        managed_python = Path(managed_python_text).resolve(strict=True)
        managed_python.relative_to((root / "python").resolve(strict=True))
    except (FileNotFoundError, ValueError) as error:
        raise ToolchainError("managed Python escaped the toolchain root") from error

    build_environment = root / "build-env"
    pipx_environment = root / "uv-tools" / "pipx"
    for destination in (build_environment, pipx_environment):
        _run(
            [
                str(uv),
                "venv",
                "--python",
                str(managed_python),
                "--no-python-downloads",
                "--no-project",
                "--no-config",
                str(destination),
            ],
            environment=environment,
            cwd=root,
        )

    python = _executable(build_environment, "python")
    pipx_python = _executable(pipx_environment, "python")
    _run(
        [
            str(uv),
            "pip",
            "sync",
            "--python",
            str(python),
            "--require-hashes",
            "--link-mode",
            "copy",
            "--no-python-downloads",
            "--no-config",
            str(lock.build_requirements),
        ],
        environment=environment,
        cwd=root,
    )
    _run(
        [
            str(uv),
            "pip",
            "sync",
            "--python",
            str(pipx_python),
            "--require-hashes",
            "--link-mode",
            "copy",
            "--no-python-downloads",
            "--no-config",
            str(lock.pipx_requirements),
        ],
        environment=environment,
        cwd=root,
    )
    pipx = _executable(pipx_environment, "pipx")

    expected_python = f"CPython {lock.python_version}"
    python_probe = "import platform; print(platform.python_implementation(), platform.python_version())"
    for command in (managed_python, python):
        if _run([str(command), "-I", "-c", python_probe], environment=environment, cwd=root) != expected_python:
            raise ToolchainError("provisioned Python version does not match")
    build_probe = "import pip, setuptools; print(pip.__version__, setuptools.__version__)"
    expected_build = f"{lock.pip_version} {lock.setuptools_version}"
    if _run([str(python), "-I", "-c", build_probe], environment=environment, cwd=root) != expected_build:
        raise ToolchainError("provisioned build tool versions do not match")
    if _run([str(pipx), "--version"], environment=environment, cwd=root) != lock.pipx_version:
        raise ToolchainError("provisioned pipx version does not match")

    document = create_receipt(
        root,
        lock,
        identity,
        uv=uv,
        managed_python=managed_python,
        python=python,
        pipx=pipx,
        managed_python_environment=root / "python",
        build_environment=build_environment,
        pipx_environment=pipx_environment,
    )
    temporary_receipt = root / "receipt.json.tmp"
    temporary_receipt.write_text(
        json.dumps(document, sort_keys=True, indent=2, ensure_ascii=True) + "\n",
        encoding="ascii",
    )
    os.replace(temporary_receipt, root / "receipt.json")
    marker.unlink()
    return root / "receipt.json"


def resolve_receipt(lock_path: Path, cache_root: Path) -> tuple[ValidationToolchainLock, Path]:
    lock = load_lock(lock_path)
    identity = current_platform(lock)
    return lock, toolchain_root(cache_root, lock, identity) / "receipt.json"


def _remove_incomplete_cache(root: Path) -> None:
    target = root.resolve(strict=True)
    removal = Path("\\\\?\\" + str(target)) if os.name == "nt" else target
    if os.name == "nt":
        for current, directories, _files in os.walk(removal, topdown=True):
            for name in tuple(directories):
                child = Path(current) / name
                if child.is_junction():
                    try:
                        child.rmdir()
                    except FileNotFoundError:
                        pass
                    directories.remove(name)

    def handle_error(_function: object, _path: str, error: BaseException) -> None:
        if not isinstance(error, FileNotFoundError):
            raise error

    shutil.rmtree(removal, onexc=handle_error)


def provision(lock_path: Path, cache_root: Path, *, rebuild: bool = False) -> Path:
    lock, receipt = resolve_receipt(lock_path, cache_root)
    identity = current_platform(lock)
    root = receipt.parent
    if receipt.exists():
        verify_receipt(receipt, lock, identity)
        return receipt
    if root.exists():
        if not rebuild:
            raise ToolchainError("incomplete toolchain cache requires explicit --rebuild")
        expected = toolchain_root(cache_root, lock, identity)
        if root.resolve() != expected.resolve() or cache_root.resolve() not in root.resolve().parents:
            raise ToolchainError("refusing to rebuild an unexpected toolchain path")
        _remove_incomplete_cache(root)
    receipt = _provision(root, lock)
    verify_receipt(receipt, lock, identity)
    return receipt


def existing_toolchain(lock_path: Path, cache_root: Path):
    lock, receipt = resolve_receipt(lock_path, cache_root)
    return verify_receipt(receipt, lock, current_platform(lock))


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--cache-root", type=Path, default=DEFAULT_CACHE)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    provision_parser = subparsers.add_parser("provision")
    provision_parser.add_argument("--rebuild", action="store_true")
    subparsers.add_parser("verify")
    execute = subparsers.add_parser("exec-python")
    execute.add_argument("command", nargs=argparse.REMAINDER)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    if arguments.operation == "provision":
        receipt = provision(arguments.lock, arguments.cache_root, rebuild=arguments.rebuild)
        print(receipt)
        return 0
    toolchain = existing_toolchain(arguments.lock, arguments.cache_root)
    if arguments.operation == "verify":
        print(toolchain.receipt)
        return 0
    command = list(arguments.command)
    if command[:1] == ["--"]:
        command.pop(0)
    if not command:
        raise ToolchainError("exec-python requires a command")
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["ROUNDWRIGHT_VALIDATION_TOOLCHAIN_RECEIPT"] = str(toolchain.receipt)
    return subprocess.run([str(toolchain.python), *command], env=environment, check=False).returncode


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ToolchainError as error:
        raise SystemExit(f"validation toolchain error: {error}") from error
