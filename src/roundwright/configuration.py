"""Typed, fail-closed configuration and repository discovery.

This module deliberately performs filesystem reads only.  It gives later
commands one deterministic configuration boundary without granting any
dispatch authority.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Generic, Mapping, TypeVar


class ConfigurationError(ValueError):
    """Raised when configuration cannot be safely understood."""


class ConfigurationSource(str, Enum):
    """Public-safe attribution for an effective setting."""

    DEFAULT = "default"
    USER = "user configuration"
    REPOSITORY = "repository configuration"
    ENVIRONMENT = "environment"
    COMMAND_LINE = "command line"


class PreflightMode(str, Enum):
    """The requirements of a command before it is allowed to start."""

    READ_ONLY = "read-only"
    DISPATCH_CAPABLE = "dispatch-capable"


class ReasoningEffort(str, Enum):
    """Supported deterministic reasoning budgets, without provider probing."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    XHIGH = "xhigh"
    MAX = "max"
    ULTRA = "ultra"


T = TypeVar("T")


@dataclass(frozen=True)
class EffectiveValue(Generic[T]):
    """A typed setting together with a non-sensitive source label."""

    value: T
    source: ConfigurationSource


@dataclass(frozen=True)
class RepositoryIdentity:
    """A normalized local repository root.

    The path is intentionally not a display identifier.  User-facing code
    should use ``Configuration.sources`` rather than rendering this object.
    """

    root: Path

    @classmethod
    def from_root(cls, root: Path) -> "RepositoryIdentity":
        try:
            normalized = root.expanduser().resolve(strict=True)
        except OSError as error:
            raise ConfigurationError("the repository root is unavailable") from error
        if not normalized.is_dir() or not _is_git_worktree_marker(normalized, normalized / ".git"):
            raise ConfigurationError("the repository root is not a Git worktree")
        return cls(root=normalized)

    @property
    def state_directory(self) -> Path:
        """Return the normalized repository-local state location without creating it."""

        return self.resolve_path(".roundwright")

    def resolve_path(self, relative_path: str | Path) -> Path:
        """Resolve one repository-relative path without permitting escape."""

        candidate = Path(relative_path)
        if candidate.is_absolute():
            raise ConfigurationError("repository-relative paths must not be absolute")
        try:
            resolved = (self.root / candidate).resolve(strict=False)
            resolved.relative_to(self.root)
        except (OSError, ValueError) as error:
            raise ConfigurationError("repository-relative path escapes the repository") from error
        return resolved


@dataclass(frozen=True)
class Configuration:
    """The effective typed settings required by the early runtime boundary."""

    repository_root: EffectiveValue[Path | None]
    cache_directory: EffectiveValue[Path]
    model: EffectiveValue[str]
    reasoning_effort: EffectiveValue[ReasoningEffort]

    @property
    def repository(self) -> RepositoryIdentity | None:
        if self.repository_root.value is None:
            return None
        return RepositoryIdentity.from_root(self.repository_root.value)

    @property
    def sources(self) -> Mapping[str, ConfigurationSource]:
        """Return source attribution only; never paths or setting contents."""

        return {
            "repository_root": self.repository_root.source,
            "cache_directory": self.cache_directory.source,
            "model": self.model.source,
            "reasoning_effort": self.reasoning_effort.source,
        }


@dataclass(frozen=True)
class PreflightReport:
    """A capability-specific, path-free preflight result."""

    mode: PreflightMode
    repository_ready: bool


_PATH_KEYS = frozenset({"repository_root", "cache_directory"})
_MODEL_KEYS = frozenset({"model", "reasoning_effort"})
_KEYS = _PATH_KEYS | _MODEL_KEYS
_ENVIRONMENT_KEYS = {
    "repository_root": "ROUNDWRIGHT_REPOSITORY_ROOT",
    "cache_directory": "ROUNDWRIGHT_CACHE_DIRECTORY",
    "model": "ROUNDWRIGHT_MODEL",
    "reasoning_effort": "ROUNDWRIGHT_REASONING_EFFORT",
}
_REPOSITORY_CONFIG = ".roundwright.toml"
_DEFAULT_MODEL = "gpt-5.6-terra"
_SUPPORTED_MODELS = frozenset({_DEFAULT_MODEL, "gpt-5.6-sol"})


def _is_git_worktree_marker(root: Path, marker: Path) -> bool:
    """Accept only a complete Git directory or a bound linked worktree."""

    try:
        if marker.is_dir():
            return _is_complete_git_directory(marker) and _git_confirms_worktree(root)
        if not marker.is_file():
            return False
        pointer = marker.read_text(encoding="utf-8").strip()
        if not pointer.startswith("gitdir:"):
            return False
        target = Path(pointer.removeprefix("gitdir:").strip())
        if not target.is_absolute():
            target = marker.parent / target
        normalized_target = target.resolve(strict=True)
        return _is_bound_linked_worktree(root, marker, normalized_target) and _git_confirms_worktree(root)
    except (OSError, ValueError):
        return False


def _git_confirms_worktree(root: Path) -> bool:
    """Use Git's own read-only identity check after structural validation."""

    try:
        result = subprocess.run(
            ["git", "-C", os.fspath(root), "rev-parse", "--is-inside-work-tree"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0 and result.stdout.strip().casefold() == "true"


def _is_complete_git_directory(directory: Path) -> bool:
    """Reject partial filesystem structures that merely resemble Git metadata."""

    return all(
        (
            (directory / "HEAD").is_file(),
            (directory / "config").is_file(),
            (directory / "objects").is_dir(),
            (directory / "refs").is_dir(),
        )
    )


def _is_bound_linked_worktree(root: Path, marker: Path, git_directory: Path) -> bool:
    """Verify both directions of a linked-worktree identity binding."""

    commondir = git_directory / "commondir"
    backlink = git_directory / "gitdir"
    if not git_directory.is_dir() or not (git_directory / "HEAD").is_file():
        return False
    if not commondir.is_file() or not backlink.is_file():
        return False
    common_directory = _read_git_pointer(commondir, git_directory)
    bound_marker = _read_git_pointer(backlink, git_directory)
    if common_directory is None or bound_marker is None:
        return False
    return (
        _is_complete_git_directory(common_directory)
        and bound_marker == marker.resolve(strict=True)
        and root == marker.parent
    )


def _read_git_pointer(pointer: Path, relative_to: Path) -> Path | None:
    """Read one Git pointer file without exposing its private filesystem value."""

    try:
        raw_value = pointer.read_text(encoding="utf-8").strip()
        if not raw_value:
            return None
        target = Path(raw_value)
        if not target.is_absolute():
            target = relative_to / target
        return target.resolve(strict=True)
    except (OSError, ValueError):
        return None


def user_config_path(
    *,
    platform: str | None = None,
    environment: Mapping[str, str] | None = None,
    home: Path | None = None,
) -> Path:
    """Return the conventional per-user configuration location."""

    system = sys.platform if platform is None else platform
    env = os.environ if environment is None else environment
    base_home = Path.home() if home is None else home
    if system.startswith("win"):
        return _environment_directory(env, "APPDATA", base_home / "AppData" / "Roaming") / "Roundwright" / "config.toml"
    if system == "darwin":
        return base_home / "Library" / "Application Support" / "roundwright" / "config.toml"
    if system.startswith("linux"):
        return _environment_directory(env, "XDG_CONFIG_HOME", base_home / ".config") / "roundwright" / "config.toml"
    raise ConfigurationError("the platform is unsupported")


def user_cache_path(
    *,
    platform: str | None = None,
    environment: Mapping[str, str] | None = None,
    home: Path | None = None,
) -> Path:
    """Return the conventional per-user cache location without creating it."""

    system = sys.platform if platform is None else platform
    env = os.environ if environment is None else environment
    base_home = Path.home() if home is None else home
    if system.startswith("win"):
        return _environment_directory(env, "LOCALAPPDATA", base_home / "AppData" / "Local") / "Roundwright" / "Cache"
    if system == "darwin":
        return base_home / "Library" / "Caches" / "roundwright"
    if system.startswith("linux"):
        return _environment_directory(env, "XDG_CACHE_HOME", base_home / ".cache") / "roundwright"
    raise ConfigurationError("the platform is unsupported")


def _environment_directory(
    environment: Mapping[str, str], name: str, fallback: Path
) -> Path:
    raw_value = environment.get(name)
    if raw_value is None:
        return fallback
    if not isinstance(raw_value, str) or not raw_value.strip():
        raise ConfigurationError("a platform configuration directory is invalid")
    directory = Path(raw_value).expanduser()
    if not directory.is_absolute():
        raise ConfigurationError("a platform configuration directory is invalid")
    return directory


def discover_repository(start: Path | None = None) -> RepositoryIdentity | None:
    """Find the nearest validated worktree without consulting Git commands."""

    try:
        current = (Path.cwd() if start is None else start).expanduser().resolve(strict=True)
    except OSError as error:
        raise ConfigurationError("the starting directory is unavailable") from error
    if not current.is_dir():
        raise ConfigurationError("the starting directory is not a directory")
    for directory in (current, *current.parents):
        if (directory / ".git").exists():
            return RepositoryIdentity.from_root(directory)
    return None


def load_configuration(
    *,
    cwd: Path | None = None,
    environment: Mapping[str, str] | None = None,
    cli_values: Mapping[str, str | Path | ReasoningEffort | None] | None = None,
    user_config: Path | None = None,
    platform: str | None = None,
    home: Path | None = None,
) -> Configuration:
    """Load settings using defaults < user < repository < environment < CLI.

    Default user and repository files are optional.  A caller that passes a
    ``user_config`` explicitly asks for that file and therefore gets a
    fail-closed error if it is absent or malformed.
    """

    env = os.environ if environment is None else environment
    discovered = discover_repository(cwd)
    values: dict[str, EffectiveValue[object]] = {
        "repository_root": EffectiveValue(
            discovered.root if discovered is not None else None, ConfigurationSource.DEFAULT
        ),
        "cache_directory": EffectiveValue(
            user_cache_path(platform=platform, environment=env, home=home),
            ConfigurationSource.DEFAULT,
        ),
        "model": EffectiveValue(_DEFAULT_MODEL, ConfigurationSource.DEFAULT),
        "reasoning_effort": EffectiveValue(
            ReasoningEffort.MEDIUM, ConfigurationSource.DEFAULT
        ),
    }

    configured_user_path = user_config_path(platform=platform, environment=env, home=home) if user_config is None else user_config
    _apply_layer(
        values,
        _read_toml(configured_user_path, required=user_config is not None),
        ConfigurationSource.USER,
    )

    repository_path = values["repository_root"].value
    if repository_path is not None:
        repository = RepositoryIdentity.from_root(repository_path)
        _apply_layer(
            values,
            _read_toml(repository.root / _REPOSITORY_CONFIG, required=False),
            ConfigurationSource.REPOSITORY,
        )

    _apply_layer(
        values,
        {key: env[name] for key, name in _ENVIRONMENT_KEYS.items() if name in env},
        ConfigurationSource.ENVIRONMENT,
    )
    _apply_layer(values, cli_values or {}, ConfigurationSource.COMMAND_LINE)

    if values["repository_root"].value is not None:
        RepositoryIdentity.from_root(values["repository_root"].value)
    return Configuration(**values)


def preflight(
    configuration: Configuration, mode: PreflightMode | str
) -> PreflightReport:
    """Validate only the requirements appropriate to the requested capability."""

    try:
        validated_mode = PreflightMode(mode)
    except (TypeError, ValueError) as error:
        raise ConfigurationError("the capability preflight mode is unsupported") from error
    repository = configuration.repository
    if validated_mode is PreflightMode.DISPATCH_CAPABLE and repository is None:
        raise ConfigurationError("dispatch-capable commands require a repository root")
    return PreflightReport(mode=validated_mode, repository_ready=repository is not None)


def _read_toml(path: Path, *, required: bool) -> Mapping[str, str]:
    if not path.exists():
        if required:
            raise ConfigurationError("an explicit configuration file is unavailable")
        return {}
    if not path.is_file():
        raise ConfigurationError("a configuration location is not a regular file")
    try:
        with path.open("rb") as handle:
            document = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ConfigurationError("configuration TOML is malformed or unreadable") from error
    if set(document) != {"roundwright"} or not isinstance(document["roundwright"], dict):
        raise ConfigurationError("configuration must contain only a [roundwright] table")
    values = document["roundwright"]
    if set(values) - _KEYS:
        raise ConfigurationError("configuration contains an unknown setting")
    if not all(isinstance(value, str) and value.strip() for value in values.values()):
        raise ConfigurationError("configuration values must be non-empty strings")
    return values


def _apply_layer(
    current: dict[str, EffectiveValue],
    updates: Mapping[str, str | Path | ReasoningEffort | None],
    source: ConfigurationSource,
) -> None:
    unknown = set(updates) - _KEYS
    if unknown:
        raise ConfigurationError("configuration contains an unknown setting")
    configured_model_keys = set(updates) & _MODEL_KEYS
    if configured_model_keys and configured_model_keys != _MODEL_KEYS:
        raise ConfigurationError("model and reasoning effort must be configured together")
    for key, raw_value in updates.items():
        if raw_value is None:
            continue
        if key in _PATH_KEYS:
            if not isinstance(raw_value, (str, Path)):
                raise ConfigurationError("configuration path values must be paths")
            if isinstance(raw_value, str) and not raw_value.strip():
                raise ConfigurationError("configuration path values must be non-empty")
            value = Path(raw_value).expanduser()
            if not value.is_absolute():
                raise ConfigurationError("configuration paths must be absolute")
        elif key == "model":
            if not isinstance(raw_value, str) or raw_value not in _SUPPORTED_MODELS:
                raise ConfigurationError("the configured model is unsupported")
            value = raw_value
        else:
            try:
                value = ReasoningEffort(raw_value)
            except (TypeError, ValueError) as error:
                raise ConfigurationError("the configured reasoning effort is unsupported") from error
        current[key] = EffectiveValue(value, source)
