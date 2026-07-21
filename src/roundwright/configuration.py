"""Typed, fail-closed configuration and repository discovery.

This module deliberately performs filesystem reads only.  It gives later
commands one deterministic configuration boundary without granting any
dispatch authority.
"""

from __future__ import annotations

import os
import sys
import tomllib
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Mapping


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


@dataclass(frozen=True)
class EffectiveValue:
    """A typed setting together with a non-sensitive source label."""

    value: Path | None
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
        if not normalized.is_dir() or not (normalized / ".git").exists():
            raise ConfigurationError("the repository root is not a Git worktree")
        return cls(root=normalized)

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

    repository_root: EffectiveValue
    cache_directory: EffectiveValue

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
        }


@dataclass(frozen=True)
class PreflightReport:
    """A capability-specific, path-free preflight result."""

    mode: PreflightMode
    repository_ready: bool


_KEYS = frozenset({"repository_root", "cache_directory"})
_ENVIRONMENT_KEYS = {
    "repository_root": "ROUNDWRIGHT_REPOSITORY_ROOT",
    "cache_directory": "ROUNDWRIGHT_CACHE_DIRECTORY",
}
_REPOSITORY_CONFIG = ".roundwright.toml"


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
        return Path(env.get("APPDATA", base_home / "AppData" / "Roaming")) / "Roundwright" / "config.toml"
    if system == "darwin":
        return base_home / "Library" / "Application Support" / "roundwright" / "config.toml"
    if system.startswith("linux"):
        return Path(env.get("XDG_CONFIG_HOME", base_home / ".config")) / "roundwright" / "config.toml"
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
        return Path(env.get("LOCALAPPDATA", base_home / "AppData" / "Local")) / "Roundwright" / "Cache"
    if system == "darwin":
        return base_home / "Library" / "Caches" / "roundwright"
    if system.startswith("linux"):
        return Path(env.get("XDG_CACHE_HOME", base_home / ".cache")) / "roundwright"
    raise ConfigurationError("the platform is unsupported")


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
    cli_values: Mapping[str, str | Path | None] | None = None,
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
    values: dict[str, EffectiveValue] = {
        "repository_root": EffectiveValue(
            discovered.root if discovered is not None else None, ConfigurationSource.DEFAULT
        ),
        "cache_directory": EffectiveValue(
            user_cache_path(platform=platform, environment=env, home=home),
            ConfigurationSource.DEFAULT,
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


def preflight(configuration: Configuration, mode: PreflightMode) -> PreflightReport:
    """Validate only the requirements appropriate to the requested capability."""

    repository = configuration.repository
    if mode is PreflightMode.DISPATCH_CAPABLE and repository is None:
        raise ConfigurationError("dispatch-capable commands require a repository root")
    return PreflightReport(mode=mode, repository_ready=repository is not None)


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
    updates: Mapping[str, str | Path | None],
    source: ConfigurationSource,
) -> None:
    unknown = set(updates) - _KEYS
    if unknown:
        raise ConfigurationError("configuration contains an unknown setting")
    for key, raw_value in updates.items():
        if raw_value is None:
            continue
        if not isinstance(raw_value, (str, Path)):
            raise ConfigurationError("configuration values must be paths")
        if isinstance(raw_value, str) and not raw_value.strip():
            raise ConfigurationError("configuration values must be non-empty")
        value = Path(raw_value).expanduser()
        if not value.is_absolute():
            raise ConfigurationError("configuration paths must be absolute")
        current[key] = EffectiveValue(value, source)
