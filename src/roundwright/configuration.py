"""Versioned, source-auditable runtime configuration.

Configuration is deliberately a pure, fail-closed boundary: it selects an
already-authorized execution profile, but never grants repository authority.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from enum import Enum
from importlib import resources
from pathlib import Path
from typing import Any, Generic, Mapping, TypeVar


class ConfigurationError(ValueError):
    """Raised when configuration cannot safely be understood."""


class ConfigurationSource(str, Enum):
    DEFAULT = "default"
    USER = "user configuration"
    REPOSITORY = "repository configuration"
    ENVIRONMENT = "environment"
    COMMAND_LINE = "command line"


class PreflightMode(str, Enum):
    READ_ONLY = "read-only"
    DISPATCH_CAPABLE = "dispatch-capable"


class ReasoningEffort(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    XHIGH = "xhigh"
    MAX = "max"
    ULTRA = "ultra"


class ReviewMode(str, Enum):
    COMPLETE = "COMPLETE"
    CONVERGING = "CONVERGING"


class FinalFindingsPolicy(str, Enum):
    WORKER_FINAL_REPAIR_THEN_MERGE = "worker-final-repair-then-merge"


class ReviewOutcome(str, Enum):
    PASS = "PASS"
    FINDINGS = "FINDINGS"


class ReviewDisposition(str, Enum):
    EARLY_PASS = "EARLY_PASS"
    NEXT_ROUND = "NEXT_ROUND"
    WORKER_FINAL_REPAIR = "WORKER_FINAL_REPAIR"
    REVIEW_LIMIT_REACHED_WORKER_FINALIZED = "REVIEW_LIMIT_REACHED_WORKER_FINALIZED"


T = TypeVar("T")
_SCHEMA_VERSION = "roundwright-runtime/v1"
_REPOSITORY_CONFIG = ".roundwright.toml"
_EXPECTED_REPOSITORY = "ythdelmar68/roundwright"
_SUPPORTED_MODELS = frozenset({"gpt-5.6-terra", "gpt-5.6-sol"})
_REVIEW_ENVIRONMENT_KEYS = {
    "complete_rounds": "ROUNDWRIGHT_REVIEW_COMPLETE_ROUNDS",
    "max_rounds": "ROUNDWRIGHT_REVIEW_MAX_ROUNDS",
    "max_supervisor_attempts_per_round": "ROUNDWRIGHT_REVIEW_MAX_SUPERVISOR_ATTEMPTS_PER_ROUND",
    "on_final_findings": "ROUNDWRIGHT_REVIEW_ON_FINAL_FINDINGS",
}
_PATH_ENVIRONMENT_KEYS = {
    "repository_root": "ROUNDWRIGHT_REPOSITORY_ROOT",
    "cache_directory": "ROUNDWRIGHT_CACHE_DIRECTORY",
}


@dataclass(frozen=True)
class EffectiveValue(Generic[T]):
    value: T
    source: ConfigurationSource


@dataclass(frozen=True)
class ProviderProfile:
    model: str
    reasoning_effort: ReasoningEffort
    name: str | None = None


@dataclass(frozen=True)
class ReviewPolicy:
    complete_rounds: int
    max_rounds: int
    max_supervisor_attempts_per_round: int
    on_final_findings: FinalFindingsPolicy

    def mode_for_round(self, round_number: int) -> ReviewMode:
        if type(round_number) is not int or round_number < 1 or round_number > self.max_rounds:
            raise ConfigurationError("review round is outside the configured limit")
        return ReviewMode.COMPLETE if round_number <= self.complete_rounds else ReviewMode.CONVERGING

    def disposition(self, round_number: int, outcome: ReviewOutcome, *, worker_finalized: bool = False) -> ReviewDisposition:
        self.mode_for_round(round_number)
        if worker_finalized:
            if outcome is not ReviewOutcome.FINDINGS or round_number != self.max_rounds:
                raise ConfigurationError("final worker repair has no valid review predecessor")
            return ReviewDisposition.REVIEW_LIMIT_REACHED_WORKER_FINALIZED
        if outcome is ReviewOutcome.PASS:
            return ReviewDisposition.EARLY_PASS
        if outcome is not ReviewOutcome.FINDINGS:
            raise ConfigurationError("review outcome is unsupported")
        return ReviewDisposition.WORKER_FINAL_REPAIR if round_number == self.max_rounds else ReviewDisposition.NEXT_ROUND

    def enforce_floor(self, floor: "ReviewPolicy") -> "ReviewPolicy":
        """A trusted policy may only make review stricter, never relax it."""
        if type(floor) is not ReviewPolicy or self.complete_rounds < floor.complete_rounds or self.max_rounds < floor.max_rounds or self.max_supervisor_attempts_per_round < floor.max_supervisor_attempts_per_round:
            raise ConfigurationError("review configuration violates the trusted policy floor")
        if self.on_final_findings is not floor.on_final_findings:
            raise ConfigurationError("review configuration violates the trusted terminal policy")
        return self


@dataclass(frozen=True)
class ResolvedConfigurationBinding:
    """Immutable evidence pinned before dispatch, review, Shadow, or mutation."""

    schema_version: str
    digest: str
    sources: Mapping[str, ConfigurationSource]
    worker_profile_identity: str
    supervisor_profile_identities: tuple[str, ...]

    def require_matches(self, other: "ResolvedConfigurationBinding") -> None:
        if type(other) is not ResolvedConfigurationBinding or self != other:
            raise ConfigurationError("resolved configuration binding has drifted")


@dataclass(frozen=True)
class RepositoryIdentity:
    root: Path

    @classmethod
    def from_root(cls, root: Path) -> "RepositoryIdentity":
        try:
            normalized = root.expanduser().resolve(strict=True)
        except OSError as error:
            raise ConfigurationError("the repository root is unavailable") from error
        if not normalized.is_dir() or not _is_git_worktree_marker(normalized, normalized / ".git"):
            raise ConfigurationError("the repository root is not a Git worktree")
        return cls(normalized)

    @property
    def state_directory(self) -> Path:
        return self.resolve_path(".roundwright")

    def resolve_path(self, relative_path: str | Path) -> Path:
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
    """The resolved runtime snapshot; no later ambient drift can alter it."""

    repository_root: EffectiveValue[Path | None]
    cache_directory: EffectiveValue[Path]
    worker: EffectiveValue[ProviderProfile]
    supervisor_attempt_profiles: EffectiveValue[tuple[ProviderProfile, ...]]
    review: Mapping[str, EffectiveValue[object]]
    schema_version: str = _SCHEMA_VERSION
    repository_configuration_root: Path | None = None

    @property
    def repository(self) -> RepositoryIdentity | None:
        return None if self.repository_root.value is None else RepositoryIdentity.from_root(self.repository_root.value)

    @property
    def review_policy(self) -> ReviewPolicy:
        return ReviewPolicy(
            complete_rounds=self.review["complete_rounds"].value,  # type: ignore[arg-type]
            max_rounds=self.review["max_rounds"].value,  # type: ignore[arg-type]
            max_supervisor_attempts_per_round=self.review["max_supervisor_attempts_per_round"].value,  # type: ignore[arg-type]
            on_final_findings=self.review["on_final_findings"].value,  # type: ignore[arg-type]
        )

    @property
    def sources(self) -> Mapping[str, ConfigurationSource]:
        values = {
            "repository_root": self.repository_root.source,
            "cache_directory": self.cache_directory.source,
            "roles.worker": self.worker.source,
            "roles.supervisor.attempt_profiles": self.supervisor_attempt_profiles.source,
        }
        values.update({f"review.{name}": value.source for name, value in self.review.items()})
        return values

    @property
    def resolved_digest(self) -> str:
        return _digest({
            "schema_version": self.schema_version,
            "worker": _profile_payload(self.worker.value),
            "supervisor_attempt_profiles": [_profile_payload(item) for item in self.supervisor_attempt_profiles.value],
            "paths": {
                "repository_root": None if self.repository_root.value is None else _digest({"path": os.fspath(self.repository_root.value)}),
                "cache_directory": _digest({"path": os.fspath(self.cache_directory.value)}),
            },
            "review": {
                name: value.value.value if isinstance(value.value, Enum) else value.value
                for name, value in sorted(self.review.items())
            },
            "sources": {name: value.value for name, value in sorted(self.sources.items())},
        })

    def pin(self) -> ResolvedConfigurationBinding:
        return ResolvedConfigurationBinding(
            self.schema_version,
            self.resolved_digest,
            dict(self.sources),
            _digest(_profile_payload(self.worker.value)),
            tuple(_digest(_profile_payload(profile)) for profile in self.supervisor_attempt_profiles.value),
        )


@dataclass(frozen=True)
class PreflightReport:
    mode: PreflightMode
    repository_ready: bool


def user_config_path(*, platform: str | None = None, environment: Mapping[str, str] | None = None, home: Path | None = None) -> Path:
    system, env, base_home = sys.platform if platform is None else platform, os.environ if environment is None else environment, Path.home() if home is None else home
    if system.startswith("win"):
        return _environment_directory(env, "APPDATA", base_home / "AppData" / "Roaming") / "Roundwright" / "config.toml"
    if system == "darwin":
        return base_home / "Library" / "Application Support" / "roundwright" / "config.toml"
    if system.startswith("linux"):
        return _environment_directory(env, "XDG_CONFIG_HOME", base_home / ".config") / "roundwright" / "config.toml"
    raise ConfigurationError("the platform is unsupported")


def user_cache_path(*, platform: str | None = None, environment: Mapping[str, str] | None = None, home: Path | None = None) -> Path:
    system, env, base_home = sys.platform if platform is None else platform, os.environ if environment is None else environment, Path.home() if home is None else home
    if system.startswith("win"):
        return _environment_directory(env, "LOCALAPPDATA", base_home / "AppData" / "Local") / "Roundwright" / "Cache"
    if system == "darwin":
        return base_home / "Library" / "Caches" / "roundwright"
    if system.startswith("linux"):
        return _environment_directory(env, "XDG_CACHE_HOME", base_home / ".cache") / "roundwright"
    raise ConfigurationError("the platform is unsupported")


def discover_repository(start: Path | None = None) -> RepositoryIdentity | None:
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


def load_configuration(*, cwd: Path | None = None, environment: Mapping[str, str] | None = None, cli_values: Mapping[str, object] | None = None, user_config: Path | None = None, authoritative_repository_root: Path | None = None, platform: str | None = None, home: Path | None = None) -> Configuration:
    """Resolve defaults < user < authoritative repository < env < CLI.

    Repository configuration is read only from the discovered/validated root;
    no configuration layer may rebind that root or carry authority switches.
    """
    env = os.environ if environment is None else environment
    repository = discover_repository(cwd)
    raw, sources = _default_runtime()[0], {}
    _mark_all(sources, raw, ConfigurationSource.DEFAULT)
    paths: dict[str, EffectiveValue[Path | None]] = {
        "repository_root": EffectiveValue(repository.root if repository else None, ConfigurationSource.DEFAULT),
        "cache_directory": EffectiveValue(user_cache_path(platform=platform, environment=env, home=home), ConfigurationSource.DEFAULT),
    }
    configured_user = user_config_path(platform=platform, environment=env, home=home) if user_config is None else user_config
    user_values = _read_runtime_toml(configured_user, required=user_config is not None)
    _apply_paths(paths, user_values.get("paths", {}), ConfigurationSource.USER)
    _merge_runtime(raw, sources, user_values, ConfigurationSource.USER)
    if paths["repository_root"].value is not None:
        repository = RepositoryIdentity.from_root(paths["repository_root"].value)
    repository_config_root: Path | None = None
    if authoritative_repository_root is None and repository is not None:
        authoritative_repository_root = discover_authoritative_repository(repository)
    if authoritative_repository_root is not None:
        authoritative_root = _validated_authoritative_repository(authoritative_repository_root)
        repository_values = _read_runtime_toml(authoritative_root / _REPOSITORY_CONFIG, required=False)
        _apply_paths(paths, repository_values.get("paths", {}), ConfigurationSource.REPOSITORY, required_repository_root=authoritative_root)
        if repository_values:
            repository_config_root = authoritative_root
        _merge_runtime(raw, sources, repository_values, ConfigurationSource.REPOSITORY)
    _merge_runtime(raw, sources, _environment_updates(env), ConfigurationSource.ENVIRONMENT)
    _apply_paths(paths, _environment_path_updates(env), ConfigurationSource.ENVIRONMENT)
    cli_updates = _cli_updates(cli_values or {})
    _apply_paths(paths, cli_updates.get("paths", {}), ConfigurationSource.COMMAND_LINE)
    _merge_runtime(raw, sources, cli_updates, ConfigurationSource.COMMAND_LINE)
    worker = _parse_profile(raw["roles"]["worker"], name_required=False)
    supervisors = tuple(_parse_profile(value, name_required=True) for value in raw["roles"]["supervisor"]["attempt_profiles"])
    review = _parse_review(raw["review"])
    if len(supervisors) != review.max_supervisor_attempts_per_round:
        raise ConfigurationError("supervisor profile count must equal the configured attempt budget")
    if len({item.name for item in supervisors}) != len(supervisors):
        raise ConfigurationError("supervisor profile names must be unique")
    return Configuration(
        repository_root=paths["repository_root"],
        cache_directory=paths["cache_directory"],  # type: ignore[arg-type]
        worker=EffectiveValue(worker, sources["roles.worker"]),
        supervisor_attempt_profiles=EffectiveValue(supervisors, sources["roles.supervisor.attempt_profiles"]),
        review={name: EffectiveValue(value, sources[f"review.{name}"]) for name, value in review.__dict__.items()},
        repository_configuration_root=repository_config_root,
    )


def preflight(configuration: Configuration, mode: PreflightMode | str) -> PreflightReport:
    try:
        selected = PreflightMode(mode)
    except (TypeError, ValueError) as error:
        raise ConfigurationError("the capability preflight mode is unsupported") from error
    repository = configuration.repository
    if selected is PreflightMode.DISPATCH_CAPABLE and repository is None:
        raise ConfigurationError("dispatch-capable commands require a repository root")
    if selected is PreflightMode.DISPATCH_CAPABLE and configuration.repository_configuration_root is not None and repository is not None and repository.root != configuration.repository_configuration_root:
        raise ConfigurationError("repository configuration does not match the effective repository root")
    return PreflightReport(selected, repository is not None)


def _default_runtime() -> tuple[dict[str, Any], dict[str, ConfigurationSource]]:
    try:
        document = tomllib.loads(resources.files("roundwright").joinpath("runtime-defaults.toml").read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ConfigurationError("packaged runtime defaults are unavailable") from error
    _validate_document(document, complete=True)
    return document, {}


def _read_runtime_toml(path: Path, *, required: bool) -> dict[str, Any]:
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
    _validate_document(document, complete=False)
    return document


def _validated_authoritative_repository(root: Path) -> Path:
    """Accept persistent repository settings only from checked-out origin/main."""
    repository = RepositoryIdentity.from_root(root)
    try:
        branch = subprocess.run(["git", "-C", os.fspath(repository.root), "symbolic-ref", "--quiet", "--short", "HEAD"], check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=5, env=_hermetic_git_environment())
        head = subprocess.run(["git", "-C", os.fspath(repository.root), "rev-parse", "--verify", "HEAD^{commit}"], check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=5, env=_hermetic_git_environment())
        remote = subprocess.run(["git", "-C", os.fspath(repository.root), "rev-parse", "--verify", "refs/remotes/origin/main^{commit}"], check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=5, env=_hermetic_git_environment())
        origin = subprocess.run(["git", "-C", os.fspath(repository.root), "config", "--get", "remote.origin.url"], check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=5, env=_hermetic_git_environment())
        status = subprocess.run(["git", "-C", os.fspath(repository.root), "status", "--porcelain=v1", "--untracked-files=all", "--", _REPOSITORY_CONFIG], check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=5, env=_hermetic_git_environment())
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ConfigurationError("authoritative repository identity is unavailable") from error
    if branch.returncode or head.returncode or remote.returncode or origin.returncode or status.returncode or branch.stdout.strip() != "main" or head.stdout.strip() != remote.stdout.strip() or not _origin_matches(origin.stdout.strip()) or status.stdout.strip():
        raise ConfigurationError("repository configuration is not from authoritative main")
    return repository.root


def discover_authoritative_repository(repository: RepositoryIdentity) -> Path | None:
    """Locate the sole clean local worktree checked out at trusted origin/main."""
    try:
        listed = subprocess.run(["git", "-C", os.fspath(repository.root), "worktree", "list", "--porcelain"], check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=5, env=_hermetic_git_environment())
    except (OSError, subprocess.TimeoutExpired):
        return None
    if listed.returncode:
        return None
    roots = [Path(line.removeprefix("worktree ")) for line in listed.stdout.splitlines() if line.startswith("worktree ")]
    candidates: list[Path] = []
    for root in roots:
        try:
            candidates.append(_validated_authoritative_repository(root))
        except ConfigurationError:
            continue
    if len(candidates) > 1:
        raise ConfigurationError("authoritative repository identity is ambiguous")
    return candidates[0] if candidates else None


def _origin_matches(value: str) -> bool:
    normalized = value.removesuffix(".git").rstrip("/").casefold()
    return normalized.endswith(_EXPECTED_REPOSITORY)


def _validate_document(document: object, *, complete: bool) -> None:
    if type(document) is not dict or set(document) - {"runtime", "paths", "roles", "review"}:
        raise ConfigurationError("configuration contains an unknown section")
    if complete and set(document) != {"runtime", "roles", "review"}:
        raise ConfigurationError("packaged runtime defaults are incomplete")
    runtime = document.get("runtime")
    if runtime is not None:
        if type(runtime) is not dict or set(runtime) != {"schema_version"} or runtime.get("schema_version") != _SCHEMA_VERSION:
            raise ConfigurationError("configuration schema version is unsupported")
    elif complete:
        raise ConfigurationError("configuration schema version is missing")
    paths = document.get("paths")
    if paths is not None:
        if type(paths) is not dict or set(paths) - {"repository_root", "cache_directory"} or not all(isinstance(item, (str, Path)) and str(item).strip() for item in paths.values()):
            raise ConfigurationError("configuration path settings are unsupported")
    roles = document.get("roles")
    if roles is not None:
        if type(roles) is not dict or set(roles) - {"worker", "supervisor"}:
            raise ConfigurationError("configuration contains an unknown role")
        if "worker" in roles:
            _validate_profile_document(roles["worker"], name_required=False)
        if "supervisor" in roles:
            supervisor = roles["supervisor"]
            if type(supervisor) is not dict or set(supervisor) != {"attempt_profiles"} or type(supervisor["attempt_profiles"]) is not list or not supervisor["attempt_profiles"]:
                raise ConfigurationError("supervisor profiles must be replaced as one non-empty list")
            for item in supervisor["attempt_profiles"]:
                _validate_profile_document(item, name_required=True)
        if complete and set(roles) != {"worker", "supervisor"}:
            raise ConfigurationError("packaged runtime roles are incomplete")
    elif complete:
        raise ConfigurationError("packaged runtime roles are missing")
    review = document.get("review")
    fields = {"complete_rounds", "max_rounds", "max_supervisor_attempts_per_round", "on_final_findings"}
    if review is not None:
        if type(review) is not dict or set(review) - fields:
            raise ConfigurationError("configuration contains an unknown review setting")
        if complete and set(review) != fields:
            raise ConfigurationError("packaged review policy is incomplete")
    elif complete:
        raise ConfigurationError("packaged review policy is missing")


def _validate_profile_document(value: object, *, name_required: bool) -> None:
    required = {"model", "reasoning_effort"} | ({"name"} if name_required else set())
    if type(value) is not dict or set(value) != required:
        raise ConfigurationError("role profile data is partial, aliased, or unsupported")


def _merge_runtime(current: dict[str, Any], sources: dict[str, ConfigurationSource], update: dict[str, Any], source: ConfigurationSource) -> None:
    if not update:
        return
    if "roles" in update:
        roles = update["roles"]
        if "worker" in roles:
            current["roles"]["worker"] = roles["worker"]
            sources["roles.worker"] = source
        if "supervisor" in roles:
            current["roles"]["supervisor"] = roles["supervisor"]
            sources["roles.supervisor.attempt_profiles"] = source
    if "review" in update:
        current["review"].update(update["review"])
        for name in update["review"]:
            sources[f"review.{name}"] = source


def _mark_all(sources: dict[str, ConfigurationSource], runtime: dict[str, Any], source: ConfigurationSource) -> None:
    sources["roles.worker"] = source
    sources["roles.supervisor.attempt_profiles"] = source
    for name in runtime["review"]:
        sources[f"review.{name}"] = source


def _environment_updates(environment: Mapping[str, str]) -> dict[str, Any]:
    review = {name: environment[variable] for name, variable in _REVIEW_ENVIRONMENT_KEYS.items() if variable in environment}
    return {} if not review else {"review": review}


def _environment_path_updates(environment: Mapping[str, str]) -> dict[str, object]:
    return {name: environment[key] for name, key in _PATH_ENVIRONMENT_KEYS.items() if key in environment}


def _cli_updates(values: Mapping[str, object]) -> dict[str, Any]:
    update: dict[str, Any] = {}
    for key, value in values.items():
        if key.startswith("review."):
            name = key.removeprefix("review.")
            if name not in _REVIEW_ENVIRONMENT_KEYS:
                raise ConfigurationError("configuration contains an unknown review setting")
            update.setdefault("review", {})[name] = value
        elif key == "roles.worker":
            update.setdefault("roles", {})["worker"] = value
        elif key == "roles.supervisor.attempt_profiles":
            update.setdefault("roles", {})["supervisor"] = {"attempt_profiles": value}
        elif key in {"repository_root", "cache_directory"}:
            update.setdefault("paths", {})[key] = value
        else:
            raise ConfigurationError("CLI override is unsupported")
    _validate_document(update, complete=False)
    return update


def _apply_paths(current: dict[str, EffectiveValue[Path | None]], updates: Mapping[str, object], source: ConfigurationSource, *, required_repository_root: Path | None = None) -> None:
    for name, raw in updates.items():
        if name not in {"repository_root", "cache_directory"} or not isinstance(raw, (str, Path)) or not str(raw).strip():
            raise ConfigurationError("configuration path settings are unsupported")
        value = Path(raw).expanduser()
        if not value.is_absolute():
            raise ConfigurationError("configuration paths must be absolute")
        if name == "repository_root":
            root = RepositoryIdentity.from_root(value).root
            if required_repository_root is not None and root != required_repository_root:
                raise ConfigurationError("repository configuration must not rebind the repository root")
            current[name] = EffectiveValue(root, source)
        else:
            current[name] = EffectiveValue(value, source)


def parse_cli_overrides(values: list[str]) -> dict[str, object]:
    """Parse one-shot ``--set key=value`` values without accepting aliases."""
    parsed: dict[str, object] = {}
    for item in values:
        if type(item) is not str or item.count("=") != 1:
            raise ConfigurationError("CLI override must be one key=value pair")
        key, raw = item.split("=", 1)
        if not key or not raw or key in parsed:
            raise ConfigurationError("CLI override is empty or duplicated")
        if key == "roles.supervisor.attempt_profiles":
            try:
                parsed[key] = json.loads(raw)
            except json.JSONDecodeError as error:
                raise ConfigurationError("supervisor profiles CLI override must be JSON") from error
        elif key == "roles.worker":
            try:
                parsed[key] = json.loads(raw)
            except json.JSONDecodeError as error:
                raise ConfigurationError("worker CLI override must be JSON") from error
        else:
            parsed[key] = raw
    return parsed


def _parse_profile(value: object, *, name_required: bool) -> ProviderProfile:
    _validate_profile_document(value, name_required=name_required)
    assert type(value) is dict
    model, effort = value["model"], value["reasoning_effort"]
    if type(model) is not str or model not in _SUPPORTED_MODELS:
        raise ConfigurationError("the configured model is unsupported")
    try:
        reasoning_effort = ReasoningEffort(effort)
    except (TypeError, ValueError) as error:
        raise ConfigurationError("the configured reasoning effort is unsupported") from error
    name = value.get("name")
    if name_required and (type(name) is not str or not name or any(character.isspace() for character in name)):
        raise ConfigurationError("supervisor profile name is invalid")
    return ProviderProfile(model, reasoning_effort, name)


def _parse_review(value: object) -> ReviewPolicy:
    fields = {"complete_rounds", "max_rounds", "max_supervisor_attempts_per_round", "on_final_findings"}
    if type(value) is not dict or set(value) != fields:
        raise ConfigurationError("review policy is incomplete")
    integers = ("complete_rounds", "max_rounds", "max_supervisor_attempts_per_round")
    parsed: dict[str, int] = {}
    for name in integers:
        raw = value[name]
        try:
            candidate = int(raw) if type(raw) is str and raw.isdecimal() else raw
        except ValueError as error:
            raise ConfigurationError("review limits must be positive integers") from error
        if type(candidate) is not int or candidate <= 0:
            raise ConfigurationError("review limits must be positive integers")
        parsed[name] = candidate
    if parsed["complete_rounds"] > parsed["max_rounds"]:
        raise ConfigurationError("complete review rounds cannot exceed maximum review rounds")
    try:
        terminal = FinalFindingsPolicy(value["on_final_findings"])
    except (TypeError, ValueError) as error:
        raise ConfigurationError("review terminal policy is unsupported") from error
    return ReviewPolicy(**parsed, on_final_findings=terminal)


def _profile_payload(profile: ProviderProfile) -> dict[str, str]:
    result = {"model": profile.model, "reasoning_effort": profile.reasoning_effort.value}
    if profile.name is not None:
        result["name"] = profile.name
    return result


def _digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _environment_directory(environment: Mapping[str, str], name: str, fallback: Path) -> Path:
    raw_value = environment.get(name)
    if raw_value is None:
        return fallback
    if type(raw_value) is not str or not raw_value.strip():
        raise ConfigurationError("a platform configuration directory is invalid")
    directory = Path(raw_value).expanduser()
    if not directory.is_absolute():
        raise ConfigurationError("a platform configuration directory is invalid")
    return directory


def _is_git_worktree_marker(root: Path, marker: Path) -> bool:
    try:
        if _has_repository_selecting_git_environment() or _is_reparse_point(marker):
            return False
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
    try:
        result = subprocess.run(["git", "-C", os.fspath(root), "rev-parse", "--is-inside-work-tree"], check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=5, env=_hermetic_git_environment())
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0 and result.stdout.strip().casefold() == "true"


def _has_repository_selecting_git_environment() -> bool:
    return any(name in os.environ for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR"))


def _hermetic_git_environment() -> dict[str, str]:
    allowed = {"PATH", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP"}
    return {key: value for key, value in os.environ.items() if key.upper() in allowed}


def _is_reparse_point(path: Path) -> bool:
    return path.is_symlink() or path.is_junction()


def _is_complete_git_directory(directory: Path) -> bool:
    return all(((directory / "HEAD").is_file(), (directory / "config").is_file(), (directory / "objects").is_dir(), (directory / "refs").is_dir()))


def _is_bound_linked_worktree(root: Path, marker: Path, git_directory: Path) -> bool:
    commondir, backlink = git_directory / "commondir", git_directory / "gitdir"
    if _is_reparse_point(git_directory) or not git_directory.is_dir() or not (git_directory / "HEAD").is_file() or not commondir.is_file() or not backlink.is_file():
        return False
    common_directory, bound_marker = _read_git_pointer(commondir, git_directory), _read_git_pointer(backlink, git_directory)
    return common_directory is not None and bound_marker is not None and _is_complete_git_directory(common_directory) and bound_marker == marker.resolve(strict=True) and root == marker.parent


def _read_git_pointer(pointer: Path, relative_to: Path) -> Path | None:
    try:
        raw_value = pointer.read_text(encoding="utf-8").strip()
        if not raw_value:
            return None
        target = Path(raw_value)
        return (target if target.is_absolute() else relative_to / target).resolve(strict=True)
    except (OSError, ValueError):
        return None
