"""Hermetic coverage for typed configuration and repository boundaries."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.configuration import (
    ConfigurationError,
    ConfigurationSource,
    PreflightMode,
    RepositoryIdentity,
    discover_repository,
    load_configuration,
    preflight,
    user_cache_path,
    user_config_path,
)


class ConfigurationTests(unittest.TestCase):
    def make_repository(self, parent: Path) -> Path:
        root = parent / "repository"
        (root / ".git").mkdir(parents=True)
        return root

    def write_config(self, path: Path, contents: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")

    def test_platform_user_locations_follow_conventions(self) -> None:
        home = Path("/home/example")
        self.assertEqual(user_config_path(platform="linux", home=home), home / ".config/roundwright/config.toml")
        self.assertEqual(user_cache_path(platform="linux", home=home), home / ".cache/roundwright")
        self.assertEqual(user_config_path(platform="darwin", home=home), home / "Library/Application Support/roundwright/config.toml")
        self.assertEqual(user_cache_path(platform="darwin", home=home), home / "Library/Caches/roundwright")
        environment = {"APPDATA": "C:/Users/example/AppData/Roaming", "LOCALAPPDATA": "C:/Users/example/AppData/Local"}
        self.assertEqual(user_config_path(platform="win32", environment=environment, home=home), Path(environment["APPDATA"]) / "Roundwright/config.toml")
        self.assertEqual(user_cache_path(platform="win32", environment=environment, home=home), Path(environment["LOCALAPPDATA"]) / "Roundwright/Cache")
        with self.assertRaisesRegex(ConfigurationError, "unsupported"):
            user_config_path(platform="freebsd", home=home)

    def test_absent_optional_files_allow_config_free_read_only_startup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = load_configuration(cwd=root, home=root / "home", environment={})
        self.assertIsNone(config.repository_root.value)
        self.assertFalse(preflight(config, PreflightMode.READ_ONLY).repository_ready)
        with self.assertRaisesRegex(ConfigurationError, "repository root"):
            preflight(config, PreflightMode.DISPATCH_CAPABLE)

    def test_nearest_repository_is_normalized_and_repository_paths_cannot_escape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.make_repository(Path(temporary))
            nested = root / "nested" / "child"
            nested.mkdir(parents=True)
            repository = discover_repository(nested)
            self.assertEqual(repository, RepositoryIdentity.from_root(root))
            self.assertEqual(repository.resolve_path("nested/file.txt"), root / "nested/file.txt")
            with self.assertRaisesRegex(ConfigurationError, "escapes"):
                repository.resolve_path("../outside.txt")
            with self.assertRaisesRegex(ConfigurationError, "must not be absolute"):
                repository.resolve_path(root / "absolute.txt")

    def test_precedence_and_source_attribution_are_deterministic_and_path_free(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            repository = self.make_repository(workspace)
            user_repository = self.make_repository(workspace / "user")
            env_repository = self.make_repository(workspace / "environment")
            cli_repository = self.make_repository(workspace / "command")
            user = workspace / "user.toml"
            user_cache = workspace / "user-cache"
            repository_cache = workspace / "repository-cache"
            environment_cache = workspace / "environment-cache"
            command_cache = workspace / "command-cache"
            self.write_config(user, f"[roundwright]\nrepository_root = {str(user_repository)!r}\ncache_directory = {str(user_cache)!r}\n")
            self.write_config(repository / ".roundwright.toml", f"[roundwright]\nrepository_root = {str(repository)!r}\ncache_directory = {str(repository_cache)!r}\n")
            config = load_configuration(
                cwd=repository,
                user_config=user,
                environment={"ROUNDWRIGHT_REPOSITORY_ROOT": str(env_repository), "ROUNDWRIGHT_CACHE_DIRECTORY": str(environment_cache)},
                cli_values={"repository_root": cli_repository, "cache_directory": command_cache},
            )
            self.assertEqual(config.repository.root, cli_repository.resolve())
            self.assertEqual(config.cache_directory.value, command_cache)
            self.assertEqual(config.sources["repository_root"], ConfigurationSource.COMMAND_LINE)
            self.assertEqual(config.sources["cache_directory"], ConfigurationSource.COMMAND_LINE)
            self.assertNotIn(str(cli_repository), str(config.sources))

    def test_repository_toml_overrides_user_file_when_user_selects_repository(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            repository = self.make_repository(workspace)
            user = workspace / "user.toml"
            user_cache = workspace / "user-cache"
            repository_cache = workspace / "repository-cache"
            self.write_config(user, f"[roundwright]\nrepository_root = {str(repository)!r}\ncache_directory = {str(user_cache)!r}\n")
            self.write_config(repository / ".roundwright.toml", f"[roundwright]\ncache_directory = {str(repository_cache)!r}\n")
            config = load_configuration(cwd=workspace, user_config=user, environment={})
        self.assertEqual(config.cache_directory.value, repository_cache)
        self.assertEqual(config.cache_directory.source, ConfigurationSource.REPOSITORY)

    def test_explicit_missing_malformed_unknown_and_invalid_configuration_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            missing = workspace / "missing.toml"
            with self.assertRaisesRegex(ConfigurationError, "explicit"):
                load_configuration(cwd=workspace, user_config=missing, environment={})
            malformed = workspace / "malformed.toml"
            self.write_config(malformed, "[roundwright\n")
            with self.assertRaisesRegex(ConfigurationError, "malformed"):
                load_configuration(cwd=workspace, user_config=malformed, environment={})
            unknown = workspace / "unknown.toml"
            self.write_config(unknown, "[roundwright]\nunknown = 'value'\n")
            with self.assertRaisesRegex(ConfigurationError, "unknown"):
                load_configuration(cwd=workspace, user_config=unknown, environment={})
            with self.assertRaisesRegex(ConfigurationError, "Git worktree"):
                load_configuration(cwd=workspace, environment={"ROUNDWRIGHT_REPOSITORY_ROOT": str(workspace)})
            with self.assertRaisesRegex(ConfigurationError, "absolute"):
                load_configuration(cwd=workspace, environment={"ROUNDWRIGHT_CACHE_DIRECTORY": "relative-cache"})

    def test_repository_preflight_requires_a_validated_repository_but_read_only_does_not(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.make_repository(Path(temporary))
            config = load_configuration(cwd=root, environment={})
            report = preflight(config, PreflightMode.DISPATCH_CAPABLE)
            self.assertTrue(report.repository_ready)
