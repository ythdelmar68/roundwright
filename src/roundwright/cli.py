"""The minimal public command line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from collections.abc import Sequence

from .deployment import blocked_command_shell_preflight
from .docker_consumer import (
    DockerConsumerContract,
    DockerConsumerError,
    DockerMountCheck,
    DockerMountName,
    DockerMountStatus,
    DockerOperationMode,
    evaluate_docker_consumer,
)
from .doctor import collect_diagnostics, render_diagnostics, render_provider_recovery_status
from .provider_health import CodexFailure
from .identity import UnsafeEntrypointIdentityError, require_safe_entrypoint_identity
from .configuration import ConfigurationError, RepositoryIdentity, discover_repository, load_configuration, parse_cli_overrides, preflight, PreflightMode
from .state import StateError, check_database, initialize


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="roundwright",
        description="Roundwright read-only diagnostics and blocked command shells.",
    )
    subcommands = parser.add_subparsers(dest="command")
    for name, help_text in (("doctor", "report read-only package diagnostics"), ("status", "report deployment modes without dispatching")):
        command = subcommands.add_parser(name, help=help_text)
        command.add_argument("--provider-failure", choices=tuple(item.value for item in CodexFailure), help="render sanitized operator recovery guidance without contacting a provider")
        if name == "doctor":
            command.add_argument("--docker-mode", choices=tuple(item.value for item in DockerOperationMode), help="evaluate one path-free Docker consumer contract")
            command.add_argument("--docker-candidate-sha")
            command.add_argument("--docker-observed-candidate-sha")
            command.add_argument("--docker-package-digest")
            command.add_argument("--docker-observed-package-digest")
            command.add_argument("--docker-base-image-digest")
            command.add_argument("--docker-observed-base-image-digest")
            command.add_argument("--docker-mount", action="append", default=[], metavar="NAME=STATUS")
            command.add_argument("--docker-authority-receipt-digest")
            command.add_argument("--docker-observed-authority-receipt-digest")
            command.add_argument("--docker-observed-authority-receipt-candidate-sha")
            command.add_argument("--docker-authority-inputs-conflict", action="store_true")
    configuration = subcommands.add_parser("config", help="validate or inspect resolved runtime configuration")
    config_commands = configuration.add_subparsers(dest="config_command")
    for name, help_text in (("validate", "validate runtime configuration without writing"), ("show", "show public-safe configuration sources")):
        command = config_commands.add_parser(name, help=help_text)
        command.add_argument("--set", dest="configuration_overrides", action="append", default=[], metavar="KEY=VALUE")
    config_commands.choices["show"].add_argument("--sources", action="store_true", help="show source labels only")
    subcommands.add_parser("init", help="create or verify repository-local state")
    database = subcommands.add_parser("db", help="inspect repository-local database state")
    database.add_subparsers(dest="database_command").add_parser("check", help="read-only database migration check")
    subcommands.add_parser("run-once", help="fail-closed dispatch shell; does not dispatch work")
    subcommands.add_parser("run-daemon", help="fail-closed daemon shell; does not start a daemon")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run a read-only command and return a deterministic process status."""

    parser = build_parser()
    arguments = parser.parse_args(argv)
    if arguments.command == "doctor":
        try:
            docker_consumer = _docker_consumer_report(arguments)
        except DockerConsumerError as error:
            sys.stdout.write(f"roundwright doctor\nDocker consumer: blocked ({error})\nresult: attention required\n")
            return 2
        report = collect_diagnostics(
            sys.argv[0], provider_failure=_provider_failure(arguments), docker_consumer=docker_consumer,
        )
        render_diagnostics(report, sys.stdout)
        return report.exit_code
    if arguments.command == "status":
        return _render_status(sys.stdout, provider_failure=_provider_failure(arguments))
    if arguments.command == "config" and arguments.config_command in {"validate", "show"}:
        return _configuration_command(arguments, sys.stdout)
    if arguments.command == "init":
        return _initialize(sys.stdout)
    if arguments.command == "db" and arguments.database_command == "check":
        return _check_database(sys.stdout)
    if arguments.command in {"run-once", "run-daemon"}:
        decision = blocked_command_shell_preflight()
        _render_blocked_shell(arguments.command, decision.reason, sys.stdout)
        return 3
    else:
        parser.print_help()
        return 0


def _configuration_command(arguments: argparse.Namespace, output: object) -> int:
    try:
        configuration = load_configuration(cwd=Path.cwd(), cli_values=parse_cli_overrides(arguments.configuration_overrides))
    except ConfigurationError as error:
        output.write(f"roundwright config {arguments.config_command}\nresult: blocked\ndetail: {error}\n")  # type: ignore[attr-defined]
        return 2
    output.write(f"roundwright config {arguments.config_command}\nschema: {configuration.schema_version}\ndigest: {configuration.resolved_digest}\n")  # type: ignore[attr-defined]
    if arguments.config_command == "show":
        for name, source in sorted(configuration.sources.items()):
            output.write(f"{name}: {source.value}\n")  # type: ignore[attr-defined]
    output.write("result: valid\n")  # type: ignore[attr-defined]
    return 0


def _repository() -> RepositoryIdentity:
    repository = discover_repository(Path.cwd())
    if repository is None:
        raise ConfigurationError("repository-local state requires a repository root")
    return repository


def _initialize(output: object) -> int:
    try:
        require_safe_entrypoint_identity(sys.argv[0])
        configuration = load_configuration(cwd=Path.cwd())
        preflight(configuration, PreflightMode.READ_ONLY)
        if configuration.repository is not None and configuration.repository_configuration_root is None:
            raise ConfigurationError("repository initialization requires sealed Git entrypoint control")
        repository = (
            RepositoryIdentity.from_root(configuration.repository_configuration_root)
            if configuration.repository_configuration_root is not None
            else configuration.repository
        )
        if repository is None:
            raise ConfigurationError("repository-local state requires a repository root")
        status = initialize(repository)
    except (ConfigurationError, StateError, UnsafeEntrypointIdentityError) as error:
        output.write(f"roundwright init\nresult: blocked\ndetail: {error}\n")  # type: ignore[attr-defined]
        return 2
    if not status.healthy:
        output.write(f"roundwright init\nstate: {status.state}\ndetail: {status.detail}\nresult: blocked\n")  # type: ignore[attr-defined]
        return 2
    output.write(f"roundwright init\nstate: {status.state}\nschema: {status.version}\nresult: ready\n")  # type: ignore[attr-defined]
    return 0


def _check_database(output: object) -> int:
    try:
        status = check_database(_repository())
    except ConfigurationError as error:
        output.write(f"roundwright db check\nstate: unavailable\ndetail: {error}\n")  # type: ignore[attr-defined]
        return 2
    output.write(f"roundwright db check\nstate: {status.state}\nschema: {status.version if status.version is not None else 'none'}\nidentity: {status.identity if status.identity is not None else 'none'}\ndetail: {status.detail}\n")  # type: ignore[attr-defined]
    return 0 if status.healthy else 2


def _render_status(output: object, *, provider_failure: CodexFailure | None = None) -> int:
    """Render deployment status without reading state or authority receipts."""

    output.write("roundwright status\n")  # type: ignore[attr-defined]
    output.write("read-only: available (inspection only)\n")  # type: ignore[attr-defined]
    output.write("test-only: available (no dispatch authority)\n")  # type: ignore[attr-defined]
    output.write("authoritative: unavailable (requires an exact external receipt)\n")  # type: ignore[attr-defined]
    output.write("blocked: active for dispatch command shells\n")  # type: ignore[attr-defined]
    render_provider_recovery_status(provider_failure, output)  # type: ignore[arg-type]
    try:
        status = check_database(_repository())
        output.write(f"local state: {status.state}\n")  # type: ignore[attr-defined]
        output.write(f"schema: {status.version if status.version is not None else 'none'}\n")  # type: ignore[attr-defined]
        output.write(f"state identity: {status.identity if status.identity is not None else 'none'}\n")  # type: ignore[attr-defined]
        output.write(f"detail: {status.detail}\n")  # type: ignore[attr-defined]
        return 0 if status.healthy or status.state == "missing" else 2
    except ConfigurationError:
        output.write("local state: unavailable\n")  # type: ignore[attr-defined]
        return 0


def _provider_failure(arguments: argparse.Namespace) -> CodexFailure | None:
    value = getattr(arguments, "provider_failure", None)
    return None if value is None else CodexFailure(value)


def _docker_consumer_report(arguments: argparse.Namespace):
    """Parse an optional path-free mount contract for ``doctor`` only."""

    mode = getattr(arguments, "docker_mode", None)
    supplied = (
        mode,
        getattr(arguments, "docker_candidate_sha", None),
        getattr(arguments, "docker_observed_candidate_sha", None),
        getattr(arguments, "docker_package_digest", None),
        getattr(arguments, "docker_observed_package_digest", None),
        getattr(arguments, "docker_base_image_digest", None),
        getattr(arguments, "docker_observed_base_image_digest", None),
        tuple(getattr(arguments, "docker_mount", ())),
        getattr(arguments, "docker_authority_receipt_digest", None),
        getattr(arguments, "docker_observed_authority_receipt_digest", None),
        getattr(arguments, "docker_observed_authority_receipt_candidate_sha", None),
        getattr(arguments, "docker_authority_inputs_conflict", False),
    )
    if not any(supplied):
        return None
    if mode is None:
        raise DockerConsumerError("Docker operation mode is required")
    parsed_mounts: list[DockerMountCheck] = []
    for value in arguments.docker_mount:
        name, separator, status = value.partition("=")
        if not separator:
            raise DockerConsumerError("Docker mount must use NAME=STATUS")
        try:
            parsed_mounts.append(DockerMountCheck(DockerMountName(name), DockerMountStatus(status)))
        except ValueError as error:
            raise DockerConsumerError("Docker mount is invalid") from error
    return evaluate_docker_consumer(
        DockerConsumerContract(
            DockerOperationMode(mode), arguments.docker_candidate_sha, arguments.docker_observed_candidate_sha,
            arguments.docker_package_digest, arguments.docker_observed_package_digest,
            arguments.docker_base_image_digest, arguments.docker_observed_base_image_digest, tuple(parsed_mounts),
            arguments.docker_authority_receipt_digest, arguments.docker_observed_authority_receipt_digest,
            arguments.docker_observed_authority_receipt_candidate_sha, arguments.docker_authority_inputs_conflict,
        )
    )


def _render_blocked_shell(command: str, reason: str, output: object) -> None:
    """Render one owner-safe denial before a dispatch command can begin."""

    output.write(f"roundwright {command}\n")  # type: ignore[attr-defined]
    output.write("mode: blocked\n")  # type: ignore[attr-defined]
    output.write(f"authority: {reason}\n")  # type: ignore[attr-defined]
    output.write("dispatch: not started\n")  # type: ignore[attr-defined]
    output.write("result: blocked\n")  # type: ignore[attr-defined]
