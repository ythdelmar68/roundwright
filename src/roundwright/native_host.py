"""Hermetic native-host lifecycle parity for receipt-bound deployments.

The native host does not install software, start a scheduler, or run a child
process. It models the small product-owned boundary those integrations must
obey: installation admits only an already-claimed authority, a scheduler wake
uses the same one-shot admission path as a direct invocation, and one host
cannot have two active process lifecycles. Credential, provider, repository,
and GitHub capabilities remain outside this module.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from threading import RLock

from .deployment_handoff import (
    DeploymentAuthorityHandoffCoordinator,
    DeploymentAuthorityHandoffReceipt,
    DeploymentAuthorityIdentity,
)


class NativeHostError(ValueError):
    """Raised when a native-host value cannot be safely represented."""


class NativeHostState(str, Enum):
    """The complete process-local lifecycle of one installed host."""

    IDLE = "idle"
    RUNNING = "running"
    STOPPED = "stopped"


class InvocationSource(str, Enum):
    """The two equivalent admission routes exposed to a native host."""

    ONE_SHOT = "one-shot"
    SCHEDULER_WAKE = "scheduler-wake"


_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")


def _require_fingerprint(value: object, description: str) -> str:
    if type(value) is not str or not _FINGERPRINT.fullmatch(value):
        raise NativeHostError(f"{description} fingerprint is invalid")
    return value


def _require_process_id(value: object) -> str:
    if type(value) is not str or not _TOKEN.fullmatch(value):
        raise NativeHostError("native host process identity is invalid")
    return value


@dataclass(frozen=True)
class NativeHostInstallation:
    """An opaque installed-host identity bound to one authority receipt."""

    installation_fingerprint: str
    identity: DeploymentAuthorityIdentity
    receipt: DeploymentAuthorityHandoffReceipt

    def __post_init__(self) -> None:
        _require_fingerprint(self.installation_fingerprint, "native host installation")
        if (
            type(self.identity) is not DeploymentAuthorityIdentity
            or type(self.receipt) is not DeploymentAuthorityHandoffReceipt
            or self.receipt.identity != self.identity
        ):
            raise NativeHostError("native host installation is not bound to its authority")


@dataclass(frozen=True)
class NativeHostDecision:
    """A public-safe installation, admission, or lifecycle disposition."""

    accepted: bool
    reason: str
    installation_fingerprint: str | None = None
    receipt_fingerprint: str | None = None
    process_id: str | None = None


class NativeHost:
    """Serialize one host's installation and process lifecycle in memory.

    A production native host may persist equivalent machine truth, but it must
    not use this process-local object as a source of authority. Each action
    revalidates the already-claimed receipt through the handoff coordinator.
    """

    def __init__(self, coordinator: DeploymentAuthorityHandoffCoordinator, installation: NativeHostInstallation) -> None:
        if type(coordinator) is not DeploymentAuthorityHandoffCoordinator or type(installation) is not NativeHostInstallation:
            raise NativeHostError("native host installation is invalid")
        self._coordinator = coordinator
        self._installation = installation
        self._lock = RLock()
        self._state = NativeHostState.IDLE
        self._active_process_id: str | None = None
        self._consumed_process_ids: set[str] = set()

    @property
    def state(self) -> NativeHostState:
        with self._lock:
            return self._state

    @property
    def installation(self) -> NativeHostInstallation:
        return self._installation

    def run_once(self, process_id: str, *, now: object) -> NativeHostDecision:
        """Admit one direct process using the same receipt check as a wake."""

        return self._start(process_id, InvocationSource.ONE_SHOT, now=now)

    def request_scheduler_wake(self, process_id: str, *, now: object) -> NativeHostDecision:
        """Translate an authorized scheduler request into one normal start.

        The scheduler cannot claim, renew, install, or transfer authority; it
        merely supplies the source of an invocation that must pass the exact
        same admission check as :meth:`run_once`.
        """

        process = _require_process_id(process_id)
        wake = self._coordinator.request_scheduler_wakeup(
            self._installation.identity, self._installation.receipt, now=now
        )
        if not wake.requested:
            return self._denied(wake.reason, process)
        return self._start(process, InvocationSource.SCHEDULER_WAKE, now=now)

    def complete(self, process_id: str) -> NativeHostDecision:
        """Finish exactly the active process and return the host to idle."""

        process = _require_process_id(process_id)
        with self._lock:
            if self._state is NativeHostState.STOPPED:
                return self._denied("native host is stopped", process)
            if self._state is not NativeHostState.RUNNING or self._active_process_id != process:
                return self._denied("native host process is not active", process)
            self._active_process_id = None
            self._state = NativeHostState.IDLE
            return self._accepted("native host process completed", process)

    def stop(self) -> NativeHostDecision:
        """Stop only an idle host; a running process must reconcile first."""

        with self._lock:
            if self._state is NativeHostState.STOPPED:
                return self._accepted("native host is already stopped", None)
            if self._state is NativeHostState.RUNNING:
                return self._denied("native host has an active process", self._active_process_id)
            self._state = NativeHostState.STOPPED
            return self._accepted("native host stopped", None)

    def _start(self, process_id: str, source: InvocationSource, *, now: object) -> NativeHostDecision:
        process = _require_process_id(process_id)
        if type(source) is not InvocationSource:
            raise NativeHostError("native host invocation source is invalid")
        with self._lock:
            if self._state is NativeHostState.STOPPED:
                return self._denied("native host is stopped", process)
            if self._state is NativeHostState.RUNNING:
                return self._denied("native host already has an active process", process)
            if process in self._consumed_process_ids:
                return self._denied("native host process identity was already consumed", process)
            authority = self._coordinator.authorize(
                self._installation.identity, self._installation.receipt, now=now
            )
            if not authority.authorized:
                return self._denied(authority.reason, process)
            self._consumed_process_ids.add(process)
            self._active_process_id = process
            self._state = NativeHostState.RUNNING
            return self._accepted(f"native host {source.value} process admitted", process)

    def _accepted(self, reason: str, process_id: str | None) -> NativeHostDecision:
        return NativeHostDecision(
            True, reason, self._installation.installation_fingerprint,
            self._installation.receipt.receipt_fingerprint, process_id,
        )

    def _denied(self, reason: str, process_id: str | None) -> NativeHostDecision:
        return NativeHostDecision(
            False, reason, self._installation.installation_fingerprint,
            self._installation.receipt.receipt_fingerprint, process_id,
        )


def install_native_host(
    coordinator: DeploymentAuthorityHandoffCoordinator,
    installation: NativeHostInstallation,
    *,
    now: object,
) -> tuple[NativeHost | None, NativeHostDecision]:
    """Install a host only after its exact receipt is already authorized.

    This performs no filesystem installation. The returned host is the
    process-local policy boundary a native installer or service wrapper must
    retain after it completes its own platform-specific work.
    """

    if type(coordinator) is not DeploymentAuthorityHandoffCoordinator or type(installation) is not NativeHostInstallation:
        raise NativeHostError("native host installation is invalid")
    authority = coordinator.authorize(installation.identity, installation.receipt, now=now)
    decision = NativeHostDecision(
        authority.authorized,
        "native host installation admitted" if authority.authorized else authority.reason,
        installation.installation_fingerprint,
        installation.receipt.receipt_fingerprint,
    )
    return (NativeHost(coordinator, installation) if authority.authorized else None, decision)
