"""Explicit, bounded provider-health qualification fixture; no environment harness."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

from .configuration import Configuration
from .provider_health import CodexHealthContract, CodexProviderHealth, CodexRuntimeAudit, HealthState, ProviderHealthAuditIdentity, ProviderHealthError, ProviderHealthReceipt, ProviderQualificationControl, ProviderQualificationReport, RoleBoundCodexCredentialStore, required_provider_selections
from .provider_recovery import ProviderRole


@dataclass(frozen=True)
class LiveProviderHealthFixtureResult:
    report: ProviderQualificationReport
    receipts: tuple[ProviderHealthReceipt, ...]
    ready_at: int
    contract_commit: str
    candidate_sha: str | None
    case_id: str

    def __post_init__(self) -> None:
        try:
            if type(self.report) is not ProviderQualificationReport or type(self.receipts) is not tuple or any(type(item) is not ProviderHealthReceipt for item in self.receipts) or type(self.ready_at) is not int or type(self.contract_commit) is not str or re.fullmatch(r"[0-9a-f]{40}", self.contract_commit) is None or (self.candidate_sha is not None and (type(self.candidate_sha) is not str or re.fullmatch(r"[0-9a-f]{40}", self.candidate_sha) is None)) or type(self.case_id) is not str or not self.case_id or len(self.case_id) > 128 or any(not (item.isalnum() or item in "._-") for item in self.case_id) or len(self.report.selections) != len(self.report.observations): raise ValueError
            ready = tuple((index, selection, observation) for index, (selection, observation) in enumerate(zip(self.report.selections, self.report.observations, strict=True)) if observation.state is HealthState.READY and observation.is_fresh_at(self.ready_at))
            if len(self.receipts) != len(ready): raise ValueError
            for (index, selection, observation), receipt in zip(ready, self.receipts, strict=True):
                if type(selection) is not tuple or len(selection) != 3: raise ValueError
                ordinal, role, profile_identity = selection
                if type(ordinal) is not int or ordinal != index or type(role) is not ProviderRole or type(profile_identity) is not str or (receipt.contract_commit, receipt.candidate_sha, receipt.case_id, receipt.selection_ordinal, receipt.configuration, receipt.role, receipt.profile_identity, receipt.observation) != (self.contract_commit, self.candidate_sha, self.case_id, index, self.report.configuration, role, profile_identity, observation) or observation.health_contract_identity != self.report.health_contract_identity: raise ValueError
                receipt.authorize(self.report.configuration, role, profile_identity, contract_commit=self.contract_commit, candidate_sha=self.candidate_sha, case_id=self.case_id, now=self.ready_at)
        except Exception as error:
            raise ProviderHealthError("live provider health fixture result is invalid") from error

    def owner_safe_evidence(self) -> dict[str, object]:
        ready = self.report.ready_at(self.ready_at)
        payload = {
            "schema": "roundwright-live-provider-health/v1", "ready_at": self.ready_at,
            "ready": ready, "status": "ready" if ready else "blocked", "contract_commit": self.contract_commit,
            "candidate_sha": self.candidate_sha, "case_id": self.case_id,
            "report": {"health_contract_identity": self.report.health_contract_identity,
                       "configuration": self.report.configuration.complete_columns(),
                       "selections": tuple((ordinal, role.value, profile_identity) for ordinal, role, profile_identity in self.report.selections),
                       "observations": tuple(observation.evidence() for observation in self.report.observations)},
            "receipts": tuple(receipt.evidence() for receipt in self.receipts),
            "receipt_digests": tuple(receipt.receipt_digest for receipt in self.receipts),
        }
        shadow_case_identity = _digest({"contract_commit": self.contract_commit, "candidate_sha": self.candidate_sha,
                                        "case_id": self.case_id, "configuration": self.report.configuration.complete_columns()})
        reference_identity = _digest({"schema": "roundwright-live-provider-health-reference/v1", "contract_commit": self.contract_commit,
                                      "candidate_sha": self.candidate_sha, "case_id": self.case_id,
                                      "report": payload["report"], "receipt_digests": payload["receipt_digests"]})
        manifest = {
            "schema": "roundwright-live-provider-health-manifest/v1",
            "shadow_case_identity": shadow_case_identity,
            "reference_identity": reference_identity,
            "comparator_version": "provider-health-receipt/v1",
            "normalizer_version": "roundwright-json-tuples/v1",
            "environment_identity": "native-read-only",
            "retention_identity": "orchestrator-capture-required",
        }
        return {**payload, "manifest": {**manifest, "bundle_digest": _digest({"payload": payload, "manifest": manifest})}}


def run_bounded_live_provider_health_fixture(store: RoleBoundCodexCredentialStore, contract: CodexHealthContract, configuration: Configuration, qualification_control: ProviderQualificationControl, *, enabled: bool, contract_commit: str, candidate_sha: str | None, case_id: str, now: int, freshness_seconds: int) -> LiveProviderHealthFixtureResult:
    """Run one forced content-free qualification pass only when explicitly enabled."""
    valid_commit = type(contract_commit) is str and re.fullmatch(r"[0-9a-f]{40}", contract_commit)
    valid_candidate = candidate_sha is None or (type(candidate_sha) is str and re.fullmatch(r"[0-9a-f]{40}", candidate_sha))
    valid_case = type(case_id) is str and 0 < len(case_id) <= 128 and all(item.isalnum() or item in "._-" for item in case_id)
    if enabled is not True or type(store) is not RoleBoundCodexCredentialStore or type(contract) is not CodexHealthContract or type(configuration) is not Configuration or type(qualification_control) is not ProviderQualificationControl or type(now) is not int or type(freshness_seconds) is not int or freshness_seconds <= 0 or not valid_commit or not valid_candidate or not valid_case or contract.contract_commit != contract_commit:
        raise ProviderHealthError("live provider health fixture is disabled or invalid")
    try:
        report = CodexProviderHealth(store, contract).qualify_configuration(configuration, binding=qualification_control.binding, control=qualification_control, freshness_seconds=freshness_seconds, max_attempts=1, force_refresh=True, now=now)
        if type(report) is not ProviderQualificationReport: raise ValueError
        profiles = (configuration.worker.value, configuration.worker.value, *configuration.supervisor_attempt_profiles.value)
        if tuple(selection for selection in report.selections) != required_provider_selections(report.configuration): raise ValueError
        receipts = []
        for ordinal, ((_, role, profile_identity), observation, profile) in enumerate(zip(report.selections, report.observations, profiles, strict=True)):
            if observation.state is not HealthState.READY or not observation.is_fresh_at(now):
                continue
            audit = store.open_role_channel(role).audit_runtime()
            if type(audit) is not CodexRuntimeAudit: raise ValueError
            audit_identity = ProviderHealthAuditIdentity(audit, profile)
            if audit_identity.runtime_fingerprint != observation.runtime_fingerprint: raise ValueError
            receipts.append(ProviderHealthReceipt(contract_commit, candidate_sha, case_id, ordinal, report.configuration, role, profile_identity, observation, audit_identity))
        return LiveProviderHealthFixtureResult(report, tuple(receipts), now, contract_commit, candidate_sha, case_id)
    except Exception as error:
        raise ProviderHealthError("live provider health fixture is blocked") from error


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
