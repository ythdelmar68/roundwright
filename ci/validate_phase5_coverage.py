"""Validate and render the public-safe Phase 5 legacy-parity coverage map.

The source ledgers intentionally retain historical, neutral descriptions.  This
tool does not reproduce them: it locks the selected opaque identifiers to their
one Phase 5 owner and produces a candidate-bound read-back artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = ROOT / "docs" / "migration" / "phase5-coverage-map.json"
DEFAULT_LEDGER = ROOT / "docs" / "migration" / "legacy-decision-ledger.md"
DEFAULT_TESTS = ROOT / "docs" / "migration" / "test-disposition.md"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
ITEM_ID = re.compile(r"(?:EV|TS)-[0-9A-F]{12}\Z")
ISSUE = re.compile(r"#1(?:1[2-9]|20)\Z")
DISPOSITIONS = frozenset({"adopt", "reframe", "merge", "defer", "retire"})
STATUSES = frozenset({"proposed", "blocked", "owner-routed"})
CONFIDENCES = frozenset({"low", "medium", "high"})
ISSUE_136_REQUIREMENTS = {
    "issue": "136",
    "destinations": [
        "trusted-advisory-admission", "accepted-guidance-resolution",
        "typed-advisory-configuration", "public-safe-advisory-qualification",
    ],
}
ISSUE_136_ARTIFACTS = {
    "advisory-policy-v3": "src/roundwright/role_capability_policy.py",
    "advisory-policy-adversarial-tests-v2": "tests/test_role_capability_policy.py",
    "advisory-role-budget-ledger-tests-v1": "tests/test_role_budget_ledger.py",
    "advisory-migration-v2": "docs/migration/issue-136-trusted-advisory-role-coverage.md",
    "advisory-authority-model-v2": "docs/architecture/authority-model.md",
    "advisory-configuration-v1": "src/roundwright/configuration.py",
    "advisory-worker-seam-v1": "src/roundwright/codex_worker.py",
    "advisory-worker-seam-tests-v1": "tests/test_codex_worker.py",
    "advisory-supervisor-seam-v1": "src/roundwright/codex_supervisor.py",
    "advisory-dependency-review-seam-v1": "src/roundwright/codex_dependency_review.py",
    "advisory-native-supervisor-bridge-v1": "src/roundwright/supervisor_toolbox.py",
    "advisory-native-supervisor-bridge-tests-v1": "tests/test_codex_supervisor.py",
    "advisory-native-dependency-review-bridge-v1": "src/roundwright/dependency_review_toolbox.py",
    "advisory-native-dependency-review-bridge-tests-v1": "tests/test_codex_dependency_review.py",
    "advisory-provider-attempt-runtime-v1": "src/roundwright/provider_attempt_runtime.py",
    "advisory-provider-attempt-runtime-tests-v1": "tests/test_provider_attempt_runtime.py",
    "advisory-worker-toolbox-v1": "src/roundwright/worker_toolbox.py",
    "advisory-worker-toolbox-tests-v1": "tests/test_worker_toolbox.py",
    "advisory-worker-shadow-v1": "src/roundwright/worker_shadow.py",
    "advisory-worker-shadow-tests-v1": "tests/test_worker_shadow.py",
    "advisory-supervisor-shadow-v1": "src/roundwright/supervisor_shadow.py",
    "advisory-external-validation-v1": "src/roundwright/external_validation.py",
    "advisory-external-validation-tests-v1": "tests/test_external_validation.py",
    "advisory-runtime-defaults-v1": "src/roundwright/runtime-defaults.toml",
    "advisory-runtime-defaults-tests-v1": "tests/test_configuration.py",
    "advisory-coding-tools-v1": "src/roundwright/coding_tools.py",
    "advisory-coding-tools-tests-v1": "tests/test_coding_tools.py",
    "advisory-production-coding-runtime-tests-v1": "tests/test_production_coding_runtime.py",
    "advisory-admission-fixture-v1": "tests/role_admission_fixture.py",
    "advisory-semantic-receipt-runner-v1": "ci/phase5_semantic_receipt.py",
    "advisory-qualification-validator-v1": "ci/validate_phase5_coverage.py",
    "advisory-qualification-validator-tests-v1": "tests/test_phase5_coverage.py",
}
ISSUE_132_REQUIREMENTS = {
    "issue": "132",
    "destinations": [
        "scoped-denial-classification", "bounded-recovery-eligibility",
        "public-safe-recovery-qualification",
    ],
}
ISSUE_132_ARTIFACTS = {
    "failure-recovery-contract-v1": "src/roundwright/failure_recovery.py",
    "failure-recovery-provider-runtime-v1": "src/roundwright/provider_recovery.py",
    "failure-recovery-tests-v1": "tests/test_failure_recovery.py",
    "failure-recovery-migration-v1": "docs/migration/issue-132-scoped-denial-recovery-coverage.md",
    "failure-recovery-state-v1": "src/roundwright/state.py",
    "failure-recovery-roadmap-v1": "docs/operations/dogfood-promotion-roadmap.md",
    "failure-recovery-supervisor-runtime-v1": "src/roundwright/provider_attempt_runtime.py",
    "failure-recovery-supervisor-boundary-v1": "src/roundwright/codex_supervisor.py",
    "failure-recovery-worker-boundary-v1": "src/roundwright/codex_worker.py",
    "failure-recovery-dependency-boundary-v1": "src/roundwright/codex_dependency_review.py",
    "failure-recovery-candidate-review-v1": "src/roundwright/candidate_review.py",
    "failure-recovery-supervisor-runtime-tests-v1": "tests/test_provider_attempt_runtime.py",
    "failure-recovery-runtime-tests-v1": "tests/test_provider_recovery.py",
    "failure-recovery-supervisor-tests-v1": "tests/test_codex_supervisor.py",
    "failure-recovery-worker-tests-v1": "tests/test_codex_worker.py",
    "failure-recovery-dependency-tests-v1": "tests/test_codex_dependency_review.py",
    "failure-recovery-candidate-review-tests-v1": "tests/test_candidate_review.py",
    "failure-recovery-state-tests-v1": "tests/test_state.py",
    "failure-recovery-semantic-receipt-v1": "ci/phase5_semantic_receipt.py",
    "failure-recovery-qualification-validator-v1": "ci/validate_phase5_coverage.py",
    "failure-recovery-qualification-tests-v1": "tests/test_phase5_coverage.py",
}

# Hashes establish candidate inventory, but do not by themselves establish
# that the listed artifacts still enforce the Phase 5 boundary.  These named
# assertions bind the read-back to the exact executable semantic contracts and
# adversarial tests that must remain present on the candidate.
SEMANTIC_CONTRACTS = {
    "src/roundwright/worker_toolbox.py": (
        "require_external_production_activation()",
        "class ProductionCodingWorkerRuntime",
        "production coding activation is unavailable",
    ),
    "src/roundwright/coding_tools.py": (
        "TEST_INPUT_SET", "NETWORK", "RESOURCE",
        "bounded coding scope root is invalid",
        "_require_static_validation_descriptors",
    ),
    "src/roundwright/role_capability_policy.py": (
        "class TrustedProviderLaunchContext",
        "_authenticated_payload",
        "trusted provider launch context is immutable",
        "role effect descriptors are not admitted",
    ),
    "tests/test_production_coding_runtime.py": (
        "test_direct_production_runtime_construction_denies_before_provider_or_local_effect",
        "test_fabricated_direct_runtime_dispatch_denies_before_any_effect",
        "test_test_only_harness_preserves_drift_feedback_and_reconciliation_coverage",
    ),
    "tests/test_coding_tools.py": (
        "test_scope_root_label_cannot_authorize_a_different_resolved_workspace",
    ),
    "tests/test_worker_toolbox.py": (
        "test_sealed_launch_context_rejects_coherent_public_instruction_mutation",
    ),
    "src/roundwright/failure_recovery.py": (
        "class FailureRecord",
        "def record_durable_clearance",
        "def record_durable_clearance_revocation",
        "def admit_recovery",
    ),
    "src/roundwright/provider_recovery.py": (
        "class ProviderAttempt",
        "def read_supervisor_accounting_snapshot",
        "def record_supervisor_terminal_failure",
        "def read_supervisor_terminal_failure",
        "def prepare_attempt",
    ),
    "src/roundwright/provider_attempt_runtime.py": (
        "class ProviderAttemptFormatCorrectionExhausted",
        "physical_format_output_ordinal",
        "provider terminal failure cannot use a format correction route",
    ),
    "src/roundwright/codex_supervisor.py": (
        "roundwright-provider-attempt-accounting-material/v3",
        "physical_format_output_ordinal",
        "_eligible_prebound_failover",
    ),
    "src/roundwright/codex_worker.py": (
        "class CodexWorkerAdapter",
        "SANDBOX_OR_APPROVAL_DENIED",
    ),
    "src/roundwright/codex_dependency_review.py": (
        "record_durable_failure(",
        "DependencyReviewResultKind.BLOCKED",
    ),
    "tests/test_failure_recovery.py": (
        "test_denial_blocks_same_scope_across_restart_until_exact_clearance",
    ),
    "tests/test_provider_recovery.py": (
        "test_durable_clearance_and_revocation_are_append_only_and_restart_verified",
        "test_durable_failure_readback_revalidates_current_admission_authority",
        "test_supervisor_coordinates_are_unique_and_strictly_monotonic",
    ),
    "tests/test_codex_worker.py": (
        "test_typed_denial_and_transport_failure_remain_typed",
    ),
    "tests/test_codex_dependency_review.py": (
        "test_restart_scope_denial_blocks_before_dependency_provider_session",
        "test_typed_blocked_turn_records_a_shared_durable_failure_from_the_session_claim",
        "test_restart_of_an_authoritative_session_claim_has_zero_later_provider_or_budget_effects",
    ),
    "tests/test_codex_supervisor.py": (
        "test_ambiguous_and_incomplete_results_stop_before_fallback",
        "test_sequence_advances_invalid_primary_to_valid_fallback",
    ),
    "tests/test_provider_attempt_runtime.py": (
        "test_terminal_supervisor_failure_is_durable_and_never_fails_over_without_invalid_output",
        "test_same_profile_format_ordinals_are_durable_and_exhaust_before_a_fourth_dispatch",
        "test_restart_continues_same_profile_at_next_physical_format_ordinal",
        "test_same_format_ordinal_replay_is_inert_but_changed_attempt_identity_is_rejected",
        "test_later_accounting_request_reads_prior_invalid_recovery_without_disclosure",
    ),
}

# This is intentionally independent of the rendered map.  Adding, dropping,
# or reassigning a selected identifier requires a reviewed code change.
EXPECTED_OWNERS = {
    "EV-0F91CDC81DEA": "#120", "EV-11F2ACA46283": "#118", "EV-305347E6CE3A": "#120",
    "EV-312D7F292898": "#119", "EV-346AD74E1323": "#115", "EV-3C97D24C7ECE": "#114",
    "EV-457FC17699F7": "#115", "EV-50613D9E02C5": "#118", "EV-5AAD74DCC184": "#119",
    "EV-6FCE77814A22": "#119", "EV-70980A46DE9E": "#120", "EV-8B3ADA5DCF43": "#115",
    "EV-9C3DC7F9F8A0": "#115", "EV-A66CF4326777": "#115", "EV-AC0B36BE5F29": "#114",
    "EV-B766FE226AE0": "#115", "EV-BC32C3A410F6": "#119", "EV-CA4BBED76303": "#117",
    "EV-F467391FEB1E": "#119", "EV-6BC84399BF20": "#119",
    "TS-0351A26DBE99": "#118", "TS-06896C06863C": "#114", "TS-126BD58C04F8": "#119",
    "TS-176D0551EC9C": "#114", "TS-28CD3D7A4ECA": "#115", "TS-3135EFA60899": "#120",
    "TS-38B72E44AD2C": "#115", "TS-5ECC2458A2BF": "#118", "TS-617815F1AF67": "#120",
    "TS-658FBA7F941B": "#115", "TS-9C2FE6B21A18": "#115", "TS-A0D00D74FBB0": "#119",
    "TS-A1630BB5E806": "#115", "TS-D5AC3D130518": "#115", "TS-E0FEB594E104": "#114",
    "TS-E5C8F4C6FEA2": "#119", "TS-E739091723AA": "#120", "TS-EABDEABE0FC0": "#119",
    "TS-ECEA91EAD390": "#115", "TS-F6DC3340D9FF": "#114", "TS-F8EA5D587E87": "#115",
    "TS-FCE318E20A2A": "#119", "TS-856DFB0B5E51": "#119", "TS-94DA8C4D0395": "#119", "TS-CA4258665663": "#119",
}

EXPECTED_DESTINATIONS = {
    "EV-0F91CDC81DEA": "promotion-evaluation", "EV-11F2ACA46283": "daemon-authority", "EV-305347E6CE3A": "promotion-verification-policy",
    "EV-312D7F292898": "retention-policy", "EV-346AD74E1323": "review-item-lifecycle", "EV-3C97D24C7ECE": "dependency-graph-validator",
    "EV-457FC17699F7": "worker-objective-state", "EV-50613D9E02C5": "daemon-lifecycle", "EV-5AAD74DCC184": "execution-profile-policy",
    "EV-6FCE77814A22": "maintenance-lifecycle", "EV-70980A46DE9E": "promotion-evidence-gate", "EV-8B3ADA5DCF43": "review-item-lifecycle",
    "EV-9C3DC7F9F8A0": "owner-command-queue", "EV-A66CF4326777": "owner-command-queue", "EV-AC0B36BE5F29": "final-gate-aggregation",
    "EV-B766FE226AE0": "review-item-lifecycle", "EV-BC32C3A410F6": "cleanup-eligibility", "EV-CA4BBED76303": "configured-source-ingestion",
    "EV-F467391FEB1E": "verification-denial-taxonomy", "EV-6BC84399BF20": "optional-daemon-autostart-deferment",
    "TS-0351A26DBE99": "daemon-lifecycle", "TS-06896C06863C": "dependency-graph-validator", "TS-126BD58C04F8": "cleanup-eligibility",
    "TS-176D0551EC9C": "dependency-graph-validator", "TS-28CD3D7A4ECA": "review-item-lifecycle", "TS-3135EFA60899": "promotion-public-safety",
    "TS-38B72E44AD2C": "owner-command-queue", "TS-5ECC2458A2BF": "daemon-lifecycle", "TS-617815F1AF67": "promotion-final-gate",
    "TS-658FBA7F941B": "review-item-lifecycle", "TS-9C2FE6B21A18": "owner-command-queue", "TS-A0D00D74FBB0": "owner-command-policy",
    "TS-A1630BB5E806": "owner-command-queue", "TS-D5AC3D130518": "owner-command-queue", "TS-E0FEB594E104": "dependency-graph-validator",
    "TS-E5C8F4C6FEA2": "cleanup-eligibility", "TS-E739091723AA": "promotion-final-gate", "TS-EABDEABE0FC0": "verification-denial-taxonomy",
    "TS-ECEA91EAD390": "review-item-lifecycle", "TS-F6DC3340D9FF": "dependency-graph-validator", "TS-F8EA5D587E87": "review-item-lifecycle",
    "TS-FCE318E20A2A": "owner-command-policy", "TS-856DFB0B5E51": "destructive-cleanup-retirement",
    "TS-94DA8C4D0395": "destructive-cleanup-retirement", "TS-CA4258665663": "destructive-cleanup-retirement",
}

EXPECTED_VERIFICATIONS = (
    {identifier: "candidate-bound-promotion-package" for identifier in (
        "EV-0F91CDC81DEA", "EV-305347E6CE3A", "EV-70980A46DE9E", "TS-3135EFA60899", "TS-617815F1AF67", "TS-E739091723AA",
    )}
    | {identifier: "retention-and-eligibility-suite" for identifier in (
        "EV-312D7F292898", "EV-5AAD74DCC184", "EV-6FCE77814A22", "EV-BC32C3A410F6", "EV-F467391FEB1E", "TS-126BD58C04F8",
        "TS-A0D00D74FBB0", "TS-E5C8F4C6FEA2", "TS-EABDEABE0FC0", "TS-FCE318E20A2A",
    )}
    | {identifier: "durable-review-lifecycle-suite" for identifier in (
        "EV-346AD74E1323", "EV-457FC17699F7", "EV-8B3ADA5DCF43", "EV-9C3DC7F9F8A0", "EV-A66CF4326777", "EV-B766FE226AE0",
        "TS-28CD3D7A4ECA", "TS-38B72E44AD2C", "TS-658FBA7F941B", "TS-9C2FE6B21A18", "TS-A1630BB5E806", "TS-D5AC3D130518",
        "TS-ECEA91EAD390", "TS-F8EA5D587E87",
    )}
    | {identifier: "transactional-graph-suite" for identifier in (
        "EV-3C97D24C7ECE", "EV-AC0B36BE5F29", "TS-06896C06863C", "TS-176D0551EC9C", "TS-E0FEB594E104", "TS-F6DC3340D9FF",
    )}
    | {identifier: "daemon-lifecycle-qualification" for identifier in (
        "EV-11F2ACA46283", "EV-50613D9E02C5", "TS-0351A26DBE99", "TS-5ECC2458A2BF",
    )}
    | {"EV-CA4BBED76303": "scanner-and-selection-suite"}
    | {identifier: "owner-decision-required" for identifier in (
        "EV-6BC84399BF20", "TS-856DFB0B5E51", "TS-94DA8C4D0395", "TS-CA4258665663",
    )}
)

EXPECTED_DISPOSITIONS = {identifier: "adopt" for identifier in EXPECTED_OWNERS} | {
    "EV-0F91CDC81DEA": "merge", "EV-50613D9E02C5": "reframe", "EV-B766FE226AE0": "merge",
    "EV-BC32C3A410F6": "reframe", "EV-6BC84399BF20": "defer", "TS-126BD58C04F8": "reframe",
    "TS-D5AC3D130518": "reframe", "TS-E5C8F4C6FEA2": "reframe", "TS-EABDEABE0FC0": "reframe",
    "TS-856DFB0B5E51": "retire", "TS-94DA8C4D0395": "retire", "TS-CA4258665663": "retire",
}
EXPECTED_PREREQUISITES = (
    {identifier: ("#112", "#119") for identifier in (
        "EV-0F91CDC81DEA", "EV-305347E6CE3A", "EV-70980A46DE9E", "TS-3135EFA60899", "TS-617815F1AF67", "TS-E739091723AA",
    )}
    | {identifier: ("#113",) for identifier in (
        "EV-3C97D24C7ECE", "EV-AC0B36BE5F29", "TS-06896C06863C", "TS-176D0551EC9C", "TS-E0FEB594E104", "TS-F6DC3340D9FF",
    )}
    | {identifier: ("#114",) for identifier in (
        "EV-346AD74E1323", "EV-457FC17699F7", "EV-8B3ADA5DCF43", "EV-9C3DC7F9F8A0", "EV-A66CF4326777", "EV-B766FE226AE0",
        "TS-28CD3D7A4ECA", "TS-38B72E44AD2C", "TS-658FBA7F941B", "TS-9C2FE6B21A18", "TS-A1630BB5E806", "TS-D5AC3D130518",
        "TS-ECEA91EAD390", "TS-F8EA5D587E87",
    )}
    | {identifier: ("#117",) for identifier in ("EV-11F2ACA46283", "EV-50613D9E02C5", "TS-0351A26DBE99", "TS-5ECC2458A2BF")}
    | {identifier: ("#118",) for identifier in (
        "EV-312D7F292898", "EV-5AAD74DCC184", "EV-6FCE77814A22", "EV-BC32C3A410F6", "EV-F467391FEB1E", "EV-6BC84399BF20",
        "TS-126BD58C04F8", "TS-A0D00D74FBB0", "TS-E5C8F4C6FEA2", "TS-EABDEABE0FC0", "TS-FCE318E20A2A",
        "TS-856DFB0B5E51", "TS-94DA8C4D0395", "TS-CA4258665663",
    )}
    | {"EV-CA4BBED76303": ("#114", "#115")}
)
EXPECTED_CONFIDENCES = {identifier: "high" for identifier in EXPECTED_OWNERS} | {
    "EV-0F91CDC81DEA": "medium", "EV-50613D9E02C5": "medium", "EV-B766FE226AE0": "medium",
    "TS-38B72E44AD2C": "medium", "TS-9C2FE6B21A18": "medium", "TS-D5AC3D130518": "medium", "TS-EABDEABE0FC0": "medium",
    "EV-6BC84399BF20": "medium", "EV-BC32C3A410F6": "low", "TS-126BD58C04F8": "low", "TS-E5C8F4C6FEA2": "low",
    "TS-856DFB0B5E51": "low", "TS-94DA8C4D0395": "low", "TS-CA4258665663": "low",
}
EXPECTED_STATUSES = {identifier: "proposed" for identifier in EXPECTED_OWNERS} | {
    "EV-BC32C3A410F6": "blocked", "EV-6BC84399BF20": "blocked", "TS-126BD58C04F8": "owner-routed",
    "TS-E5C8F4C6FEA2": "owner-routed", "TS-856DFB0B5E51": "owner-routed", "TS-94DA8C4D0395": "owner-routed",
    "TS-CA4258665663": "owner-routed",
}

# Selection is independent of the editable coverage map and expected bindings.
# These source rows explicitly defer or retire Phase 5 work and must remain
# visible and owner-routed rather than being silently converted to delivery.
REQUIRED_SOURCE_IDENTIFIERS = frozenset({
    "EV-6BC84399BF20", "TS-856DFB0B5E51", "TS-94DA8C4D0395", "TS-CA4258665663",
})

FORBIDDEN_TEXT = re.compile(
    r"(?:https?://|file://|[A-Za-z]:[\\/]|\\\\|(?:^|[\\s\"'])/(?:home|users|private|var|tmp|opt|srv)(?:/|$)|\.codex/|\b[\w.-]+/[\w.-]+\b|"
    r"private[-_ ]?(?:repo|path|url)|(?:raw|internal)[-_ ]?(?:evidence|output|artifact|migration|transcript|material)|"
    r"credential|password|token|secret|owner[-_ ]?(?:reasoning|rationale|notes?))",
    re.IGNORECASE,
)


class CoverageError(ValueError):
    """The coverage map is incomplete, stale, or unsafe to publish."""


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_source_digest(path: Path) -> str:
    """Hash source text as canonical Git content regardless of checkout EOLs."""
    return _digest(path.read_bytes().replace(b"\r\n", b"\n"))


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CoverageError("coverage map is unavailable") from error
    if type(value) is not dict:
        raise CoverageError("coverage map must be an object")
    return value


def _source_identifiers(path: Path, prefix: str) -> set[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise CoverageError("source ledger is unavailable") from error
    identifiers = re.findall(rf"\| ({prefix}-[0-9A-F]{{12}}) \|", text)
    return set(identifiers)


def current_candidate() -> str:
    """Return the exact checked-out candidate; no caller-selected SHA is trusted."""
    try:
        result = subprocess.run(
            ("git", "rev-parse", "HEAD"), cwd=ROOT, check=True,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise CoverageError("checked-out candidate is unavailable") from error
    candidate = result.stdout.strip()
    if not COMMIT_SHA.fullmatch(candidate):
        raise CoverageError("checked-out candidate is invalid")
    return candidate


def _require_current_candidate(candidate: str) -> None:
    if not COMMIT_SHA.fullmatch(candidate):
        raise CoverageError("candidate SHA is invalid")
    if candidate != current_candidate():
        raise CoverageError("candidate SHA does not match checked-out HEAD")


def validate(source: Path, ledger: Path, tests: Path) -> dict[str, Any]:
    document = _read_json(source)
    if set(document) != {"schema", "implementation_requirements", "issue_132_requirements", "sources", "items"} or document["schema"] != "roundwright-phase5-coverage/v1":
        raise CoverageError("coverage map schema is invalid")
    requirements = document["implementation_requirements"]
    if type(requirements) is not dict or {key: requirements.get(key) for key in ("issue", "destinations")} != ISSUE_136_REQUIREMENTS:
        raise CoverageError("issue 136 implementation coverage has drifted")
    artifacts = requirements.get("artifacts")
    if type(artifacts) is not list or {item.get("identity"): item.get("path") for item in artifacts if type(item) is dict} != ISSUE_136_ARTIFACTS or len(artifacts) != len(ISSUE_136_ARTIFACTS):
        raise CoverageError("issue 136 artifact identities have drifted")
    for artifact in artifacts:
        if set(artifact) != {"identity", "path", "sha256"} or type(artifact["sha256"]) is not str or not SHA256.fullmatch(artifact["sha256"]):
            raise CoverageError("issue 136 artifact digest is invalid")
        if _git_blob_sha256(artifact["path"]) != artifact["sha256"]:
            raise CoverageError("issue 136 artifact digest has drifted")
    _validate_implementation_requirements(
        document["issue_132_requirements"], ISSUE_132_REQUIREMENTS,
        ISSUE_132_ARTIFACTS, "issue 132",
    )
    _validate_semantic_contracts()
    if type(document["sources"]) is not dict or set(document["sources"]) != {"ledger_sha256", "test_disposition_sha256"}:
        raise CoverageError("coverage source bindings are invalid")
    source_bindings = document["sources"]
    if any(type(value) is not str or not SHA256.fullmatch(value) for value in source_bindings.values()):
        raise CoverageError("coverage source digest is invalid")
    if source_bindings["ledger_sha256"] != _canonical_source_digest(ledger) or source_bindings["test_disposition_sha256"] != _canonical_source_digest(tests):
        raise CoverageError("coverage source content has drifted")
    items = document["items"]
    if type(items) is not list or not items:
        raise CoverageError("coverage items are invalid")
    observed: dict[str, str] = {}
    for item in items:
        if type(item) is not dict or set(item) != {"id", "disposition", "destination", "owner_issue", "prerequisites", "verification", "confidence", "status"}:
            raise CoverageError("coverage item fields are invalid")
        identifier = item["id"]
        if type(identifier) is not str or not ITEM_ID.fullmatch(identifier) or identifier in observed:
            raise CoverageError("coverage identifier is invalid or duplicate")
        if item["owner_issue"] != EXPECTED_OWNERS.get(identifier) or not ISSUE.fullmatch(item["owner_issue"]):
            raise CoverageError("coverage owner issue has drifted")
        if item["disposition"] not in DISPOSITIONS or item["status"] not in STATUSES or item["confidence"] not in CONFIDENCES:
            raise CoverageError("coverage disposition metadata is invalid")
        if type(item["destination"]) is not str or type(item["verification"]) is not str or not item["destination"] or not item["verification"]:
            raise CoverageError("coverage destination or verification is invalid")
        prerequisites = item["prerequisites"]
        if type(prerequisites) is not list or not prerequisites or any(type(value) is not str or not ISSUE.fullmatch(value) for value in prerequisites):
            raise CoverageError("coverage prerequisites are invalid")
        if FORBIDDEN_TEXT.search(_canonical(item).decode("ascii")):
            raise CoverageError("coverage map contains unsafe text")
        if item["destination"] != EXPECTED_DESTINATIONS.get(identifier):
            raise CoverageError("coverage destination has drifted")
        if item["verification"] != EXPECTED_VERIFICATIONS.get(identifier):
            raise CoverageError("coverage verification has drifted")
        if item["disposition"] != EXPECTED_DISPOSITIONS.get(identifier):
            raise CoverageError("coverage disposition has drifted")
        if tuple(prerequisites) != EXPECTED_PREREQUISITES.get(identifier):
            raise CoverageError("coverage prerequisites have drifted")
        if item["confidence"] != EXPECTED_CONFIDENCES.get(identifier):
            raise CoverageError("coverage confidence has drifted")
        if item["status"] != EXPECTED_STATUSES.get(identifier):
            raise CoverageError("coverage status has drifted")
        observed[identifier] = item["owner_issue"]
    expected_sets = (EXPECTED_OWNERS, EXPECTED_DESTINATIONS, EXPECTED_VERIFICATIONS, EXPECTED_DISPOSITIONS, EXPECTED_PREREQUISITES, EXPECTED_CONFIDENCES, EXPECTED_STATUSES)
    if observed != EXPECTED_OWNERS or any(set(observed) != set(expected) for expected in expected_sets):
        raise CoverageError("coverage inventory is missing, unknown, or unassigned identifiers")
    ledger_ids = _source_identifiers(ledger, "EV")
    test_ids = _source_identifiers(tests, "TS")
    if not REQUIRED_SOURCE_IDENTIFIERS <= ledger_ids | test_ids:
        raise CoverageError("required Phase 5 source inventory is unavailable")
    if not REQUIRED_SOURCE_IDENTIFIERS <= set(observed):
        raise CoverageError("required Phase 5 source inventory is omitted")
    if not set(identifier for identifier in observed if identifier.startswith("EV-")) <= ledger_ids:
        raise CoverageError("coverage ledger identifier is stale")
    if not set(identifier for identifier in observed if identifier.startswith("TS-")) <= test_ids:
        raise CoverageError("coverage test identifier is stale")
    return document


def _validate_implementation_requirements(
    requirements: object, expected: dict[str, object], artifacts_expected: dict[str, str], label: str,
) -> None:
    if type(requirements) is not dict or {key: requirements.get(key) for key in ("issue", "destinations")} != expected:
        raise CoverageError(f"{label} implementation coverage has drifted")
    artifacts = requirements.get("artifacts")
    if type(artifacts) is not list or {item.get("identity"): item.get("path") for item in artifacts if type(item) is dict} != artifacts_expected or len(artifacts) != len(artifacts_expected):
        raise CoverageError(f"{label} artifact identities have drifted")
    for artifact in artifacts:
        if type(artifact) is not dict or set(artifact) != {"identity", "path", "sha256"} or type(artifact["sha256"]) is not str or not SHA256.fullmatch(artifact["sha256"]):
            raise CoverageError(f"{label} artifact digest is invalid")
        if _git_blob_sha256(artifact["path"]) != artifact["sha256"]:
            raise CoverageError(f"{label} artifact digest has drifted")


def _validate_semantic_contracts() -> None:
    """Fail closed if candidate code or its adversarial tests lose a boundary."""
    for relative_path, markers in SEMANTIC_CONTRACTS.items():
        try:
            source = (ROOT / relative_path).read_text(encoding="utf-8")
        except OSError as error:
            raise CoverageError("Phase 5 semantic contract is unavailable") from error
        if any(marker not in source for marker in markers):
            raise CoverageError("Phase 5 semantic contract has drifted")


def _semantic_contract_digest() -> str:
    """Candidate-local identity of every required executable/test contract."""
    payload = {
        relative_path: {
            "markers": markers,
            "sha256": _canonical_source_digest(ROOT / relative_path),
        }
        for relative_path, markers in sorted(SEMANTIC_CONTRACTS.items())
    }
    return _digest(_canonical(payload))


SEMANTIC_TESTS = (
    "tests.test_production_coding_runtime.ProductionRuntimeTests.test_direct_production_runtime_construction_denies_before_provider_or_local_effect",
    "tests.test_production_coding_runtime.ProductionRuntimeTests.test_fabricated_direct_runtime_dispatch_denies_before_any_effect",
    "tests.test_worker_toolbox.WorkerToolboxTests.test_sealed_launch_context_rejects_coherent_public_instruction_mutation",
    "tests.test_coding_tools.BoundedCodingToolsTests.test_scope_root_label_cannot_authorize_a_different_resolved_workspace",
    "tests.test_role_capability_policy.RoleCapabilityPolicyTests.test_scope_traversal_unknown_descriptors_and_capability_expansion_fail_closed",
    "tests.test_codex_worker.CodexWorkerAdapterTests.test_typed_denial_and_transport_failure_remain_typed",
    "tests.test_codex_supervisor.SupervisorTests.test_security_denial_stops_before_a_prebound_profile_fallback",
    "tests.test_codex_dependency_review.DependencyReviewServiceTests.test_restart_scope_denial_blocks_before_dependency_provider_session",
    "tests.test_failure_recovery.FailureRecoveryTests.test_denial_blocks_same_scope_across_restart_until_exact_clearance",
    "tests.test_failure_recovery.FailureRecoveryTests.test_only_verified_terminal_or_transient_fault_uses_prebound_equivalent_route",
    "tests.test_failure_recovery.FailureRecoveryTests.test_closed_matrix_allows_only_canonical_evidence_and_recovery_categories",
    "tests.test_failure_recovery.FailureRecoveryTests.test_closed_record_parser_rejects_tampered_or_unknown_payload",
    "tests.test_provider_recovery.ProviderRecoveryTests.test_durable_failure_readback_revalidates_current_admission_authority",
    "tests.test_provider_recovery.ProviderRecoveryTests.test_durable_clearance_and_revocation_are_append_only_and_restart_verified",
    "tests.test_provider_recovery.ProviderRecoveryTests.test_supervisor_coordinates_are_unique_and_strictly_monotonic",
    "tests.test_provider_recovery.ProviderRecoveryTests.test_terminal_block_and_invalid_output_replays_keep_their_original_classification",
    "tests.test_codex_supervisor.SupervisorTests.test_ambiguous_and_incomplete_results_stop_before_fallback",
    "tests.test_provider_attempt_runtime.ProviderAttemptRuntimeTests.test_terminal_supervisor_failure_is_durable_and_never_fails_over_without_invalid_output",
    "tests.test_provider_attempt_runtime.ProviderAttemptRuntimeTests.test_same_profile_format_ordinals_are_durable_and_exhaust_before_a_fourth_dispatch",
    "tests.test_provider_attempt_runtime.ProviderAttemptRuntimeTests.test_restart_continues_same_profile_at_next_physical_format_ordinal",
    "tests.test_provider_attempt_runtime.ProviderAttemptRuntimeTests.test_same_format_ordinal_replay_is_inert_but_changed_attempt_identity_is_rejected",
    "tests.test_provider_attempt_runtime.ProviderAttemptRuntimeTests.test_later_accounting_request_reads_prior_invalid_recovery_without_disclosure",
    "tests.test_production_coding_runtime.ProductionRuntimeTests.test_test_only_harness_preserves_drift_feedback_and_reconciliation_coverage",
    "tests.test_codex_supervisor.SupervisorTests.test_sequence_advances_invalid_primary_to_valid_fallback",
    "tests.test_codex_dependency_review.DependencyReviewServiceTests.test_typed_blocked_turn_records_a_shared_durable_failure_from_the_session_claim",
    "tests.test_codex_dependency_review.DependencyReviewServiceTests.test_restart_of_an_authoritative_session_claim_has_zero_later_provider_or_budget_effects",
)
WINDOWS_DECLARED_SKIPS: tuple[str, ...] = ()
ISSUE_132_FINDING_REQUIREMENTS = {
    "E1R2-01": ("src/roundwright/codex_worker.py", "tests.test_codex_worker.CodexWorkerAdapterTests.test_typed_denial_and_transport_failure_remain_typed"),
    "E1R2-02": ("src/roundwright/codex_supervisor.py", "tests.test_codex_supervisor.SupervisorTests.test_security_denial_stops_before_a_prebound_profile_fallback"),
    "E1R2-03": ("src/roundwright/codex_dependency_review.py", "tests.test_codex_dependency_review.DependencyReviewServiceTests.test_restart_scope_denial_blocks_before_dependency_provider_session"),
    "E1R2-04": ("src/roundwright/failure_recovery.py", "tests.test_failure_recovery.FailureRecoveryTests.test_only_verified_terminal_or_transient_fault_uses_prebound_equivalent_route"),
    "E1R2-05": ("src/roundwright/failure_recovery.py", "tests.test_failure_recovery.FailureRecoveryTests.test_closed_matrix_allows_only_canonical_evidence_and_recovery_categories"),
    "E1R2-06": ("src/roundwright/provider_recovery.py", "tests.test_provider_recovery.ProviderRecoveryTests.test_durable_failure_readback_revalidates_current_admission_authority"),
    "E1R2-07": ("src/roundwright/failure_recovery.py", "tests.test_provider_recovery.ProviderRecoveryTests.test_durable_clearance_and_revocation_are_append_only_and_restart_verified"),
    "E1R2-08": ("src/roundwright/provider_recovery.py", "tests.test_provider_recovery.ProviderRecoveryTests.test_supervisor_coordinates_are_unique_and_strictly_monotonic"),
}
ISSUE_132_E1R3_TESTS = (
    "tests.test_production_coding_runtime.ProductionRuntimeTests.test_test_only_harness_preserves_drift_feedback_and_reconciliation_coverage",
    "tests.test_codex_supervisor.SupervisorTests.test_sequence_advances_invalid_primary_to_valid_fallback",
    "tests.test_codex_dependency_review.DependencyReviewServiceTests.test_typed_blocked_turn_records_a_shared_durable_failure_from_the_session_claim",
    "tests.test_codex_dependency_review.DependencyReviewServiceTests.test_restart_of_an_authoritative_session_claim_has_zero_later_provider_or_budget_effects",
)
ISSUE_132_SEMANTIC_TESTS = tuple(test for _code, test in ISSUE_132_FINDING_REQUIREMENTS.values()) + (
    "tests.test_provider_recovery.ProviderRecoveryTests.test_terminal_block_and_invalid_output_replays_keep_their_original_classification",
    "tests.test_provider_attempt_runtime.ProviderAttemptRuntimeTests.test_same_profile_format_ordinals_are_durable_and_exhaust_before_a_fourth_dispatch",
    "tests.test_provider_attempt_runtime.ProviderAttemptRuntimeTests.test_restart_continues_same_profile_at_next_physical_format_ordinal",
    "tests.test_provider_attempt_runtime.ProviderAttemptRuntimeTests.test_same_format_ordinal_replay_is_inert_but_changed_attempt_identity_is_rejected",
) + ISSUE_132_E1R3_TESTS
def _validate_issue_132_semantic_tests() -> None:
    """Keep the independently maintained E1R2/E1R3 inventory closed and ordered."""
    if len(ISSUE_132_FINDING_REQUIREMENTS) != 8 or len(set(ISSUE_132_FINDING_REQUIREMENTS)) != 8:
        raise CoverageError("Issue 132 E1R2 finding inventory is incomplete")
    if any(not (ROOT / path).is_file() for path, _test in ISSUE_132_FINDING_REQUIREMENTS.values()):
        raise CoverageError("Issue 132 E1R2 finding mapping has drifted")
    if len(ISSUE_132_E1R3_TESTS) != 4 or any(test not in SEMANTIC_TESTS for test in ISSUE_132_E1R3_TESTS):
        raise CoverageError("Issue 132 E1R3 finding inventory is incomplete")
    if tuple(test for test in SEMANTIC_TESTS if test in ISSUE_132_SEMANTIC_TESTS) != ISSUE_132_SEMANTIC_TESTS:
        raise CoverageError("Issue 132 semantic test inventory is omitted, reordered, or drifted")

def _semantic_execution(path: Path, candidate: str) -> str:
    _validate_issue_132_semantic_tests()
    try:
        actual = _read_json(path)
    except CoverageError as error:
        raise CoverageError("Phase 5 semantic execution receipt is unavailable") from error
    payload = {"schema": "roundwright-phase5-semantic-execution/v3", "candidate_sha": candidate, "tests": list(SEMANTIC_TESTS), "executed_tests": list(SEMANTIC_TESTS), "skipped_tests": list(WINDOWS_DECLARED_SKIPS if sys.platform == "win32" else ()), "windows_declared_skips": list(WINDOWS_DECLARED_SKIPS), "status": "passed"}
    if actual != {**payload, "receipt_digest": "sha256:" + _digest(_canonical(payload))}:
        raise CoverageError("Phase 5 semantic execution receipt is stale or forged")
    return actual["receipt_digest"]


def _git_blob_sha256(relative_path: object) -> str:
    """Hash the tracked Git blob, never platform-transformed checkout bytes."""
    if type(relative_path) is not str or not relative_path or relative_path.startswith("/") or "\\" in relative_path or ".." in relative_path.split("/"):
        raise CoverageError("issue 136 artifact path is invalid")
    try:
        result = subprocess.run(["git", "-C", str(ROOT), "show", f"HEAD:{relative_path}"], check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError as error:
        raise CoverageError("issue 136 artifact Git content is unavailable") from error
    if result.returncode:
        raise CoverageError("issue 136 artifact Git content is unavailable")
    return hashlib.sha256(result.stdout).hexdigest()


def render(source: Path, ledger: Path, tests: Path, candidate: str, output: Path, semantic_receipt: Path) -> None:
    _require_current_candidate(candidate)
    document = validate(source, ledger, tests)
    payload = {"schema": "roundwright-phase5-coverage-readback/v2", "candidate_sha": candidate, "source_digest": _digest(_canonical(document)), "semantic_contract_digest": _semantic_contract_digest(), "semantic_execution_receipt": _semantic_execution(semantic_receipt,candidate), "items": document["items"]}
    receipt = {**payload, "coverage_digest": _digest(_canonical(payload))}
    output.write_bytes(_canonical(receipt) + b"\n")


def verify(source: Path, ledger: Path, tests: Path, candidate: str, manifest: Path, semantic_receipt: Path) -> None:
    _require_current_candidate(candidate)
    document = validate(source, ledger, tests)
    actual = _read_json(manifest)
    payload = {"schema": "roundwright-phase5-coverage-readback/v2", "candidate_sha": candidate, "source_digest": _digest(_canonical(document)), "semantic_contract_digest": _semantic_contract_digest(), "semantic_execution_receipt": _semantic_execution(semantic_receipt,candidate), "items": document["items"]}
    expected = {**payload, "coverage_digest": _digest(_canonical(payload))}
    if actual != expected:
        raise CoverageError("candidate-bound coverage manifest does not match")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("validate", "render", "verify"))
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER)
    parser.add_argument("--tests", type=Path, default=DEFAULT_TESTS)
    parser.add_argument("--candidate")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--semantic-receipt", type=Path)
    arguments = parser.parse_args()
    if arguments.operation == "validate":
        validate(arguments.source, arguments.ledger, arguments.tests)
    elif arguments.operation == "render":
        if not arguments.candidate or arguments.output is None or arguments.semantic_receipt is None:
            raise CoverageError("render requires a candidate and output")
        render(arguments.source, arguments.ledger, arguments.tests, arguments.candidate, arguments.output, arguments.semantic_receipt)
    else:
        if not arguments.candidate or arguments.manifest is None or arguments.semantic_receipt is None:
            raise CoverageError("verify requires a candidate and manifest")
        verify(arguments.source, arguments.ledger, arguments.tests, arguments.candidate, arguments.manifest, arguments.semantic_receipt)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CoverageError as error:
        raise SystemExit(f"phase-5 coverage validation failed: {error}")
