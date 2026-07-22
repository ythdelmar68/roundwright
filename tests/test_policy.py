"""Hermetic contract tests for trusted policy activation."""

from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.policy import (
    ActivationReceipt,
    PolicyAction,
    PolicyDocument,
    PolicyError,
    ReceiptStatus,
    StandingAuthority,
    TrustedControlSource,
    TrustedPolicySnapshot,
    evaluate_policy,
    parse_policy_document,
)


def fingerprint(character: str) -> str:
    return character * 64


CURRENT_CANDIDATE_SHA = "e76c621213d0001f766bdb92ba07d2a9e1d7b894"


class TrustedPolicyTests(unittest.TestCase):
    now = datetime(2026, 7, 21, 8, 0, tzinfo=timezone.utc)

    def snapshot(self, contents: str = '{"schema_version":1,"allowed_actions":["issue-comment"]}') -> TrustedPolicySnapshot:
        return TrustedPolicySnapshot(
            source=TrustedControlSource(fingerprint("a"), fingerprint("b")),
            document=parse_policy_document(contents),
        )

    def receipt(self, snapshot: TrustedPolicySnapshot, **changes: object) -> ActivationReceipt:
        values: dict[str, object] = {
            "owner_fingerprint": fingerprint("c"),
            "receipt_fingerprint": fingerprint("d"),
            "source_fingerprint": snapshot.source.source_fingerprint,
            "revision_fingerprint": snapshot.source.revision_fingerprint,
            "policy_digest": snapshot.policy_digest,
            "schema_version": 1,
            "task_fingerprint": fingerprint("e"),
            "candidate_sha": CURRENT_CANDIDATE_SHA,
            "activated_at": self.now - timedelta(minutes=1),
            "expires_at": self.now + timedelta(minutes=1),
        }
        values.update(changes)
        return ActivationReceipt(**values)  # type: ignore[arg-type]

    def evaluate(self, snapshot: TrustedPolicySnapshot, receipt: ActivationReceipt, **changes: object):
        values: dict[str, object] = {
            "task_fingerprint": fingerprint("e"),
            "candidate_sha": CURRENT_CANDIDATE_SHA,
            "standing_authority": StandingAuthority(frozenset(PolicyAction)),
            "now": self.now,
            "receipt_status": ReceiptStatus.FRESH,
        }
        values.update(changes)
        return evaluate_policy(snapshot, receipt, **values)  # type: ignore[arg-type]

    def test_policy_schema_is_versioned_exact_and_canonical(self) -> None:
        policy = parse_policy_document('{"allowed_actions":["issue-comment"],"schema_version":1}')
        reordered = parse_policy_document('{"schema_version":1,"allowed_actions":["issue-comment"]}')
        self.assertEqual(policy.digest, reordered.digest)
        for contents in (
            '{"schema_version":1,"allowed_actions":[],"unknown":true}',
            '{"schema_version":2,"allowed_actions":[]}',
            '{"schema_version":1,"allowed_actions":["unknown"]}',
            '{"schema_version":1,"allowed_actions":["issue-comment","issue-comment"]}',
        ):
            with self.assertRaises(PolicyError):
                parse_policy_document(contents)

    def test_policy_can_narrow_but_cannot_widen_standing_authority(self) -> None:
        snapshot = self.snapshot()
        receipt = self.receipt(snapshot)
        allowed = self.evaluate(snapshot, receipt, standing_authority=StandingAuthority(frozenset({PolicyAction.ISSUE_COMMENT})))
        denied = self.evaluate(snapshot, receipt, standing_authority=StandingAuthority(frozenset()))
        self.assertTrue(allowed.authorized)
        self.assertFalse(denied.authorized)
        self.assertIn("widen", denied.reason)

    def test_missing_or_malformed_standing_authority_denies_safely(self) -> None:
        class ForgedStandingAuthority(StandingAuthority):
            def __post_init__(self) -> None:
                pass

        snapshot = self.snapshot()
        receipt = self.receipt(snapshot)
        with self.assertRaises(PolicyError):
            StandingAuthority([PolicyAction.ISSUE_COMMENT])  # type: ignore[arg-type]
        malformed = StandingAuthority(frozenset())
        object.__setattr__(malformed, "allowed_actions", [PolicyAction.ISSUE_COMMENT])
        forged = ForgedStandingAuthority([PolicyAction.ISSUE_COMMENT])  # type: ignore[arg-type]
        for authority, reason in (
            (None, "standing authority evidence is unavailable"),
            (object(), "standing authority evidence is unavailable"),
            (forged, "standing authority evidence is unavailable"),
            (malformed, "standing authority evidence is invalid"),
        ):
            with self.subTest(authority=type(authority).__name__):
                decision = self.evaluate(snapshot, receipt, standing_authority=authority)
                self.assertFalse(decision.authorized)
                self.assertEqual(decision.reason, reason)
                self.assertEqual(decision.allowed_actions, frozenset())
                self.assertNotIn("path", str(decision.diagnostic()).casefold())

    def test_activation_rejects_tamper_source_schema_digest_and_conflicts(self) -> None:
        snapshot = self.snapshot()
        receipt = self.receipt(snapshot)
        for changes in (
            {"source_fingerprint": fingerprint("0")},
            {"revision_fingerprint": fingerprint("0")},
            {"policy_digest": fingerprint("0")},
            {"task_fingerprint": fingerprint("0")},
        ):
            with self.subTest(changes=changes):
                changed = self.receipt(snapshot, **changes)
                self.assertFalse(self.evaluate(snapshot, changed).authorized)
        with self.assertRaises(PolicyError):
            self.receipt(snapshot, schema_version=0)

    def test_receipt_replay_staleness_and_candidate_drift_fail_closed(self) -> None:
        snapshot = self.snapshot()
        receipt = self.receipt(snapshot)
        self.assertTrue(self.evaluate(snapshot, receipt).authorized)
        self.assertFalse(self.evaluate(snapshot, receipt, candidate_sha="0" * 40).authorized)
        stale = self.receipt(snapshot, expires_at=self.now)
        self.assertFalse(self.evaluate(snapshot, stale).authorized)
        future = self.receipt(snapshot, activated_at=self.now + timedelta(seconds=1), expires_at=self.now + timedelta(minutes=1))
        self.assertFalse(self.evaluate(snapshot, future).authorized)
        self.assertFalse(
            self.evaluate(snapshot, receipt, receipt_status=ReceiptStatus.CONSUMED).authorized
        )

    def test_receipt_lifecycle_evidence_is_required_and_replay_is_denied(self) -> None:
        snapshot = self.snapshot()
        receipt = self.receipt(snapshot)
        first = self.evaluate(snapshot, receipt, receipt_status=ReceiptStatus.FRESH)
        missing = evaluate_policy(
            snapshot,
            receipt,
            task_fingerprint=fingerprint("e"),
            candidate_sha=CURRENT_CANDIDATE_SHA,
            standing_authority=StandingAuthority(frozenset(PolicyAction)),
            now=self.now,
        )
        unknown = self.evaluate(snapshot, receipt, receipt_status="fresh")
        replayed = self.evaluate(snapshot, receipt, receipt_status=ReceiptStatus.CONSUMED)
        self.assertTrue(first.authorized)
        self.assertFalse(missing.authorized)
        self.assertFalse(unknown.authorized)
        self.assertFalse(replayed.authorized)
        self.assertIn("unavailable", missing.reason)
        self.assertIn("replayed", replayed.reason)

    def test_missing_or_invalid_policy_and_receipt_evidence_deny_safely(self) -> None:
        snapshot = self.snapshot()
        receipt = self.receipt(snapshot)
        calls = (
            (None, None, "trusted policy evidence is unavailable"),
            (None, receipt, "trusted policy evidence is unavailable"),
            (snapshot, None, "activation receipt evidence is unavailable"),
            (object(), object(), "trusted policy evidence is unavailable"),
        )
        for policy, activation_receipt, reason in calls:
            with self.subTest(policy=policy is None, receipt=activation_receipt is None):
                decision = evaluate_policy(
                    policy,  # type: ignore[arg-type]
                    activation_receipt,  # type: ignore[arg-type]
                    task_fingerprint=fingerprint("e"),
                    candidate_sha=CURRENT_CANDIDATE_SHA,
                    standing_authority=StandingAuthority(frozenset(PolicyAction)),
                    now=self.now,
                    receipt_status=ReceiptStatus.FRESH,
                )
                self.assertFalse(decision.authorized)
                self.assertEqual(decision.reason, reason)
                self.assertNotIn("path", str(decision.diagnostic()).casefold())

    def test_malformed_snapshot_source_and_document_deny_safely(self) -> None:
        snapshot = self.snapshot()
        receipt = self.receipt(snapshot)
        with self.assertRaises(PolicyError):
            PolicyDocument(1, [PolicyAction.ISSUE_COMMENT])  # type: ignore[arg-type]
        malformed_document = self.snapshot().document
        object.__setattr__(malformed_document, "allowed_actions", [PolicyAction.ISSUE_COMMENT])
        malformed_snapshots = (
            (
                TrustedPolicySnapshot(None, snapshot.document),  # type: ignore[arg-type]
                "trusted policy source evidence is unavailable",
            ),
            (
                TrustedPolicySnapshot(StandingAuthority(frozenset()), snapshot.document),  # type: ignore[arg-type]
                "trusted policy source evidence is unavailable",
            ),
            (
                TrustedPolicySnapshot(snapshot.source, None),  # type: ignore[arg-type]
                "trusted policy document evidence is unavailable",
            ),
            (
                TrustedPolicySnapshot(snapshot.source, StandingAuthority(frozenset())),  # type: ignore[arg-type]
                "trusted policy document evidence is unavailable",
            ),
            (
                TrustedPolicySnapshot(snapshot.source, malformed_document),
                "trusted policy evidence is invalid",
            ),
        )
        for malformed, reason in malformed_snapshots:
            with self.subTest(reason=reason):
                decision = self.evaluate(malformed, receipt)
                self.assertFalse(decision.authorized)
                self.assertEqual(decision.reason, reason)
                self.assertNotIn("path", str(decision.diagnostic()).casefold())
                self.assertIsNone(decision.source_fingerprint)
                self.assertIsNone(decision.policy_digest)

    def test_malformed_receipt_fields_deny_without_leaking_or_raising(self) -> None:
        snapshot = self.snapshot()
        missing_field = object.__new__(ActivationReceipt)
        invalid_timestamp = self.receipt(snapshot)
        object.__setattr__(invalid_timestamp, "activated_at", "not-a-timestamp")
        for malformed in (missing_field, invalid_timestamp):
            with self.subTest(receipt=type(malformed).__name__):
                decision = self.evaluate(snapshot, malformed)
                self.assertFalse(decision.authorized)
                self.assertEqual(decision.reason, "activation receipt evidence is invalid")
                self.assertIsNone(decision.receipt_fingerprint)
                self.assertIsNone(decision.activated_at)
                self.assertIsNone(decision.diagnostic()["activated_at"])

    def test_forged_trusted_evidence_subclasses_deny_safely(self) -> None:
        class ForgedSource(TrustedControlSource):
            def __post_init__(self) -> None:
                pass

        class ForgedDocument(PolicyDocument):
            def __post_init__(self) -> None:
                pass

        class ForgedReceipt(ActivationReceipt):
            def __post_init__(self) -> None:
                pass

        snapshot = self.snapshot()
        receipt = self.receipt(snapshot)
        forged_source = ForgedSource("invalid", "invalid")
        forged_document = ForgedDocument(1, [PolicyAction.ISSUE_COMMENT])  # type: ignore[arg-type]
        forged_receipt = ForgedReceipt(
            "invalid", "invalid", "invalid", "invalid", "invalid", 1,
            "invalid", "invalid", self.now, self.now,
        )
        cases = (
            (
                TrustedPolicySnapshot(forged_source, snapshot.document),
                receipt,
                "trusted policy source evidence is unavailable",
            ),
            (
                TrustedPolicySnapshot(snapshot.source, forged_document),
                receipt,
                "trusted policy document evidence is unavailable",
            ),
            (snapshot, forged_receipt, "activation receipt evidence is unavailable"),
        )
        for policy, activation_receipt, reason in cases:
            with self.subTest(reason=reason):
                decision = self.evaluate(policy, activation_receipt)
                self.assertFalse(decision.authorized)
                self.assertEqual(decision.reason, reason)
                self.assertEqual(decision.allowed_actions, frozenset())
                if type(activation_receipt) is ActivationReceipt:
                    self.assertEqual(decision.receipt_fingerprint, receipt.receipt_fingerprint)
                else:
                    self.assertIsNone(decision.receipt_fingerprint)
                self.assertNotIn("path", str(decision.diagnostic()).casefold())

    def test_subtype_valued_fields_deny_before_comparison(self) -> None:
        class FingerprintSubtype(str):
            pass

        class CommitSubtype(str):
            pass

        class TimestampSubtype(datetime):
            pass

        class ComparisonForgingActions(frozenset[PolicyAction]):
            def __le__(self, other: object) -> bool:
                raise AssertionError("the policy action collection was compared")

        snapshot = self.snapshot()
        receipt = self.receipt(snapshot)
        with self.assertRaises(PolicyError):
            TrustedControlSource(FingerprintSubtype(fingerprint("a")), fingerprint("b"))
        with self.assertRaises(PolicyError):
            self.receipt(snapshot, candidate_sha=CommitSubtype(CURRENT_CANDIDATE_SHA))
        with self.assertRaises(PolicyError):
            self.receipt(
                snapshot,
                activated_at=TimestampSubtype(2026, 7, 21, 7, 59, tzinfo=timezone.utc),
            )
        with self.assertRaises(PolicyError):
            StandingAuthority(ComparisonForgingActions({PolicyAction.RELEASE}))

        object.__setattr__(snapshot.document, "allowed_actions", ComparisonForgingActions({PolicyAction.RELEASE}))
        decision = self.evaluate(snapshot, receipt, standing_authority=StandingAuthority(frozenset()))
        self.assertFalse(decision.authorized)
        self.assertEqual(decision.reason, "trusted policy evidence is invalid")
        self.assertEqual(decision.allowed_actions, frozenset())
        self.assertNotIn("path", str(decision.diagnostic()).casefold())

    def test_timezone_and_document_hooks_deny_without_dispatch(self) -> None:
        class RaisingTimezone(tzinfo):
            def utcoffset(self, value: datetime | None) -> timedelta:
                raise AssertionError("timezone behavior was invoked")

            def dst(self, value: datetime | None) -> timedelta:
                raise AssertionError("timezone behavior was invoked")

            def tzname(self, value: datetime | None) -> str:
                raise AssertionError("timezone behavior was invoked")

        snapshot = self.snapshot()
        receipt = self.receipt(snapshot)
        object.__setattr__(
            receipt,
            "activated_at",
            datetime(2026, 7, 21, 7, 59, tzinfo=RaisingTimezone()),
        )
        timestamp_decision = self.evaluate(snapshot, receipt)
        self.assertFalse(timestamp_decision.authorized)
        self.assertEqual(timestamp_decision.reason, "activation receipt evidence is invalid")

        shadowed_snapshot = self.snapshot()
        shadowed_receipt = self.receipt(shadowed_snapshot)

        def raising_canonical_bytes() -> bytes:
            raise AssertionError("document method was invoked")

        object.__setattr__(shadowed_snapshot.document, "canonical_bytes", raising_canonical_bytes)
        digest_decision = self.evaluate(shadowed_snapshot, shadowed_receipt)
        self.assertFalse(digest_decision.authorized)
        self.assertEqual(digest_decision.reason, "trusted policy evidence is invalid")
        self.assertIsNone(digest_decision.source_fingerprint)
        self.assertIsNone(digest_decision.policy_digest)
        self.assertNotIn("path", str(digest_decision.diagnostic()).casefold())

    def test_candidate_commit_identity_rejects_malformed_values(self) -> None:
        snapshot = self.snapshot()
        with self.assertRaisesRegex(PolicyError, "commit identity"):
            self.receipt(snapshot, candidate_sha="f" * 64 + "0")
        with self.assertRaisesRegex(PolicyError, "commit identity"):
            self.receipt(snapshot, candidate_sha="F" * 40)

    def test_candidate_policy_edit_cannot_authorize_its_own_task(self) -> None:
        trusted = self.snapshot('{"schema_version":1,"allowed_actions":[]}')
        receipt = self.receipt(trusted)
        candidate_edited = self.snapshot('{"schema_version":1,"allowed_actions":["issue-comment"]}')
        decision = self.evaluate(candidate_edited, receipt)
        self.assertFalse(decision.authorized)
        self.assertIn("digest", decision.reason)

    def test_owner_safe_diagnostic_contains_no_private_source_or_receipt_contents(self) -> None:
        snapshot = self.snapshot()
        receipt = self.receipt(snapshot)
        decision = self.evaluate(snapshot, receipt)
        diagnostic = decision.diagnostic()
        rendered = str(diagnostic)
        self.assertTrue(decision.authorized)
        self.assertIn(snapshot.policy_digest, rendered)
        self.assertNotIn("path", rendered.casefold())
        self.assertNotIn("credential", rendered.casefold())

    def test_evaluation_is_deterministic_and_has_no_filesystem_side_effects(self) -> None:
        snapshot = self.snapshot()
        receipt = self.receipt(snapshot)
        with mock.patch("builtins.open", side_effect=AssertionError("filesystem access")):
            first = self.evaluate(snapshot, receipt)
            second = self.evaluate(snapshot, receipt)
        self.assertEqual(first, second)
