"""Hermetic coverage for the explicitly gated live-provider fixture core."""
from __future__ import annotations
import unittest
import io, json, contextlib
import tempfile
from unittest import mock
from pathlib import Path
from roundwright.configuration import load_configuration
from roundwright.provider_health import CodexCapability, CodexHealthContract, CodexRuntimeAudit, ProbeOutcome, ProviderHealthError, ProviderHealthReceipt, RoleBoundCodexCredentialStore
from roundwright.provider_health_live import run_bounded_live_provider_health_fixture
from roundwright.provider_recovery import ProviderRole
from tests import live_provider_health as live_harness
from roundwright.shadow import compare_provider_health_receipt, ComparisonOutcome, rehydrate_live_provider_health_evidence

def live_provider_factory():
    test = LiveFixtureTests(); store, configuration, _ = test.fixture()
    return store, CodexHealthContract("1.2.3", "4.5.6", "b" * 40), configuration

class Channel:
    def __init__(self, audit, outcome=ProbeOutcome(True)): self.audit, self.outcome, self.audits, self.requests = audit, outcome, 0, []
    def __repr__(self): return "token C:/private/path payload"
    def audit_runtime(self): self.audits += 1; return self.audit
    def qualify_read_only(self, request): self.requests.append(request); return self.outcome

class LiveFixtureTests(unittest.TestCase):
    def fixture(self, outcome=ProbeOutcome(True), malformed=False):
        with tempfile.TemporaryDirectory(prefix="roundwright live ") as temporary:
            return self.fixture_at(Path(temporary), outcome=outcome, malformed=malformed)

    def fixture_at(self, workspace, outcome=ProbeOutcome(True), malformed=False):
        configuration = load_configuration(cwd=workspace, environment={}, home=workspace)
        capabilities = tuple({(p.model, p.reasoning_effort.value) for p in (configuration.worker.value, *configuration.supervisor_attempt_profiles.value)})
        audit = object() if malformed else CodexRuntimeAudit("1.2.3", "4.5.6", tuple(CodexCapability(*item) for item in capabilities))
        channels = {role: ("sha256:" + f"{index:x}" * 64, Channel(audit, outcome)) for index, role in enumerate(ProviderRole)}
        return RoleBoundCodexCredentialStore("sha256:" + "a" * 64, channels), configuration, channels
    def test_disabled_and_malformed_inputs_touch_no_backend(self):
        store, config, channels = self.fixture(); contract = CodexHealthContract("1.2.3", "4.5.6", "b" * 40)
        for values in ({"enabled": False}, {"contract_commit": "bad"}, {"candidate_sha": "bad"}, {"case_id": "bad space"}, {"freshness_seconds": 0}):
            args = dict(enabled=True, contract_commit="b" * 40, candidate_sha=None, case_id="case", now=100, freshness_seconds=30); args.update(values)
            with self.assertRaises(ProviderHealthError): run_bounded_live_provider_health_fixture(store, contract, config, **args)
        self.assertTrue(all(not channel.audits and not channel.requests for _, channel in channels.values()))
    def test_enabled_fixture_returns_ordered_canonical_redacted_receipts(self):
        with tempfile.TemporaryDirectory(prefix="roundwright live ") as temporary:
            workspace = Path(temporary)
            self.assertTrue(workspace.is_dir())
            self.assertIn(" ", workspace.name)
            with mock.patch.dict("os.environ", {"HOME": "ignored"}, clear=True), mock.patch("os.getcwd", return_value="ignored"):
                store, config, channels = self.fixture_at(workspace)
        contract = CodexHealthContract("1.2.3", "4.5.6", "b" * 40)
        result = run_bounded_live_provider_health_fixture(store, contract, config, enabled=True, contract_commit="b" * 40, candidate_sha="c" * 40, case_id="case", now=100, freshness_seconds=30)
        self.assertEqual(len(result.receipts), 2 + len(config.supervisor_attempt_profiles.value))
        self.assertTrue(all(ProviderHealthReceipt.from_evidence(item.evidence()) == item for item in result.receipts))
        self.assertEqual(sum(len(channel.requests) for _, channel in channels.values()), len(result.receipts))
    def test_blocked_or_malformed_live_profile_returns_only_generic_error(self):
        for outcome, malformed in ((ProbeOutcome(False, __import__("roundwright.provider_health", fromlist=["CodexFailure"]).CodexFailure.AUTH_MISSING), False), (ProbeOutcome(True), True)):
            store, config, _ = self.fixture(outcome, malformed); contract = CodexHealthContract("1.2.3", "4.5.6", "b" * 40)
            with self.assertRaisesRegex(ProviderHealthError, "^live provider health fixture is blocked$"):
                run_bounded_live_provider_health_fixture(store, contract, config, enabled=True, contract_commit="b" * 40, candidate_sha=None, case_id="case", now=100, freshness_seconds=30)

    def test_harness_disabled_blocked_and_success_contract(self):
        output = io.StringIO()
        with mock.patch.dict("os.environ", {}, clear=True), contextlib.redirect_stdout(output), mock.patch.object(live_harness.importlib, "import_module", side_effect=AssertionError):
            self.assertEqual(live_harness.main(), 2)
        self.assertEqual(output.getvalue(), '{"schema":"roundwright-live-provider-health/v1","status":"disabled"}\n')
        output = io.StringIO(); env = {"ROUNDWRIGHT_RUN_LIVE_PROVIDER_HEALTH":"1", "ROUNDWRIGHT_LIVE_PROVIDER_FACTORY":"bad:factory", "ROUNDWRIGHT_CONTRACT_COMMIT":"b" * 40, "ROUNDWRIGHT_SHADOW_CASE_ID":"case"}
        with mock.patch.dict("os.environ", env, clear=True), contextlib.redirect_stdout(output): self.assertEqual(live_harness.main(), 1)
        self.assertEqual(output.getvalue(), '{"schema":"roundwright-live-provider-health/v1","status":"blocked"}\n')
        output, errors = io.StringIO(), io.StringIO()
        env = {"ROUNDWRIGHT_RUN_LIVE_PROVIDER_HEALTH":"1", "ROUNDWRIGHT_LIVE_PROVIDER_FACTORY":"tests.test_provider_health_live:live_provider_factory", "ROUNDWRIGHT_CONTRACT_COMMIT":"b" * 40, "ROUNDWRIGHT_CANDIDATE_SHA":"c" * 40, "ROUNDWRIGHT_SHADOW_CASE_ID":"case-42-live"}
        with mock.patch.dict("os.environ", env, clear=True), contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors), mock.patch.object(live_harness.time, "time", return_value=100): self.assertEqual(live_harness.main(), 0)
        self.assertEqual(errors.getvalue(), "")
        self.assertTrue(output.getvalue().endswith("\n"))
        lines = output.getvalue().splitlines(); self.assertEqual(len(lines), 1)
        value = json.loads(lines[0]); self.assertEqual((value["schema"], value["ready"], value["ready_at"], value["contract_commit"], value["candidate_sha"], value["case_id"]), ("roundwright-live-provider-health/v1", True, 100, "b" * 40, "c" * 40, "case-42-live"))
        expected_selections = 2 + len(live_provider_factory()[2].supervisor_attempt_profiles.value)
        self.assertEqual(len(value["report"]["selections"]), expected_selections)
        self.assertEqual(len(value["report"]["observations"]), expected_selections)
        self.assertEqual(len(value["receipts"]), expected_selections)
        self.assertEqual(len(value["receipt_digests"]), expected_selections)
        self.assertEqual(value["receipt_digests"], [item["receipt_digest"] for item in value["receipts"]])
        self.assertEqual(len(set(value["receipt_digests"])), len(value["receipt_digests"]))
        replayed = rehydrate_live_provider_health_evidence(value)
        self.assertEqual(compare_provider_health_receipt(replayed[0].evidence(), replayed[0].evidence(), now=100).outcome, ComparisonOutcome.MATCH)
        self.assertFalse(any(marker in lines[0].lower() for marker in ("secret-token", "c:/private", "payload", "_backend", "0x")))
