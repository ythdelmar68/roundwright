"""Hermetic contracts for configured-source normalization and selection."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from roundwright.configuration import RepositoryIdentity, load_configuration
from roundwright.configured_source import (
    ConfiguredSource, ConfiguredSourceError, ConfiguredSourceStore, SourceIngestionBinding,
    ConfiguredSourceHostInputs, ConfiguredSourceIngestionAdapter, SourceItem, SourcePage,
    SourceType, TrustedConfiguredSourceReadHost, configured_source_capture_plan,
    configured_source_component_identities, configured_source_executor_request,
    _create_owner_blocker_state_read_host, _seal_configured_source_authority, create_configured_source_read_capability,
    _create_task_feed_fixture_capability, create_task_feed_read_host,
    create_issue_list_read_host, prepare_configured_source_ingestion,
    resolve_source_ingestion_binding,
    scan_configured_sources, select_runnable_work,
)
from roundwright.dependency_graph import DependencyGraphBinding, DependencyGraphStore, GraphEdge, GraphMember, GraphSnapshot
from roundwright.github_runtime import (
    CredentialedGitHubReadCapabilityBinding, OwnerGitHubReadIpcClient,
    unavailable_capability_health,
)
from roundwright.dependency_review import AffectedMember, EdgeKind
from roundwright.external_validation import run_configured_source_ingestion_profile
from roundwright.git_identity import acquire_transition_lease
from roundwright.state import SourceSnapshot, TaskIdentity, admit_task, database_path, initialize


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def freeze_harness_json(value: object) -> object:
    if type(value) is dict:
        return MappingProxyType({str(key): freeze_harness_json(item) for key, item in value.items()})
    if type(value) is list:
        return tuple(freeze_harness_json(item) for item in value)
    return value


class Adapter:
    def __init__(self, pages): self.pages, self.calls = pages, []
    def read(self, source, *, cursor):
        self.calls.append((source.public_identity, cursor))
        return self.pages[(source.public_identity, cursor)]


class Harness:
    class ProfileComponentIdentities:
        def __init__(self, *values): self.values = values
        def __eq__(self, other): return isinstance(other, Harness.ProfileComponentIdentities) and self.values == other.values
    class ProfileExecution:
        def __init__(self, value, *, mutation_count): self.value, self.mutation_count = value, mutation_count
    class ProfileExecutionContext:
        def __init__(self, identity, value): self.identity, self.value = identity, value
    class ProfileComparison:
        def __init__(self, status, result_identity): self.status, self.result_identity = status, result_identity


class ExactHarnessV2:
    """Hermetic model of the reviewed Harness V2 validation boundary.

    Its request and plan checks deliberately match the pinned V2 public
    contract, including Recorder/store binding.  Validate never calls execute,
    record, verify, or a configured-source reader.
    """

    plan_fields = {
        "schema", "profile", "case_id", "candidate_sha", "ready_at",
        "producer_identity", "exporter_identity", "comparator_identity",
        "recorder_identity", "store_identity", "observation_identity",
    }
    calls = {"dispatch": 0, "record": 0, "verify": 0, "mutation": 0}
    run_calls = 0

    class ProfileComponentIdentities:
        def __init__(self, producer_identity, exporter_identity, comparator_identity):
            self.producer_identity = producer_identity
            self.exporter_identity = exporter_identity
            self.comparator_identity = comparator_identity
        def __eq__(self, other):
            return type(other) is ExactHarnessV2.ProfileComponentIdentities and self.__dict__ == other.__dict__

    class ProfileExecutionContext:
        def __init__(self, identity, value): self.identity, self.value = identity, value

    class ProfileExecution:
        def __init__(self, value, *, mutation_count): self.value, self.mutation_count = value, mutation_count

    class ProfileComparison:
        def __init__(self, status, result_identity): self.status, self.result_identity = status, result_identity

    class ExecutorRequest:
        def __init__(self, value):
            self.schema = value["schema"]
            self.capture_plan = value["capture_plan"]
            self.execution_context = value["execution_context"]
        @classmethod
        def parse(cls, value):
            if type(value) is not dict or set(value) != {"schema", "capture_plan", "execution_context"}:
                raise ValueError("V2 request is not closed")
            if value["schema"] != "roundwright-harness-profile-executor-request/v2":
                raise ValueError("wrong executor schema")
            if type(value["capture_plan"]) is not dict or type(value["execution_context"]) is not dict:
                raise ValueError("V2 request must be structured")
            return cls(value)

    @staticmethod
    def prepare_capture(plan):
        if type(plan) is not dict or set(plan) != ExactHarnessV2.plan_fields:
            raise ValueError("V2 plan is incomplete")
        if plan["schema"] != "roundwright-harness-capture-plan/v1":
            raise ValueError("wrong capture schema")
        return SimpleNamespace(
            plan_digest=digest(plan), profile=plan["profile"], case_id=plan["case_id"],
            candidate_sha=plan["candidate_sha"], ready_at=plan["ready_at"],
        )

    @staticmethod
    def run_profile_executor(mode, request_value, adapter, store_root, *, expected_readiness_digest=None):
        ExactHarnessV2.run_calls += 1
        if mode != "validate" or expected_readiness_digest is not None:
            raise ValueError("this hermetic gate only validates")
        request = ExactHarnessV2.ExecutorRequest.parse(request_value)
        plan = ExactHarnessV2.prepare_capture(request.capture_plan)
        components = adapter.component_identities
        context = adapter.prepare_execution_context(SimpleNamespace(
            descriptor=freeze_harness_json(request.execution_context), input_digest=digest(request.execution_context),
            components=components, plan=plan,
        ))
        binding = SimpleNamespace(
            profile=plan.profile, case_id=plan.case_id, candidate_sha=plan.candidate_sha,
            ready_at=plan.ready_at, plan=plan, components=components,
            execution_context=context, execution_context_input_digest=digest(request.execution_context),
        )
        adapter.validate(binding)
        return SimpleNamespace(
            status="ready", state="PREFLIGHT_READY", plan_digest=plan.plan_digest,
            dispatch_count=0, record_count=0, verify_count=0, mutation_count=0,
        )


class ConfiguredSourceTests(unittest.TestCase):
    candidate = "a" * 40
    policy = digest("policy")
    configuration = digest("configuration")

    def setUp(self):
        self.owner_state_directories = []

    def tearDown(self):
        for temporary in self.owner_state_directories:
            temporary.cleanup()

    def source(self, identity="team/queue", *, pages=2):
        return ConfiguredSource(SourceType.TASK_FEED, identity, pages, 10)

    def production_configuration(self, root, sources):
        config = root / "configured-sources.toml"
        rendered = ", ".join(
            "{ source_type = \"%s\", public_identity = \"%s\", max_pages = %d, max_items = %d }"
            % (source["source_type"], source["public_identity"], source["max_pages"], source["max_items"])
            for source in sources
        )
        config.write_text(
            "[runtime]\n"
            "schema_version = \"roundwright-runtime/v1\"\n"
            f"configured_sources = [{rendered}]\n",
            encoding="utf-8",
        )
        return load_configuration(cwd=root, user_config=config, environment={}, home=root / "home").pin()

    @staticmethod
    def issue_host():
        client = OwnerGitHubReadIpcClient(unavailable_capability_health())
        identity = digest("issue-host")
        receipt = CredentialedGitHubReadCapabilityBinding(
            "ythdelmar68/roundwright", "task-117", "a" * 40, identity,
            digest({
                "schema": "roundwright-credentialed-github-read-capability-binding/v1",
                "repository": "ythdelmar68/roundwright",
                "task_id": "task-117",
                "candidate_sha": "a" * 40,
                "capability_identity": identity,
            }),
        )
        with (
            patch("roundwright.configured_source.credentialed_github_read_capability_identity", return_value=identity),
            patch("roundwright.configured_source.credentialed_github_read_capability_binding", return_value=receipt),
        ):
            return create_issue_list_read_host(client)

    def item(self, public, member, content="a", mechanical="1"):
        return SourceItem(public, member, digest({"content": content}), digest({"mechanical": mechanical}))

    def inventory(self, sources, pages):
        return scan_configured_sources(SourceIngestionBinding(self.candidate, self.policy, self.configuration, tuple(sources)), Adapter(pages))

    @staticmethod
    def seal_owner_blocker_state(repository, candidate, task_id="task-117", repository_id="repo-117"):
        suffix = task_id.removeprefix("task-")
        identity = TaskIdentity(
            task_id, f"source-{suffix}", repository_id, f"codex/{suffix}",
            f"C:/configured-source-{suffix}", "b" * 40,
        )
        lease = acquire_transition_lease(repository, repository_id=identity.repository_id, owner="configured-source-tests", ttl_seconds=60)
        admit_task(repository, identity, (SourceSnapshot(identity.source_id, identity.repository_id, "c" * 64),), lease=lease)
        connection = sqlite3.connect(database_path(repository))
        try:
            connection.execute(
                "INSERT INTO candidate_seals(task_id, base_sha, candidate_sha, state_identity) VALUES (?, ?, ?, ?)",
                (identity.task_id, identity.base_sha, candidate, lease.state_identity),
            )
            connection.commit()
        finally:
            connection.close()
        return identity

    def owner_blocker_host(self, candidate=None, *, task_id="task-117", repository_id="repo-117"):
        temporary = tempfile.TemporaryDirectory()
        self.owner_state_directories.append(temporary)
        repository = object.__new__(RepositoryIdentity)
        object.__setattr__(repository, "root", Path(temporary.name).resolve())
        initialize(repository)
        self.seal_owner_blocker_state(
            repository, candidate or self.candidate, task_id, repository_id,
        )
        return _create_owner_blocker_state_read_host(repository, task_id, candidate or self.candidate)

    @staticmethod
    def source_authority(binding, graph=None, *, repository_id="repo-117", task_id="task-117"):
        return _seal_configured_source_authority(
            binding, graph, repository_id=repository_id, task_id=task_id,
        )

    def source_host(self, authority, reader, blocker_host):
        capability = _create_task_feed_fixture_capability(reader.pages)
        reader.source_capability = capability
        return TrustedConfiguredSourceReadHost(
            authority,
            create_configured_source_read_capability(
                authority, task_id=blocker_host.receipt.task_id,
                owner_blocker_receipt=blocker_host.receipt,
                task_feed=create_task_feed_read_host(capability, authority, blocker_host.receipt),
            ),
        )

    def test_only_explicit_bounded_sources_and_cursor_progress_are_accepted(self):
        source = self.source()
        first = SourcePage(source, None, "page-2", (self.item("item/a", "task-a"),))
        second = SourcePage(source, "page-2", None, (self.item("item/b", "task-b", "b", "2"),))
        inventory = self.inventory((source,), {(source.public_identity, None): first, (source.public_identity, "page-2"): second})
        self.assertEqual([item.member_id for item in inventory.items], ["task-a", "task-b"])
        with self.assertRaises(ConfiguredSourceError):
            ConfiguredSource(SourceType.TASK_FEED, "org/*", 1, 1)
        loop = SourcePage(source, None, "same", ())
        with self.assertRaises(ConfiguredSourceError):
            self.inventory((source,), {(source.public_identity, None): loop, (source.public_identity, "same"): SourcePage(source, "same", "same", ())})

    def test_page_budget_rejects_continuation_without_an_overread(self):
        source = self.source(pages=1)
        reader = Adapter({(source.public_identity, None): SourcePage(source, None, "next", ())})
        with self.assertRaises(ConfiguredSourceError):
            scan_configured_sources(SourceIngestionBinding(self.candidate, self.policy, self.configuration, (source,)), reader)
        self.assertEqual(reader.calls, [(source.public_identity, None)])

    def test_member_identity_ambiguity_is_retained_as_blocked_decisions(self):
        source = self.source()
        first = self.item("item/a", "task-a", content="one", mechanical="one")
        second = self.item("item/b", "task-a", content="two", mechanical="two")
        inventory = self.inventory((source,), {(source.public_identity, None): SourcePage(source, None, None, (first, second))})
        result = select_runnable_work(inventory, None)
        self.assertEqual(len(result.decisions), 2)
        self.assertTrue(all("member-identity-ambiguous" in decision.blockers for decision in result.decisions))

    def test_production_binding_derives_only_the_resolved_typed_allowlist(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "configured-sources.toml"
            config.write_text(
                "[runtime]\n"
                "schema_version = \"roundwright-runtime/v1\"\n"
                "configured_sources = [{ source_type = \"task-feed\", public_identity = \"team/queue\", max_pages = 2, max_items = 10 }]\n",
                encoding="utf-8",
            )
            resolved = load_configuration(cwd=root, user_config=config, environment={}, home=root / "home").pin()
        binding = resolve_source_ingestion_binding(resolved, self.candidate)
        self.assertEqual(binding.configured_sources, (self.source(),))
        self.assertEqual(binding.configuration_digest, resolved.digest)
        self.assertEqual(binding.policy_digest, "sha256:" + resolved.runtime_binding().review_policy_digest)
        with self.assertRaises(ConfiguredSourceError):
            resolve_source_ingestion_binding(resolved, "not-a-sha")

    def test_issue_list_capability_receipt_must_match_repository_task_and_candidate(self):
        source = ConfiguredSource(SourceType.ISSUE_LIST, "ythdelmar68/roundwright/issue/117", 1, 1)
        host = self.issue_host()
        owner_blocker_host = self.owner_blocker_host()
        binding = SourceIngestionBinding(self.candidate, self.policy, self.configuration, (source,))
        authority = self.source_authority(binding)
        with self.assertRaises(ConfiguredSourceError):
            create_configured_source_read_capability(authority, task_id="task-118", owner_blocker_receipt=owner_blocker_host.receipt, issue_list=host)
        changed_candidate = self.source_authority(
            SourceIngestionBinding("b" * 40, self.policy, self.configuration, (source,)),
        )
        with self.assertRaises(ConfiguredSourceError):
            create_configured_source_read_capability(changed_candidate, task_id="task-117", owner_blocker_receipt=owner_blocker_host.receipt, issue_list=host)
        other_repository = self.source_authority(SourceIngestionBinding(
            self.candidate, self.policy, self.configuration,
            (ConfiguredSource(SourceType.ISSUE_LIST, "other/repository/issue/117", 1, 1),),
        ))
        with self.assertRaises(ConfiguredSourceError):
            create_configured_source_read_capability(other_repository, task_id="task-117", owner_blocker_receipt=owner_blocker_host.receipt, issue_list=host)

    def configured_host_inputs(self, authority, reader, *, base_sha="b" * 40, case_id="configured-source-case", ready_at=71, recorder=None, store=None):
        blocker_host = self.owner_blocker_host(authority.binding.candidate_sha)
        read_host = self.source_host(authority, reader, blocker_host)
        return ConfiguredSourceHostInputs(
            base_sha, authority, case_id, ready_at, read_host,
            recorder or digest("recorder"), store or digest("store"),
            blocker_host.receipt.blockers_pending, blocker_host.receipt, blocker_host,
        )

    def test_production_prepare_treats_one_source_graph_as_not_applicable(self):
        source = {"source_type": "issue-list", "public_identity": "ythdelmar68/roundwright/issue/117", "max_pages": 1, "max_items": 1}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = object.__new__(RepositoryIdentity)
            object.__setattr__(repository, "root", root.resolve())
            initialize(repository)
            self.seal_owner_blocker_state(repository, self.candidate)
            configuration = self.production_configuration(root, [source])
            ExactHarnessV2.run_calls = 0
            with patch("roundwright.external_validation._harness_executor", return_value=ExactHarnessV2):
                inputs, request = prepare_configured_source_ingestion(
                    repository, configuration, self.candidate, "b" * 40, "configured-source-case", 71,
                    digest("recorder"), digest("store"), "task-117", issue_list=self.issue_host(),
                )
        self.assertIsNone(inputs.graph)
        self.assertEqual(inputs.authority.graph_applicability.value, "not-applicable")
        self.assertIsNone(request["execution_context"]["graph_digest"])
        self.assertEqual(ExactHarnessV2.run_calls, 0)

    def test_production_prepare_requires_current_owner_blocker_seal(self):
        source = {"source_type": "issue-list", "public_identity": "ythdelmar68/roundwright/issue/117", "max_pages": 1, "max_items": 1}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = object.__new__(RepositoryIdentity)
            object.__setattr__(repository, "root", root.resolve())
            initialize(repository)
            configuration = self.production_configuration(root, [source])
            with self.assertRaises(ConfiguredSourceError):
                prepare_configured_source_ingestion(
                    repository, configuration, self.candidate, "b" * 40, "configured-source-case", 71,
                    digest("recorder"), digest("store"), "task-117", issue_list=self.issue_host(),
                )

    def test_execution_rejects_owner_blocker_receipt_drift_before_source_read(self):
        source = ConfiguredSource(SourceType.TASK_FEED, "team/queue", 1, 1)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = object.__new__(RepositoryIdentity)
            object.__setattr__(repository, "root", root.resolve())
            initialize(repository)
            self.seal_owner_blocker_state(repository, self.candidate)
            configuration = self.production_configuration(root, [{
                "source_type": source.source_type.value, "public_identity": source.public_identity,
                "max_pages": source.max_pages, "max_items": source.max_items,
            }])
            capability = _create_task_feed_fixture_capability({
                (source.public_identity, None): SourcePage(source, None, None, ()),
            })
            with patch("roundwright.external_validation._harness_executor", return_value=ExactHarnessV2):
                inputs, _ = prepare_configured_source_ingestion(
                    repository, configuration, self.candidate, "b" * 40, "configured-source-case", 71,
                    digest("recorder"), digest("store"), "task-117",
                    task_feed=capability,
                )
            connection = sqlite3.connect(database_path(repository))
            try:
                connection.execute("UPDATE candidate_seals SET candidate_sha = ? WHERE task_id = ?", ("c" * 40, "task-117"))
                connection.commit()
            finally:
                connection.close()
            capture = digest(configured_source_capture_plan(inputs))
            plan = SimpleNamespace(candidate_sha=self.candidate, case_id=inputs.case_id, plan_digest=capture, ready_at=inputs.ready_at)
            context = inputs.execution_context(capture)
            binding = SimpleNamespace(
                profile="roundwright-shadow-profile/configured-source-ingestion/v1", case_id=inputs.case_id,
                candidate_sha=self.candidate, ready_at=inputs.ready_at, plan=plan,
                components=SimpleNamespace(**dict(zip(("producer_identity", "exporter_identity", "comparator_identity"), configured_source_component_identities(), strict=True))),
                execution_context=SimpleNamespace(value=inputs, identity=digest({
                    "observation_identity": inputs.observation_identity, "capture_plan_digest": capture,
                    "execution_context_input_digest": digest(context),
                })),
                execution_context_input_digest=digest(context),
            )
            with patch("roundwright.external_validation._harness_executor", return_value=ExactHarnessV2), self.assertRaises(ConfiguredSourceError):
                ConfiguredSourceIngestionAdapter(inputs).execute(binding)
        self.assertEqual(capability.source_read_count, 0)

    def test_production_prepare_requires_matching_current_graph_for_multiple_sources(self):
        sources = [
            {"source_type": "issue-list", "public_identity": "ythdelmar68/roundwright/issue/117", "max_pages": 1, "max_items": 1},
            {"source_type": "issue-list", "public_identity": "ythdelmar68/roundwright/issue/118", "max_pages": 1, "max_items": 1},
        ]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = object.__new__(RepositoryIdentity)
            object.__setattr__(repository, "root", root.resolve())
            initialize(repository)
            self.seal_owner_blocker_state(repository, self.candidate)
            configuration = self.production_configuration(root, sources)
            with self.assertRaises(ConfiguredSourceError):
                prepare_configured_source_ingestion(repository, configuration, self.candidate, "b" * 40, "configured-source-case", 71, digest("recorder"), digest("store"), "task-117", issue_list=self.issue_host())
            binding = resolve_source_ingestion_binding(configuration, self.candidate)
            graph_binding = DependencyGraphBinding(binding.candidate_sha, binding.policy_digest, binding.configuration_digest)
            current = GraphSnapshot("graph-117", graph_binding, (), (), ())
            ExactHarnessV2.run_calls = 0
            with patch.object(DependencyGraphStore, "current", return_value=current), patch("roundwright.external_validation._harness_executor", return_value=ExactHarnessV2):
                inputs, _ = prepare_configured_source_ingestion(repository, configuration, self.candidate, "b" * 40, "configured-source-case", 71, digest("recorder"), digest("store"), "task-117", issue_list=self.issue_host())
        self.assertEqual(inputs.graph, current)
        self.assertEqual(inputs.authority.graph_applicability.value, "required")
        self.assertEqual(ExactHarnessV2.run_calls, 0)

    def test_owner_host_factories_expose_no_callback_or_claimed_identity_seam(self):
        source = self.source()
        reader = Adapter({(source.public_identity, None): SourcePage(source, None, None, ())})
        with self.assertRaises(ConfiguredSourceError):
            create_task_feed_read_host(reader.read, None, None)
        from roundwright.configured_source import create_issue_list_read_host
        with self.assertRaises(ConfiguredSourceError):
            create_issue_list_read_host(reader.read)

    def test_host_inputs_require_a_sealed_owner_blocker_receipt_before_source_or_harness(self):
        source = self.source()
        reader = Adapter({(source.public_identity, None): SourcePage(source, None, None, ())})
        authority = self.source_authority(
            SourceIngestionBinding(self.candidate, self.policy, self.configuration, (source,)),
        )
        blocker_host = self.owner_blocker_host()
        read_host = self.source_host(authority, reader, blocker_host)
        with self.assertRaises(ConfiguredSourceError):
            ConfiguredSourceHostInputs(
                "b" * 40, authority, "configured-source-case", 71, read_host,
                digest("recorder"), digest("store"), False, None, None,
            )
        self.assertEqual(reader.calls, [])
        self.assertEqual(reader.source_capability.source_read_count, 0)

    def test_task_feed_authority_rejects_cross_task_and_repository_before_read(self):
        source = self.source()
        reader = Adapter({(source.public_identity, None): SourcePage(source, None, None, ())})
        authority = self.source_authority(
            SourceIngestionBinding(self.candidate, self.policy, self.configuration, (source,)),
        )
        expected = self.owner_blocker_host()
        task_mismatch = self.owner_blocker_host(task_id="task-118")
        repository_mismatch = self.owner_blocker_host(repository_id="repo-118")
        capability = _create_task_feed_fixture_capability(reader.pages)

        for mismatched in (task_mismatch, repository_mismatch):
            with self.subTest(mismatched=mismatched.receipt), self.assertRaises(ConfiguredSourceError):
                create_configured_source_read_capability(
                    authority, task_id=expected.receipt.task_id,
                    owner_blocker_receipt=expected.receipt,
                    task_feed=create_task_feed_read_host(capability, authority, mismatched.receipt),
                )
            self.assertEqual(capability.source_read_count, 0)

    def test_host_inputs_reject_cross_task_feed_receipt_before_read(self):
        source = self.source()
        reader = Adapter({(source.public_identity, None): SourcePage(source, None, None, ())})
        binding = SourceIngestionBinding(self.candidate, self.policy, self.configuration, (source,))
        authority = self.source_authority(binding)
        expected = self.owner_blocker_host()
        mismatched = self.owner_blocker_host(task_id="task-118")
        mismatched_authority = self.source_authority(binding, task_id="task-118")
        capability = _create_task_feed_fixture_capability(reader.pages)
        read_host = TrustedConfiguredSourceReadHost(
            mismatched_authority,
            create_configured_source_read_capability(
                mismatched_authority, task_id=mismatched.receipt.task_id,
                owner_blocker_receipt=mismatched.receipt,
                task_feed=create_task_feed_read_host(capability, mismatched_authority, mismatched.receipt),
            ),
        )
        with self.assertRaises(ConfiguredSourceError):
            ConfiguredSourceHostInputs(
                "b" * 40, authority, "configured-source-case", 71, read_host,
                digest("recorder"), digest("store"), expected.receipt.blockers_pending,
                expected.receipt, expected,
            )
        self.assertEqual(capability.source_read_count, 0)

    def test_host_inputs_reject_self_consistent_foreign_repository_before_read(self):
        source = self.source()
        reader = Adapter({(source.public_identity, None): SourcePage(source, None, None, ())})
        binding = SourceIngestionBinding(self.candidate, self.policy, self.configuration, (source,))
        authority_a = self.source_authority(binding, repository_id="repo-117")
        authority_b = self.source_authority(binding, repository_id="repo-118")
        owner_b = self.owner_blocker_host(repository_id="repo-118")
        capability = _create_task_feed_fixture_capability(reader.pages)
        read_host_b = TrustedConfiguredSourceReadHost(
            authority_b,
            create_configured_source_read_capability(
                authority_b, task_id=owner_b.receipt.task_id,
                owner_blocker_receipt=owner_b.receipt,
                task_feed=create_task_feed_read_host(capability, authority_b, owner_b.receipt),
            ),
        )
        with self.assertRaises(ConfiguredSourceError):
            ConfiguredSourceHostInputs(
                "b" * 40, authority_a, "configured-source-case", 71, read_host_b,
                digest("recorder"), digest("store"), owner_b.receipt.blockers_pending,
                owner_b.receipt, owner_b,
            )
        self.assertEqual(capability.source_read_count, 0)

    def test_identical_typed_endpoint_reconstruction_is_stable_and_changed_endpoint_is_not(self):
        source = self.source()
        page = SourcePage(source, None, None, (self.item("item/a", "task-a"),))
        stable_first = _create_task_feed_fixture_capability({(source.public_identity, None): page})
        stable_second = _create_task_feed_fixture_capability({(source.public_identity, None): page})
        changed = _create_task_feed_fixture_capability({
            (source.public_identity, None): SourcePage(source, None, None, (self.item("item/a", "task-a", content="changed"),)),
        })
        self.assertEqual(stable_first.endpoint_identity, stable_second.endpoint_identity)
        self.assertNotEqual(stable_first.endpoint_identity, changed.endpoint_identity)

    def test_only_mechanically_identical_items_merge_and_content_collision_blocks(self):
        first, second = self.source("team/one"), self.source("team/two")
        identical = self.item("item/a", "task-a")
        same_content_other_identity = self.item("item/b", "task-b", mechanical="2")
        inventory = self.inventory(
            (first, second),
            {(first.public_identity, None): SourcePage(first, None, None, (identical,)),
             (second.public_identity, None): SourcePage(second, None, None, (same_content_other_identity,))},
        )
        self.assertEqual(len(inventory.items), 2)
        result = select_runnable_work(inventory, None)
        self.assertTrue(all("current-graph-unavailable" in decision.blockers for decision in result.decisions))
        self.assertTrue(any("ambiguous-deduplication" in decision.blockers for decision in result.decisions))

    def test_multi_source_selection_requires_current_matching_graph_and_leaves_unrelated_root_runnable(self):
        first, second = self.source("team/one"), self.source("team/two")
        a, b, c = self.item("item/a", "task-a"), self.item("item/b", "task-b", "b", "2"), self.item("item/c", "task-c", "c", "3")
        inventory = self.inventory(
            (first, second),
            {(first.public_identity, None): SourcePage(first, None, None, (a, b)),
             (second.public_identity, None): SourcePage(second, None, None, (c,))},
        )
        binding = DependencyGraphBinding(self.candidate, self.policy, self.configuration)
        members = tuple(GraphMember("task-117", "subset-117", AffectedMember(item.member_id, digest({"fingerprint": item.member_id}), item.content_digest)) for item in inventory.items)
        edges = (GraphEdge("task-a", "task-b", EdgeKind.EXPLICIT, "proposal-117", digest("edge")),)
        graph = GraphSnapshot("graph-117", binding, members, edges, ("proposal-117",))
        result = select_runnable_work(inventory, graph)
        by_id = {decision.opaque_id: decision for decision in result.decisions}
        self.assertEqual(len(result.runnable_ids), 2)
        self.assertTrue(any("dependency-not-complete" in decision.blockers for decision in by_id.values()))

    def test_inventory_store_is_append_only_and_content_addressed(self):
        source = self.source()
        inventory = self.inventory((source,), {(source.public_identity, None): SourcePage(source, None, None, (self.item("item/a", "task-a"),))})
        with tempfile.TemporaryDirectory() as temporary:
            repository = object.__new__(RepositoryIdentity)
            object.__setattr__(repository, "root", Path(temporary).resolve())
            initialize(repository)
            store = ConfiguredSourceStore()
            self.assertEqual(store.record(repository, inventory), inventory.inventory_digest)
            self.assertEqual(store.record(repository, inventory), inventory.inventory_digest)
            self.assertEqual(json.loads(store.read(repository, inventory.inventory_digest))["candidate_sha"], self.candidate)

    def test_profile_exports_public_safe_capture_time_evidence_without_a_provider(self):
        source = self.source()
        item = self.item("item/private-looking", "task-a")
        source_binding = SourceIngestionBinding(self.candidate, self.policy, self.configuration, (source,))
        graph_binding = DependencyGraphBinding(self.candidate, self.policy, self.configuration)
        graph = GraphSnapshot(
            "graph-117", graph_binding,
            (GraphMember("task-117", "subset-117", AffectedMember("task-a", digest("member"), item.content_digest)),), (), (),
        )
        reader = Adapter({(source.public_identity, None): SourcePage(source, None, None, (item,))})
        authority = self.source_authority(source_binding)
        host = self.configured_host_inputs(authority, reader)
        capture = digest(configured_source_capture_plan(host))
        plan = SimpleNamespace(candidate_sha=self.candidate, case_id=host.case_id, plan_digest=capture, ready_at=71)
        context_value = host.execution_context(capture)
        binding = SimpleNamespace(
            profile="roundwright-shadow-profile/configured-source-ingestion/v1", case_id=host.case_id,
            candidate_sha=self.candidate, ready_at=71, plan=plan,
            components=SimpleNamespace(**dict(zip(("producer_identity", "exporter_identity", "comparator_identity"), configured_source_component_identities(), strict=True))),
            execution_context=SimpleNamespace(value=host, identity=digest({
                "observation_identity": host.observation_identity, "capture_plan_digest": capture,
                "execution_context_input_digest": digest(context_value),
            })),
            execution_context_input_digest=digest(context_value),
        )
        with patch("roundwright.external_validation._harness_executor", return_value=Harness):
            adapter = ConfiguredSourceIngestionAdapter(host)
            adapter.validate(binding)
            execution = adapter.execute(binding)
            evidence = adapter.project(binding, execution)
            comparison = adapter.compare(binding, evidence)
            self.assertEqual((execution.mutation_count, comparison.status), (0, "pass"))
            self.assertEqual(evidence["ready_at"], 71)
            self.assertNotIn("item/private-looking", json.dumps(evidence))
            self.assertEqual(evidence["configured_source_ingestion"]["zero_mutation_proof"]["provider_dispatch_count"], 0)
            changed = dict(evidence); changed["ready_at"] = 72
            self.assertEqual(adapter.compare(binding, changed).status, "fail")
            self.assertEqual(configured_source_capture_plan(host)["observation_identity"], host.observation_identity)

    def test_exact_v2_harness_validate_is_closed_and_performs_zero_live_actions(self):
        source = self.source()
        item = self.item("item/a", "task-a")
        source_binding = SourceIngestionBinding(self.candidate, self.policy, self.configuration, (source,))
        graph = GraphSnapshot(
            "graph-117", DependencyGraphBinding(self.candidate, self.policy, self.configuration),
            (GraphMember("task-117", "subset-117", AffectedMember("task-a", digest("member"), item.content_digest)),), (), (),
        )
        reader = Adapter({(source.public_identity, None): SourcePage(source, None, None, (item,))})
        authority = self.source_authority(source_binding)
        host = self.configured_host_inputs(authority, reader)
        ExactHarnessV2.calls = {"dispatch": 0, "record": 0, "verify": 0, "mutation": 0}
        with patch("roundwright.external_validation._harness_executor", return_value=ExactHarnessV2):
            request = configured_source_executor_request(host)
            receipt = run_configured_source_ingestion_profile("validate", request, Path("unused-store"), host)
        self.assertEqual(receipt.state, "PREFLIGHT_READY")
        self.assertEqual(
            (receipt.dispatch_count, receipt.record_count, receipt.verify_count, receipt.mutation_count),
            (0, 0, 0, 0),
        )
        self.assertEqual(reader.calls, [])
        self.assertEqual(ExactHarnessV2.calls, {"dispatch": 0, "record": 0, "verify": 0, "mutation": 0})
        self.assertEqual(set(request["capture_plan"]), ExactHarnessV2.plan_fields)
        self.assertEqual(request["capture_plan"]["observation_identity"], host.observation_identity)

    def test_preflight_rejects_capability_authority_and_request_movement_before_read(self):
        source = self.source()
        item = self.item("item/a", "task-a")
        binding = SourceIngestionBinding(self.candidate, self.policy, self.configuration, (source,))
        graph = GraphSnapshot(
            "graph-117", DependencyGraphBinding(self.candidate, self.policy, self.configuration),
            (GraphMember("task-117", "subset-117", AffectedMember("task-a", digest("member"), item.content_digest)),), (), (),
        )
        reader = Adapter({(source.public_identity, None): SourcePage(source, None, None, (item,))})
        authority = self.source_authority(binding)
        host = self.configured_host_inputs(authority, reader)
        different_reader = Adapter({
            (source.public_identity, None): SourcePage(source, None, None, (self.item("item/a", "task-a", content="replacement"),)),
        })
        changed_capability = self.configured_host_inputs(
            authority, different_reader, base_sha=host.base_sha,
            case_id=host.case_id, ready_at=host.ready_at, recorder=host.recorder_identity, store=host.store_identity,
        )
        changed_source = self.source("team/other")
        changed_binding = SourceIngestionBinding(self.candidate, self.policy, self.configuration, (changed_source,))
        changed_source_graph = GraphSnapshot("graph-119", DependencyGraphBinding(self.candidate, self.policy, self.configuration), graph.members, graph.edges, graph.proposal_ids)
        changed_source_authority = self.source_authority(changed_binding)
        changed_source_reader = Adapter({(changed_source.public_identity, None): SourcePage(changed_source, None, None, (item,))})
        changed_configuration = self.configured_host_inputs(
            changed_source_authority, changed_source_reader,
            base_sha=host.base_sha, case_id=host.case_id, ready_at=host.ready_at,
            recorder=host.recorder_identity, store=host.store_identity,
        )
        moved_candidate = "c" * 40
        moved_binding = SourceIngestionBinding(moved_candidate, self.policy, self.configuration, (source,))
        moved_graph = GraphSnapshot(
            "graph-120", DependencyGraphBinding(moved_candidate, self.policy, self.configuration),
            graph.members, graph.edges, graph.proposal_ids,
        )
        moved_authority = self.source_authority(moved_binding)
        moved_candidate_host = self.configured_host_inputs(
            moved_authority, reader, base_sha=host.base_sha,
            case_id=host.case_id, ready_at=host.ready_at, recorder=host.recorder_identity, store=host.store_identity,
        )
        changed_ready = ConfiguredSourceHostInputs(host.base_sha, authority, host.case_id, 72, host.read_host, host.recorder_identity, host.store_identity, host.owner_blockers_pending, host.owner_blocker_receipt, host.owner_blocker_read_host)
        changed_recorder = ConfiguredSourceHostInputs(host.base_sha, authority, host.case_id, host.ready_at, host.read_host, digest("other-recorder"), host.store_identity, host.owner_blockers_pending, host.owner_blocker_receipt, host.owner_blocker_read_host)
        changed_store = ConfiguredSourceHostInputs(host.base_sha, authority, host.case_id, host.ready_at, host.read_host, host.recorder_identity, digest("other-store"), host.owner_blockers_pending, host.owner_blocker_receipt, host.owner_blocker_read_host)
        ExactHarnessV2.run_calls = 0
        with patch("roundwright.external_validation._harness_executor", return_value=ExactHarnessV2):
            request = configured_source_executor_request(host)
            for moved in (changed_capability, changed_configuration, moved_candidate_host, changed_ready, changed_recorder, changed_store):
                with self.subTest(moved=moved.observation_identity), self.assertRaises(Exception):
                    run_configured_source_ingestion_profile("validate", request, Path("unused-store"), moved)
        self.assertEqual(ExactHarnessV2.run_calls, 0)
        self.assertEqual(reader.calls, [])
        self.assertEqual(reader.source_capability.source_read_count, 0)
        self.assertEqual(different_reader.source_capability.source_read_count, 0)
        self.assertEqual(changed_source_reader.calls, [])


if __name__ == "__main__":
    unittest.main()
