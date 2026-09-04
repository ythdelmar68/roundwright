"""Regression coverage for the Phase 5 public-safe coverage map."""

from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("phase5_coverage", ROOT / "ci" / "validate_phase5_coverage.py")
assert SPEC and SPEC.loader
coverage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(coverage)


class Phase5CoverageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.source = self.directory / "map.json"
        self.ledger = self.directory / "ledger.md"
        self.tests = self.directory / "tests.md"
        shutil.copy2(ROOT / "docs" / "migration" / "phase5-coverage-map.json", self.source)
        shutil.copy2(ROOT / "docs" / "migration" / "legacy-decision-ledger.md", self.ledger)
        shutil.copy2(ROOT / "docs" / "migration" / "test-disposition.md", self.tests)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def document(self) -> dict[str, object]:
        return json.loads(self.source.read_text(encoding="utf-8"))

    def write_document(self, document: dict[str, object]) -> None:
        self.source.write_text(json.dumps(document, sort_keys=True) + "\n", encoding="utf-8")

    def test_validates_exact_inventory_and_renders_candidate_bound_readback(self) -> None:
        document = coverage.validate(self.source, self.ledger, self.tests)
        self.assertEqual(len(document["items"]), len(coverage.EXPECTED_OWNERS))
        manifest = self.directory / "readback.json"
        candidate = coverage.current_candidate()
        coverage.render(self.source, self.ledger, self.tests, candidate, manifest)
        coverage.verify(self.source, self.ledger, self.tests, candidate, manifest)

    def test_rejects_duplicate_unknown_and_owner_drift(self) -> None:
        document = self.document()
        items = document["items"]
        items.append(items[0].copy())
        self.write_document(document)
        with self.assertRaisesRegex(coverage.CoverageError, "duplicate"):
            coverage.validate(self.source, self.ledger, self.tests)
        items.pop()
        items[0]["id"] = "EV-FFFFFFFFFFFF"
        self.write_document(document)
        with self.assertRaisesRegex(coverage.CoverageError, "owner issue"):
            coverage.validate(self.source, self.ledger, self.tests)

    def test_rejects_public_safe_destination_drift(self) -> None:
        document = self.document()
        document["items"][0]["destination"] = "another-public-safe-target"
        self.write_document(document)
        with self.assertRaisesRegex(coverage.CoverageError, "destination has drifted"):
            coverage.validate(self.source, self.ledger, self.tests)

    def test_rejects_verification_drift_and_unsafe_verification_values(self) -> None:
        document = self.document()
        for verification, expected_error in (
            ("another-public-safe-contract", "verification has drifted"),
            ("ythdelmar68/roundwright", "unsafe"),
            ("/private/roundwright/evidence", "unsafe"),
            ("raw-internal-evidence", "unsafe"),
            ("owner-reasoning", "unsafe"),
        ):
            document["items"][0]["verification"] = verification
            self.write_document(document)
            with self.subTest(verification=verification), self.assertRaisesRegex(coverage.CoverageError, expected_error):
                coverage.validate(self.source, self.ledger, self.tests)

    def test_rejects_disposition_prerequisite_confidence_and_status_drift(self) -> None:
        baseline = self.document()
        for field, value, expected_error in (
            ("disposition", "adopt", "disposition has drifted"),
            ("prerequisites", ["#118"], "prerequisites have drifted"),
            ("confidence", "low", "confidence has drifted"),
            ("status", "blocked", "status has drifted"),
        ):
            document = json.loads(json.dumps(baseline))
            item = next(item for item in document["items"] if item["id"] == "EV-0F91CDC81DEA")
            item[field] = value
            self.write_document(document)
            with self.subTest(field=field), self.assertRaisesRegex(coverage.CoverageError, expected_error):
                coverage.validate(self.source, self.ledger, self.tests)

    def test_required_source_selection_survives_map_and_binding_omission(self) -> None:
        identifier = "TS-856DFB0B5E51"
        document = self.document()
        document["items"] = [item for item in document["items"] if item["id"] != identifier]
        self.write_document(document)
        tables = (
            "EXPECTED_OWNERS", "EXPECTED_DESTINATIONS", "EXPECTED_VERIFICATIONS", "EXPECTED_DISPOSITIONS",
            "EXPECTED_PREREQUISITES", "EXPECTED_CONFIDENCES", "EXPECTED_STATUSES",
        )
        with ExitStack() as stack:
            for name in tables:
                values = getattr(coverage, name)
                stack.enter_context(patch.object(coverage, name, {key: value for key, value in values.items() if key != identifier}))
            with self.assertRaisesRegex(coverage.CoverageError, "required Phase 5 source inventory is omitted"):
                coverage.validate(self.source, self.ledger, self.tests)

    def test_rejects_stale_sources_unsafe_text_and_candidate_drift(self) -> None:
        document = self.document()
        document["items"][0]["destination"] = "C:/private/source"
        self.write_document(document)
        with self.assertRaisesRegex(coverage.CoverageError, "unsafe"):
            coverage.validate(self.source, self.ledger, self.tests)
        document["items"][0]["destination"] = "promotion-evaluation"
        document["sources"]["ledger_sha256"] = "a" * 64
        self.write_document(document)
        with self.assertRaisesRegex(coverage.CoverageError, "drifted"):
            coverage.validate(self.source, self.ledger, self.tests)
        shutil.copy2(ROOT / "docs" / "migration" / "phase5-coverage-map.json", self.source)
        manifest = self.directory / "readback.json"
        candidate = coverage.current_candidate()
        coverage.render(self.source, self.ledger, self.tests, candidate, manifest)
        other_candidate = "0" * 40 if candidate != "0" * 40 else "1" * 40
        with self.assertRaisesRegex(coverage.CoverageError, "does not match checked-out HEAD"):
            coverage.verify(self.source, self.ledger, self.tests, other_candidate, manifest)
