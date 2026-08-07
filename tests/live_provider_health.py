"""Explicit opt-in harness for already-resolved native provider channels."""
from __future__ import annotations
import importlib
import json
import os
import re
import sys
import time
from roundwright.configuration import Configuration
from roundwright.provider_health import CodexHealthContract, RoleBoundCodexCredentialStore
from roundwright.provider_health_live import run_bounded_live_provider_health_fixture

_SCHEMA = "roundwright-live-provider-health/v1"
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_CASE = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_FACTORY = re.compile(r"(?:[A-Za-z_]\w*\.)*[A-Za-z_]\w*:[A-Za-z_]\w*\Z")
def _emit(status: str) -> None: sys.stdout.write(json.dumps({"schema": _SCHEMA, "status": status}, separators=(",", ":")) + "\n")
def main() -> int:
    if os.environ.get("ROUNDWRIGHT_RUN_LIVE_PROVIDER_HEALTH") != "1": _emit("disabled"); return 2
    try:
        factory_name, commit, case = os.environ["ROUNDWRIGHT_LIVE_PROVIDER_FACTORY"], os.environ["ROUNDWRIGHT_CONTRACT_COMMIT"], os.environ["ROUNDWRIGHT_SHADOW_CASE_ID"]
        candidate = os.environ.get("ROUNDWRIGHT_CANDIDATE_SHA") or None
        if not _FACTORY.fullmatch(factory_name) or not _COMMIT.fullmatch(commit) or not _CASE.fullmatch(case) or (candidate is not None and not _COMMIT.fullmatch(candidate)): raise ValueError
        module, name = factory_name.split(":"); factory = getattr(importlib.import_module(module), name); value = factory()
        if type(value) is not tuple or len(value) != 3 or type(value[0]) is not RoleBoundCodexCredentialStore or type(value[1]) is not CodexHealthContract or type(value[2]) is not Configuration or value[1].contract_commit != commit: raise ValueError
        result = run_bounded_live_provider_health_fixture(*value, enabled=True, contract_commit=commit, candidate_sha=candidate, case_id=case, now=int(time.time()), freshness_seconds=60)
        evidence = result.owner_safe_evidence()
        sys.stdout.write(json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n"); return 0 if evidence["status"] == "ready" else 1
    except Exception:
        _emit("blocked"); return 1
if __name__ == "__main__": raise SystemExit(main())
