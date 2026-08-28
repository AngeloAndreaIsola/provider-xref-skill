"""
test_phase10_extraction_rules.py — Phase 10: extraction-rule coverage for
high-leverage UNKNOWN-policy API-key providers, and the plan-file naming fix.

These providers are the first Phase 10 registration candidates (api_key auth,
reusable generic api_key workflow):
  - deepinfra  (JWT bearer token)
  - siliconflow (sk- prefix)
  - nebius     (xnd_ prefix)

Also guards the planner bug fixed in Phase 10: plan files were written as
``plan_plan_<hash>.json`` because uuid_id("plan") already prefixes "plan_".
"""
import sys
import os
import json
import re

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from adapters.credential_extractor import (
    get_extraction_rules,
    extract_credential,
    PageSnapshot,
    ExtractionRule,
    ExtractionStrategy,
)
from engine import utils as utils_mod
from engine.planner import plan_new_phone


# ── Extraction rule coverage ──────────────────────────────────────────────


class TestPhase10ExtractionRules:
    """New UNKNOWN-policy providers have accurate extraction rules."""

    def test_deepinfra_rule_present(self):
        rules = get_extraction_rules("deepinfra")
        assert rules, "deepinfra must have a rule"
        assert rules[0].credential_type == "api_key"
        assert "JWT" in rules[0].description or "bearer" in rules[0].description.lower()

    def test_siliconflow_rule_present(self):
        rules = get_extraction_rules("siliconflow")
        assert rules, "siliconflow must have a rule"
        assert rules[0].prefix == "sk-"

    def test_nebius_rule_present(self):
        rules = get_extraction_rules("nebius")
        assert rules, "nebius must have a rule"
        assert rules[0].prefix == "xnd_"

    def test_deepinfra_extracts_jwt(self):
        """DeepInfra keys are JWT bearer tokens — extract the token group."""
        snapshot = PageSnapshot(
            text="Your API key: Authorization: Bearer eyJabc123def456ghi789jkl012mno345pqr678stu901vwx234yz0123456789.end.more",
            url="https://deepinfra.com/dash/api-keys",
        )
        result = extract_credential(snapshot, get_extraction_rules("deepinfra"))
        assert result.found is True
        # The full secret is never in debug output — only a short masked prefix
        dbg = json.dumps(result.to_debug_dict())
        assert "eyJabc123def456ghi789jkl012mno345pqr678" not in dbg
        # The masked_value keeps only the first mask_after chars
        assert result.to_debug_dict()["masked_value"].count("*") > 8

    def test_siliconflow_extracts_sk(self):
        snapshot = PageSnapshot(
            text="export SILICONFLOW_API_KEY=sk-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
            url="https://cloud.siliconflow.cn/account/api-keys",
        )
        result = extract_credential(snapshot, get_extraction_rules("siliconflow"))
        assert result.found is True

    def test_nebius_extracts_xnd(self):
        snapshot = PageSnapshot(
            text="API key: xnd_9f8e7d6c5b4a39281706f5e4d3c2b1a0",
            url="https://nebius.ai/console/api-keys",
        )
        result = extract_credential(snapshot, get_extraction_rules("nebius"))
        assert result.found is True

    def test_new_rules_contain_no_secret_in_debug(self):
        """ExtractionResult debug dict must never leak the raw secret."""
        for pid in ("deepinfra", "siliconflow", "nebius"):
            rules = get_extraction_rules(pid)
            snap = PageSnapshot(
                text=f"key={rules[0].prefix}SECRETSAMPLEVALUE1234567890end",
                url="https://example.com/api-keys",
            )
            res = extract_credential(snap, rules)
            dbg = json.dumps(res.to_debug_dict())
            assert "SECRETSAMPLEVALUE" not in dbg


# ── Plan-file naming fix ──────────────────────────────────────────────────


class TestPlanFileNameFix:
    """plan_new_phone now writes <plan_id>.json, not plan_plan_<hash>.json."""

    def test_plan_filename_has_single_prefix(self, tmp_path, monkeypatch):
        # Redirect skill data dir to tmp
        from engine import planner as planner_mod

        def fake_skill_path(rel):
            return str(tmp_path / rel)

        monkeypatch.setattr(planner_mod, "_get_skill_path", fake_skill_path)
        # Use a minimal state so the function runs without external calls
        from engine.state import default_state

        state = default_state()
        # Ensure no identities so it's a new phone
        plan = plan_new_phone("+15555550199", state=state, catalog=None)
        plan_id = plan["id"]
        assert plan_id.startswith("plan_")
        expected = tmp_path / "data" / "plans" / f"{plan_id}.json"
        assert expected.exists(), f"Expected plan file at {expected}"
        # The double-prefix bug must not recur
        bad = tmp_path / "data" / "plans" / f"plan_{plan_id}.json"
        assert not bad.exists(), "Double 'plan_' prefix regressed"
