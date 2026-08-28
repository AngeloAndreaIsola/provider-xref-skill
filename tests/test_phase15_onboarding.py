"""
test_phase15_onboarding.py — Phase 15 data-driven provider onboarding.

The central claim under test: a provider can be onboarded by supplying
CATALOG + EXTRACTION data, without modifying engine code. Tests therefore
add a synthetic provider purely as data and assert the pipeline picks it up.

Also covers:
  * wave-1 providers (DeepInfra, SiliconFlow, Nebius) validate
  * the policy gate never auto-enables disallowed/restricted/unknown providers
  * planning is a pure dry-run (no mutations, no adapter calls)
  * no bulk registration
  * browser/checkpoint requirements come from data
  * plans are JSON-serializable and secret-free
"""

import copy
import json
import sys
from pathlib import Path

import pytest

SKILL_ROOT = Path(__file__).parent.parent
if str(SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT))

from engine.onboarding import (
    BLOCKED,
    NEEDS_DATA,
    NEEDS_REVIEW,
    PIPELINE_STAGES,
    PROVIDER_WAVE_1,
    READY,
    STAGE_BROWSER,
    STAGE_CAPABILITY,
    STAGE_CATALOG,
    STAGE_EXTRACTION,
    STAGE_OMNIROUTE,
    STAGE_ONEPASSWORD,
    STAGE_POLICY,
    STAGE_RECONCILE,
    STAGE_REVIEW,
    STAGE_WORKFLOW,
    can_onboard_from_data_only,
    onboarding_steps,
    plan_onboarding,
    plan_wave,
    validate_capability,
    validate_catalog_entry,
    validate_extraction,
    validate_policy,
)
from engine.review import assert_secret_free
from engine.catalog import load_catalog


@pytest.fixture
def real_catalog():
    return load_catalog()


def _clone_with_provider(catalog: dict, provider: dict) -> dict:
    c = copy.deepcopy(catalog)
    c["providers"] = [p for p in c["providers"] if p["id"] != provider["id"]]
    c["providers"].append(provider)
    return c


def synthetic_provider(pid="synthprov", policy_automation="allowed",
                       omniroute=True, extraction_ref="groq"):
    """A provider defined ENTIRELY as data — no engine change."""
    return {
        "id": pid,
        "name": "Synth Provider",
        "category": "llm",
        "auth_type": "api_key",
        "signup_url": "https://synthprov.example/signup",
        "login_url": "https://synthprov.example/login",
        "free_tier": {"enabled": True, "quota": "free", "type": "credit"},
        "identity_requirements": ["email"],
        "omniroute_support": {"supported": omniroute, "type": "direct"},
        "policy": {
            "multiple_accounts": "allowed",
            "duplicate_account_policy": "allowed",
            "automation_allowed": policy_automation,
            "third_party_proxy_allowed": "allowed",
            "phone_reuse_allowed": "allowed",
        },
        "signup_difficulty": "easy",
        "verification_requirements": ["email"],
        "tos_notes": {"personal_use_only": False, "proxy_clause": False,
                      "multi_account_clause": False},
        "registration": {
            "methods": ["api_key"],
            "browser_required": True,
            "human_checkpoint_possible": True,
            "credential_type": "api_key",
            "checkpoint_types": ["email_verification"],
            "automation_supported": True,
        },
        "extraction": {
            "automation_supported": True,
            "rules_ref": extraction_ref,
            "checkpoint_types": ["email_verification"],
            "notes": "data-driven",
        },
        "tier_value": 10, "usefulness": 10, "compatibility": 80, "metadata": {},
    }


# ── Data-driven onboarding: the core claim ──────────────────────────────────

class TestDataDrivenOnboarding:

    def test_new_provider_onboards_from_catalog_data_only(self, real_catalog):
        cat = _clone_with_provider(real_catalog, synthetic_provider())
        ok, gaps = can_onboard_from_data_only("synthprov", cat)
        assert ok, f"data-only onboarding should suffice, gaps: {gaps}"

    def test_new_provider_plan_is_ready_without_engine_change(self, real_catalog):
        cat = _clone_with_provider(real_catalog, synthetic_provider())
        plan = plan_onboarding("synthprov", cat)
        assert plan.status == READY
        assert plan.blocking_reasons == []

    def test_extraction_rules_ref_is_data(self, real_catalog):
        cat = _clone_with_provider(
            real_catalog, synthetic_provider(extraction_ref="nebius"))
        st = validate_extraction("synthprov", cat)
        assert st.ok
        assert st.data["rules_ref"] == "nebius"

    def test_missing_extraction_rules_yields_needs_data_not_success(self, real_catalog):
        cat = _clone_with_provider(
            real_catalog, synthetic_provider(extraction_ref="no_such_rules"))
        plan = plan_onboarding("synthprov", cat)
        assert plan.status == NEEDS_DATA
        assert plan.stage(STAGE_EXTRACTION).ok is False

    def test_checkpoints_derived_from_catalog_data(self, real_catalog):
        cat = _clone_with_provider(real_catalog, synthetic_provider())
        plan = plan_onboarding("synthprov", cat)
        assert "email_verification" in plan.checkpoints
        assert plan.browser_required is True

    def test_unknown_provider_is_blocked_not_ready(self, real_catalog):
        plan = plan_onboarding("this-provider-does-not-exist", real_catalog)
        assert plan.status == BLOCKED
        assert plan.stage(STAGE_CATALOG).ok is False
        assert plan.auto_enable_allowed is False


# ── Wave 1 ──────────────────────────────────────────────────────────────────

class TestWaveOne:

    @pytest.mark.parametrize("pid", PROVIDER_WAVE_1)
    def test_catalog_entry_valid(self, pid, real_catalog):
        assert validate_catalog_entry(pid, real_catalog).ok

    @pytest.mark.parametrize("pid", PROVIDER_WAVE_1)
    def test_capability_valid(self, pid, real_catalog):
        assert validate_capability(pid, real_catalog).ok

    @pytest.mark.parametrize("pid", PROVIDER_WAVE_1)
    def test_extraction_rules_exist(self, pid, real_catalog):
        st = validate_extraction(pid, real_catalog)
        assert st.ok
        assert st.data["rule_count"] >= 1

    @pytest.mark.parametrize("pid", PROVIDER_WAVE_1)
    def test_no_blocking_reasons(self, pid, real_catalog):
        assert plan_onboarding(pid, real_catalog).blocking_reasons == []

    @pytest.mark.parametrize("pid", PROVIDER_WAVE_1)
    def test_policy_unknown_prevents_auto_enable(self, pid, real_catalog):
        """Wave-1 providers have unknown policy → never auto-enabled."""
        plan = plan_onboarding(pid, real_catalog)
        assert plan.auto_enable_allowed is False
        assert plan.approval_required is True
        assert plan.status == NEEDS_REVIEW

    @pytest.mark.parametrize("pid", PROVIDER_WAVE_1)
    def test_omniroute_target_declared(self, pid, real_catalog):
        assert plan_onboarding(pid, real_catalog).stage(STAGE_OMNIROUTE).ok

    def test_all_pipeline_stages_present(self, real_catalog):
        plan = plan_onboarding("deepinfra", real_catalog)
        assert [s.stage for s in plan.stages] == list(PIPELINE_STAGES)


# ── Policy gate ─────────────────────────────────────────────────────────────

class TestPolicyGate:

    def test_disallowed_never_auto_enabled(self, real_catalog):
        cat = _clone_with_provider(
            real_catalog, synthetic_provider(policy_automation="disallowed"))
        plan = plan_onboarding("synthprov", cat)
        assert plan.auto_enable_allowed is False
        assert plan.stage(STAGE_POLICY).ok is False

    def test_restricted_never_auto_enabled(self, real_catalog):
        cat = _clone_with_provider(
            real_catalog, synthetic_provider(policy_automation="restricted"))
        plan = plan_onboarding("synthprov", cat)
        assert plan.auto_enable_allowed is False

    def test_unknown_policy_never_auto_enabled(self, real_catalog):
        cat = _clone_with_provider(
            real_catalog, synthetic_provider(policy_automation="unknown"))
        plan = plan_onboarding("synthprov", cat)
        assert plan.auto_enable_allowed is False
        assert "policy" in " ".join(plan.approval_required_reasons)

    def test_allowed_policy_still_requires_approval(self, real_catalog):
        cat = _clone_with_provider(
            real_catalog, synthetic_provider(policy_automation="allowed"))
        plan = plan_onboarding("synthprov", cat)
        assert plan.auto_enable_allowed is True
        assert plan.approval_required is True, "auto-enable != auto-execute"
        assert plan.executed is False

    def test_policy_validator_reports_status(self, real_catalog):
        st = validate_policy("deepinfra", real_catalog)
        assert st.data["policy_status"] in (
            "allowed", "disallowed", "restricted", "unknown")


# ── Dry-run purity ──────────────────────────────────────────────────────────

class TestDryRunPurity:

    def test_plan_is_dry_run(self, real_catalog):
        plan = plan_onboarding("deepinfra", real_catalog)
        assert plan.dry_run is True
        assert plan.executed is False

    def test_planning_calls_no_mutating_adapter(self, real_catalog, monkeypatch):
        calls = []
        import adapters.omniroute as omni
        import adapters.onepassword as op
        for mod, names in ((omni, ("create_connection", "add_provider")),
                           (op, ("create_item", "create_login", "create_api_key"))):
            for n in names:
                if hasattr(mod, n):
                    monkeypatch.setattr(mod, n, lambda *a, **k: calls.append(n))
        plan_wave(PROVIDER_WAVE_1, real_catalog)
        assert calls == []

    def test_planning_does_not_write_provider_state(self, real_catalog):
        import engine.state as state_mod
        before = Path(state_mod.STATE_FILE).read_text()
        plan_wave(PROVIDER_WAVE_1, real_catalog)
        assert Path(state_mod.STATE_FILE).read_text() == before

    def test_onboarding_module_has_no_mutating_calls(self):
        src = (SKILL_ROOT / "engine" / "onboarding.py").read_text()
        for forbidden in ("create_connection(", "create_item(", "save_state(",
                          "add_provider_account(", "register("):
            assert forbidden not in src, f"onboarding.py must not call {forbidden}"

    def test_mutating_steps_flagged_and_require_approval(self, real_catalog):
        steps = onboarding_steps("deepinfra", real_catalog)
        muts = [s for s in steps if s.get("mutating")]
        assert muts, "there must be identified mutating steps"
        for s in muts:
            assert s.get("human_approval") is True


# ── No bulk registration ────────────────────────────────────────────────────

class TestNoBulkRegistration:

    def test_wave_is_plan_only(self, real_catalog):
        w = plan_wave(PROVIDER_WAVE_1, real_catalog)
        assert w["dry_run"] is True
        assert w["bulk_registration"] is False
        assert w["sequential_only"] is True

    def test_wave_contains_one_plan_per_provider(self, real_catalog):
        w = plan_wave(PROVIDER_WAVE_1, real_catalog)
        assert set(w["plans"]) == set(PROVIDER_WAVE_1)
        for pl in w["plans"].values():
            assert pl["executed"] is False


# ── Serialization / secrets ─────────────────────────────────────────────────

class TestSerializationSecrets:

    def test_plan_json_serializable(self, real_catalog):
        json.dumps(plan_onboarding("deepinfra", real_catalog).to_dict())

    def test_plan_secret_free(self, real_catalog):
        for pid in PROVIDER_WAVE_1:
            assert_secret_free(plan_onboarding(pid, real_catalog).to_dict())

    def test_plan_contains_no_credential_values(self, real_catalog):
        blob = json.dumps(plan_wave(PROVIDER_WAVE_1, real_catalog))
        for bad in ("gsk_live", "sk-proj", "DO_NOT_LEAK", "xnd_live"):
            assert bad not in blob

    def test_onepassword_target_is_title_only(self, real_catalog):
        st = plan_onboarding("deepinfra", real_catalog).stage(STAGE_ONEPASSWORD)
        assert st.data["planned_api_key_title"].endswith("Api Key")
        assert st.data["write_requires_approval"] is True


# ── CLI ─────────────────────────────────────────────────────────────────────

class TestCli:

    def test_onboard_wave_json(self, capsys):
        import cli
        assert cli.main(["onboard", "--json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["dry_run"] is True

    def test_onboard_single_provider_json(self, capsys):
        import cli
        assert cli.main(["onboard", "deepinfra", "--json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["provider_id"] == "deepinfra"
        assert payload["executed"] is False

    def test_onboard_human_output_states_dry_run(self, capsys):
        import cli
        assert cli.main(["onboard", "deepinfra"]) == 0
        assert "DRY RUN" in capsys.readouterr().out
