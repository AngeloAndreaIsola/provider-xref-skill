"""
test_phase10_schema_drift.py — Phase 10 production/test schema alignment.

Phase 10 discovered that the real provider_state.json diverges from what the
schema + fixtures assumed:

  * credentials / capabilities have NO ``id`` — they are keyed by
    ``provider_id`` (and link to a provider account via the optional
    ``provider_account_id`` when known).
  * ExternalAccount uses ``provider_id`` (not ``provider``).
  * credential ``status`` can be ``stored``.

These tests lock in the corrected behaviour:

  A. ProviderGraph builds from production-shaped state (no id on creds/caps).
  B. recommendations() / planning work against production-shaped state.
  C. The production state validates against provider_state.schema.json.
  D. The schema rejects the OLD drift shapes (id-required) so the drift
     cannot silently return.
  E. Derived node keys are stable & deterministic for the same (provider, type).
"""
import json
import sys
from pathlib import Path

import pytest

SKILL_ROOT = Path(__file__).parent.parent
if str(SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT))

from engine.graph import ProviderGraph
from engine.state import load_state, validate_state, default_state
from engine.audit import recommendations, audit, reconcile_real_state
from engine.planner import plan_registration
from engine.utils import load_json, SCHEMA_DIR


def _production_shaped_state() -> dict:
    return load_json(SKILL_ROOT / "tests" / "fixtures" / "state" / "production_shaped_state.json")


class TestGraphBuildsFromProductionShapedState:

    def test_graph_builds_without_credential_id(self, isolated_catalog):
        state = _production_shaped_state()
        # Sanity: production-shaped state has no id on credentials/capabilities
        assert all("id" not in c for c in state["credentials"])
        assert all("id" not in c for c in state["capabilities"])

        g = ProviderGraph(state, isolated_catalog)
        assert len(g.credentials) == 1
        assert len(g.capabilities) == 1

    def test_derived_credential_key_is_provider_scoped(self, isolated_catalog):
        state = _production_shaped_state()
        g = ProviderGraph(state, isolated_catalog)
        key = list(g.credentials.keys())[0]
        assert key == "cred:cloudflare-ai:api_key"

    def test_derived_capability_key_is_provider_scoped(self, isolated_catalog):
        state = _production_shaped_state()
        g = ProviderGraph(state, isolated_catalog)
        key = list(g.capabilities.keys())[0]
        assert key == "cap:cloudflare-ai:model_inference"

    def test_edges_indexed_by_provider_id(self, isolated_catalog):
        state = _production_shaped_state()
        g = ProviderGraph(state, isolated_catalog)
        # cloudflare-ai provider should reach its credential + capability via provider_id
        cred_keys = g.provider_id_to_credential.get("cloudflare-ai", [])
        cap_keys = g.provider_id_to_capability.get("cloudflare-ai", [])
        assert cred_keys == ["cred:cloudflare-ai:api_key"]
        assert cap_keys == ["cap:cloudflare-ai:model_inference"]

    def test_explicit_id_still_wins(self, isolated_catalog):
        state = default_state()
        state["credentials"] = [
            {"id": "cred_explicit", "type": "api_key", "provider_id": "openai"},
        ]
        state["capabilities"] = [
            {"id": "cap_explicit", "type": "model_inference", "provider_id": "openai"},
        ]
        g = ProviderGraph(state, isolated_catalog)
        assert "cred_explicit" in g.credentials
        assert "cap_explicit" in g.capabilities


class TestLifecycleAgainstProductionShapedState:

    def test_recommendations_runs(self, isolated_catalog):
        state = _production_shaped_state()
        recs = recommendations(state, isolated_catalog)
        assert isinstance(recs, list)
        # groq is already connected (omniroute_connected) — should not be recommended
        provider_ids = {r["provider"] for r in recs}
        assert "groq" not in provider_ids

    def test_audit_runs(self, isolated_catalog):
        state = _production_shaped_state()
        result = audit()
        assert isinstance(result, dict)
        assert "summary" in result

    def test_reconcile_runs(self, isolated_catalog):
        state = _production_shaped_state()
        result = reconcile_real_state()
        assert isinstance(result, dict)

    def test_plan_registration_runs_for_unconnected_provider(self, isolated_catalog, monkeypatch):
        # Provider "openai" is not in production-shaped state -> plannable
        state = _production_shaped_state()
        plan = plan_registration("openai", state, isolated_catalog)
        assert isinstance(plan, dict)
        assert plan.get("provider_id") == "openai"


class TestSchemaEnforcesProductionShape:

    def test_production_shaped_state_validates(self):
        state = _production_shaped_state()
        ok, msg = validate_state(state)
        assert ok, f"Production-shaped state must validate: {msg}"

    def test_old_id_required_shape_is_rejected_for_credentials(self):
        """The old schema required `id` on credentials; the corrected schema
        requires `provider_id`. A credential with neither must be rejected."""
        schema = load_json(SKILL_ROOT / "schemas" / "provider_state.schema.json")
        state = default_state()
        state["credentials"] = [{"type": "api_key"}]  # no provider_id -> invalid
        import jsonschema
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=state, schema=schema)

    def test_external_account_provider_id_required_not_provider(self):
        schema = load_json(SKILL_ROOT / "schemas" / "provider_state.schema.json")
        state = default_state()
        # Old shape used "provider"; corrected schema requires "provider_id"
        state["external_accounts"] = [
            {"id": "ea_1", "identity_id": "ident_1", "provider": "google"},
        ]
        import jsonschema
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=state, schema=schema)

    def test_credential_status_stored_allowed(self):
        schema = load_json(SKILL_ROOT / "schemas" / "provider_state.schema.json")
        state = default_state()
        state["credentials"] = [
            {"type": "api_key", "provider_id": "openai", "status": "stored"},
        ]
        import jsonschema
        jsonschema.validate(instance=state, schema=schema)  # must not raise


class TestSchemaValidationCatchesRealDrift:

    def test_validate_state_function_enforces_schema(self):
        """validate_state must actually reject drift (not silently pass)."""
        bad = default_state()
        bad["credentials"] = [{"type": "api_key"}]  # missing provider_id
        ok, _ = validate_state(bad)
        assert ok is False

    def test_real_production_file_validates(self):
        real = load_json(SKILL_ROOT / "provider_state.json")
        # The real file should validate now that the schema matches reality
        ok, msg = validate_state(real)
        assert ok, f"Real provider_state.json must validate: {msg}"
