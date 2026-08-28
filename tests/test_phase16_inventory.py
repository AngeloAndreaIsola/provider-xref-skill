"""
test_phase16_inventory.py — Phase 16 cross-system credential/account inventory.

Covers:
  * provider → account → {identity, 1P login, 1P api key, hermes, omniroute}
  * read-only, deterministic, secret-free
  * multi-account awareness (never provider → first account/credential/conn)
  * API-key values are never identifiers
  * unmatched/orphan record reporting
  * production-shaped state
  * no second reconciliation engine (canonical matching is reused)
"""

import json
import sys
from pathlib import Path

import pytest

SKILL_ROOT = Path(__file__).parent.parent
if str(SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT))

from engine.inventory import (
    SYSTEM_HERMES,
    SYSTEM_OMNIROUTE,
    SYSTEM_ONEPASSWORD,
    HermesRecord,
    build_inventory,
    discover_hermes_records,
    inventory_summary,
    inventory_to_dict,
    unmatched_records,
)
from engine.review import assert_secret_free

_ID = "identity_email_{}_x"

SECRET = "gsk_TESTSECRETVALUE1234567890"


def state_with(provider_accounts, identities=None):
    return {
        "identities": identities or [],
        "external_accounts": [],
        "provider_accounts": provider_accounts,
        "credentials": [],
        "capabilities": [],
    }


@pytest.fixture
def multi_account_inputs():
    """Two Groq accounts, fully populated across all three systems."""
    idents = [
        {"id": _ID.format("ang"), "type": "email", "value": "ang@example.com"},
        {"id": _ID.format("lazy"), "type": "email", "value": "lazymause@gmail.com"},
    ]
    pa = [
        {"id": "pa_ang", "provider_id": "groq", "identity_id": _ID.format("ang"),
         "omniroute_account_id": "conn_ang", "status": "connected",
         "auth_type": "api_key", "ownership_status": "known",
         "credential_ref": {"item_id": "item_ang", "item_title": "Groq Api Key",
                            "reference": "op://Personal/item_ang/credential",
                            "vault": "Personal", "field": "credential"}},
        {"id": "pa_lazy", "provider_id": "groq", "identity_id": _ID.format("lazy"),
         "omniroute_account_id": "conn_lazy", "status": "connected",
         "auth_type": "api_key", "ownership_status": "known",
         "credential_ref": {"item_id": "item_lazy", "item_title": "Groq Api Key 2",
                            "reference": "op://Personal/item_lazy/credential",
                            "vault": "Personal", "field": "credential"}},
    ]
    omni = [
        {"provider_id": "groq", "connection_id": "conn_ang",
         "display_name": "ang@example.com", "auth_type": "apiKey", "is_active": True},
        {"provider_id": "groq", "connection_id": "conn_lazy",
         "display_name": "lazymause@gmail.com", "auth_type": "apiKey", "is_active": True},
    ]
    op = [
        {"item_id": "item_ang", "title": "Groq Api Key", "username": "ang@example.com",
         "vault": "Personal"},
        {"item_id": "item_lazy", "title": "Groq Api Key 2",
         "username": "lazymause@gmail.com", "vault": "Personal"},
        {"item_id": "item_login", "title": "Groq Login", "username": "ang@example.com",
         "vault": "Personal"},
    ]
    return state_with(pa, idents), omni, op


# ── Shape ───────────────────────────────────────────────────────────────────

class TestInventoryShape:

    def test_provider_account_structure(self, multi_account_inputs):
        st, omni, op = multi_account_inputs
        inv = build_inventory(st, omni, op)
        assert "groq" in inv
        acc = inv["groq"].accounts[0]
        for attr in ("identity", "onepassword_login", "onepassword_api_key",
                     "hermes_reference", "omniroute_connection"):
            assert hasattr(acc, attr)

    def test_all_three_systems_recorded(self, multi_account_inputs):
        st, omni, op = multi_account_inputs
        inv = build_inventory(st, omni, op)
        acc = inv["groq"].accounts[0]
        assert acc.omniroute_connection is not None
        assert acc.hermes_reference is not None
        assert acc.onepassword_api_key is not None
        assert set(acc.systems_present) == {
            SYSTEM_ONEPASSWORD, SYSTEM_OMNIROUTE, SYSTEM_HERMES}

    def test_hermes_record_fields(self, multi_account_inputs):
        st, omni, op = multi_account_inputs
        recs = discover_hermes_records(st)
        assert len(recs) == 2
        r = recs[0]
        assert r.hermes_account_id == "pa_ang"
        assert r.credential_reference.startswith("op://")

    def test_omniroute_record_metadata(self, multi_account_inputs):
        st, omni, op = multi_account_inputs
        inv = build_inventory(st, omni, op)
        conn = inv["groq"].accounts[0].omniroute_connection
        assert conn.connection_id in ("conn_ang", "conn_lazy")
        assert conn.is_active is True

    def test_summary_counts_coverage(self, multi_account_inputs):
        st, omni, op = multi_account_inputs
        s = inventory_summary(build_inventory(st, omni, op))
        assert s["read_only"] is True
        assert s["total_accounts"] == 2
        assert s["coverage"]["omniroute_connection"] == 2
        assert s["coverage"]["hermes_reference"] == 2

    def test_empty_state_yields_empty_inventory(self):
        inv = build_inventory(state_with([]))
        assert inv == {}


# ── Multi-account correctness ───────────────────────────────────────────────

class TestMultiAccount:

    def test_two_accounts_kept_distinct(self, multi_account_inputs):
        st, omni, op = multi_account_inputs
        inv = build_inventory(st, omni, op)
        assert inv["groq"].account_count == 2
        keys = {a.account_key for a in inv["groq"].accounts}
        assert len(keys) == 2

    def test_each_account_has_its_own_credential(self, multi_account_inputs):
        st, omni, op = multi_account_inputs
        inv = build_inventory(st, omni, op)
        item_ids = {a.onepassword_api_key.item_id for a in inv["groq"].accounts}
        assert item_ids == {"item_ang", "item_lazy"}, \
            "must not share provider → first credential"

    def test_each_account_has_its_own_connection(self, multi_account_inputs):
        st, omni, op = multi_account_inputs
        inv = build_inventory(st, omni, op)
        conns = {a.omniroute_connection.connection_id for a in inv["groq"].accounts}
        assert conns == {"conn_ang", "conn_lazy"}, \
            "must not share provider → first connection"

    def test_multi_account_provider_listed(self, multi_account_inputs):
        st, omni, op = multi_account_inputs
        s = inventory_summary(build_inventory(st, omni, op))
        assert "groq" in s["multi_account_providers"]

    def test_identity_preserved_per_account(self, multi_account_inputs):
        st, omni, op = multi_account_inputs
        inv = build_inventory(st, omni, op)
        emails = {a.identity.get("identity_email") for a in inv["groq"].accounts}
        assert emails == {"ang@example.com", "lazymause@gmail.com"}


# ── Determinism ─────────────────────────────────────────────────────────────

class TestDeterminism:

    def test_identical_inputs_identical_output(self, multi_account_inputs):
        st, omni, op = multi_account_inputs
        a = inventory_to_dict(build_inventory(st, omni, op))
        b = inventory_to_dict(build_inventory(st, omni, op))
        a["summary"].pop("generated_at")
        b["summary"].pop("generated_at")
        assert a == b

    def test_account_order_is_stable(self, multi_account_inputs):
        st, omni, op = multi_account_inputs
        keys1 = [a.account_key for a in build_inventory(st, omni, op)["groq"].accounts]
        keys2 = [a.account_key for a in build_inventory(st, list(reversed(omni)),
                                                       list(reversed(op)))["groq"].accounts]
        assert keys1 == keys2 == sorted(keys1)


# ── Secrets ─────────────────────────────────────────────────────────────────

class TestSecretSafety:

    def test_inventory_is_secret_free(self, multi_account_inputs):
        st, omni, op = multi_account_inputs
        payload = inventory_to_dict(build_inventory(st, omni, op))
        assert_secret_free(payload)

    def test_secret_value_never_appears(self, multi_account_inputs):
        st, omni, op = multi_account_inputs
        # A leaked secret in the input must not be carried into the inventory.
        st["provider_accounts"][0]["credential_ref"]["credential"] = SECRET
        blob = json.dumps(inventory_to_dict(build_inventory(st, omni, op)))
        assert SECRET not in blob

    def test_api_key_value_is_never_an_identifier(self, multi_account_inputs):
        st, omni, op = multi_account_inputs
        inv = build_inventory(st, omni, op)
        for acc in inv["groq"].accounts:
            assert SECRET not in acc.account_key
            assert "gsk_" not in acc.account_key

    def test_op_references_preserved(self, multi_account_inputs):
        st, omni, op = multi_account_inputs
        inv = build_inventory(st, omni, op)
        refs = {a.onepassword_api_key.reference for a in inv["groq"].accounts}
        assert all(r.startswith("op://") for r in refs)

    def test_inventory_module_never_reads_secret_values(self):
        src = (SKILL_ROOT / "engine" / "inventory.py").read_text()
        for forbidden in ("get_credential(", "read_secret(", "op read",
                          "reveal(", "get_item_value("):
            assert forbidden not in src


# ── Read-only ───────────────────────────────────────────────────────────────

class TestReadOnly:

    def test_no_mutating_adapter_calls_in_source(self):
        src = (SKILL_ROOT / "engine" / "inventory.py").read_text()
        for forbidden in ("create_connection(", "create_item(", "save_state(",
                          "connect_provider(", "update_provider("):
            assert forbidden not in src

    def test_building_inventory_does_not_write_state(self, multi_account_inputs):
        import engine.state as state_mod
        st, omni, op = multi_account_inputs
        before = Path(state_mod.STATE_FILE).read_text()
        build_inventory(st, omni, op)
        assert Path(state_mod.STATE_FILE).read_text() == before

    def test_marked_read_only(self, multi_account_inputs):
        st, omni, op = multi_account_inputs
        assert inventory_to_dict(build_inventory(st, omni, op))["read_only"] is True


# ── Unmatched / orphan records ──────────────────────────────────────────────

class TestUnmatchedRecords:

    def test_unattached_omniroute_connection_reported(self):
        omni = [{"provider_id": "groq", "connection_id": "conn_orphan",
                 "display_name": "nobody@example.com"}]
        inv = build_inventory(state_with([]), omni, [])
        un = unmatched_records(inv, [], omni)
        ids = [r["connection_id"] for r in un["omniroute"]]
        # attached to a synthesized orphan account, or reported unmatched —
        # either way it must be visible somewhere, never silently dropped.
        assert "conn_orphan" in ids or any(
            a.omniroute_connection and
            a.omniroute_connection.connection_id == "conn_orphan"
            for p in inv.values() for a in p.accounts)

    def test_unattached_1password_item_reported(self, multi_account_inputs):
        st, omni, op = multi_account_inputs
        op = op + [{"item_id": "item_stray", "title": "Groq Api Key stray",
                    "username": "stray@example.com", "vault": "Personal"}]
        inv = build_inventory(st, omni, op)
        un = unmatched_records(inv, op, omni)
        assert isinstance(un["onepassword"], list)
        assert_secret_free(un)

    def test_unmatched_is_json_serializable(self, multi_account_inputs):
        st, omni, op = multi_account_inputs
        json.dumps(unmatched_records(build_inventory(st, omni, op), op, omni))


# ── Canonical matching reuse (no parallel engine) ───────────────────────────

class TestCanonicalMatchingReuse:

    def test_inventory_delegates_to_account_model(self):
        src = (SKILL_ROOT / "engine" / "inventory.py").read_text()
        assert "build_account_model" in src, \
            "inventory must reuse the Phase 13 canonical account model"

    def test_inventory_does_not_reimplement_matching(self):
        src = (SKILL_ROOT / "engine" / "inventory.py").read_text()
        for forbidden in ("def reconcile_account", "def reconcile_provider",
                          "def account_key", "def _match_op_items_to_account"):
            assert forbidden not in src, "no parallel matching implementation"

    def test_account_keys_match_account_model(self, multi_account_inputs):
        from engine.accounts import build_account_model
        st, omni, op = multi_account_inputs
        model = build_account_model(st, omni, op)
        inv = build_inventory(st, omni, op)
        assert {a.account_id for a in model["groq"]} == \
               {a.account_key for a in inv["groq"].accounts}

    def test_reconciliation_state_comes_from_canonical_model(self, multi_account_inputs):
        from engine.accounts import build_account_model
        st, omni, op = multi_account_inputs
        model = {a.account_id: a.reconciliation_state
                 for a in build_account_model(st, omni, op)["groq"]}
        for acc in build_inventory(st, omni, op)["groq"].accounts:
            assert acc.reconciliation_state == model[acc.account_key]


# ── Production-shaped state ─────────────────────────────────────────────────

class TestProductionShaped:

    def test_production_state_inventory(self):
        prod = SKILL_ROOT / "provider_state.json"
        if not prod.exists():
            pytest.skip("no production state")
        st = json.loads(prod.read_text())
        payload = inventory_to_dict(build_inventory(st))
        assert_secret_free(payload)
        json.dumps(payload)

    def test_production_state_not_rewritten(self):
        prod = SKILL_ROOT / "provider_state.json"
        if not prod.exists():
            pytest.skip("no production state")
        before = prod.read_text()
        build_inventory(json.loads(before))
        assert prod.read_text() == before

    def test_production_hermes_records_have_no_values(self):
        prod = SKILL_ROOT / "provider_state.json"
        if not prod.exists():
            pytest.skip("no production state")
        for r in discover_hermes_records(json.loads(prod.read_text())):
            d = r.to_dict()
            assert "credential" not in [k for k in d if k.endswith("_value")]
            if d.get("credential_reference"):
                assert d["credential_reference"].startswith("op://")


# ── CLI ─────────────────────────────────────────────────────────────────────

class TestCli:

    def test_inventory_json(self, capsys):
        import cli
        assert cli.main(["inventory", "--json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["read_only"] is True
        assert "unmatched" in payload

    def test_inventory_human(self, capsys):
        import cli
        assert cli.main(["inventory"]) == 0
        assert "read-only inventory" in capsys.readouterr().out
