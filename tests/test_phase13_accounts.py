"""
test_phase13_accounts.py — Phase 13 multi-account / multi-identity model.

Covers:
  * deterministic account_key (never API-key value)
  * multiple accounts per provider remain DISTINCT
  * two accounts NOT merged merely because same provider
  * two accounts NOT merged merely because same 1Password login title
  * duplicate detection (same identity / connection / hermes id)
  * conflicting identity (same connection, different identities)
  * API-key value is never an identifier
  * secret-free output
  * Groq production-shaped multi-account example
"""

import sys
import json
import copy
from pathlib import Path

import pytest

SKILL_ROOT = Path(__file__).parent.parent
if str(SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT))

from engine.accounts import (
    build_account_model,
    account_key,
    account_summary,
    find_duplicate_accounts,
    find_conflicting_identities,
    AccountView,
    STATE_DUPLICATE,
    STATE_CONFLICTING_IDENTITY,
)

_ID = "identity_email_{}_x"


def state_with(provider_accounts, identities=None):
    return {
        "identities": identities or [],
        "external_accounts": [],
        "provider_accounts": provider_accounts,
        "credentials": [],
        "capabilities": [],
    }


# ── account_key determinism + safety ────────────────────────────────────────

class TestAccountKey:

    def test_key_is_deterministic(self):
        k1 = account_key("groq", identity_email="Ang@example.com")
        k2 = account_key("groq", identity_email="ang@example.com")
        assert k1 == k2  # normalized

    def test_key_never_contains_api_key_value(self):
        k = account_key("groq", identity_email="ang@example.com",
                        omniroute_connection_id="conn_1")
        assert "sk-" not in k
        assert "SECRET" not in k

    def test_key_falls_back_through_signals(self):
        assert account_key("groq", identity_id="id1") == "groq::id1"
        assert account_key("groq", identity_email="ang@example.com").startswith("groq::identity_email_ang")
        assert account_key("groq", omniroute_connection_id="c1") == "groq::omni:c1"
        assert account_key("groq", hermes_account_id="pa1") == "groq::hermes:pa1"
        assert account_key("groq") == "groq::unknown"


# ── Multi-account: remains distinct ─────────────────────────────────────────

class TestMultipleAccountsDistinct:

    def test_two_groq_accounts_not_merged(self):
        pa = [
            {"id": "pa_ang", "provider_id": "groq", "omniroute_account_id": "conn_ang",
             "identity_id": _ID.format("ang_example_com"), "ownership_status": "known"},
            {"id": "pa_lazy", "provider_id": "groq", "omniroute_account_id": "conn_lazy",
             "identity_id": _ID.format("lazy_gmail"), "ownership_status": "known"},
        ]
        idents = [
            {"id": _ID.format("ang_example_com"), "type": "email", "value": "ang@example.com"},
            {"id": _ID.format("lazy_gmail"), "type": "email", "value": "lazymause@gmail.com"},
        ]
        omni = [
            {"provider_id": "groq", "connection_id": "conn_ang", "display_name": "ang@example.com"},
            {"provider_id": "groq", "connection_id": "conn_lazy", "display_name": "lazymause@gmail.com"},
        ]
        op_items = [
            {"item_id": "li_ang", "title": "Groq Account", "username": "ang@example.com", "vault": "Private"},
            {"item_id": "li_lazy", "title": "Groq Account", "username": "lazymause@gmail.com", "vault": "Private"},
        ]
        model = build_account_model(state_with(pa, idents), omni, op_items)
        gq = model["groq"]
        assert len(gq) == 2
        keys = {a.account_id for a in gq}
        assert keys == {
            account_key("groq", identity_id=_ID.format("ang_example_com")),
            account_key("groq", identity_id=_ID.format("lazy_gmail")),
        }
        emails = {a.identity_email for a in gq}
        assert emails == {"ang@example.com", "lazymause@gmail.com"}
        conns = {a.omniroute_connection_id for a in gq}
        assert conns == {"conn_ang", "conn_lazy"}

    def test_not_merged_by_same_provider_only(self):
        pa = [
            {"id": "pa1", "provider_id": "groq", "identity_id": _ID.format("a"), "omniroute_account_id": "c1"},
            {"id": "pa2", "provider_id": "groq", "identity_id": _ID.format("b"), "omniroute_account_id": "c2"},
        ]
        idents = [
            {"id": _ID.format("a"), "type": "email", "value": "a@example.com"},
            {"id": _ID.format("b"), "type": "email", "value": "b@example.com"},
        ]
        model = build_account_model(state_with(pa, idents),
                                    [{"provider_id": "groq", "connection_id": "c1"},
                                     {"provider_id": "groq", "connection_id": "c2"}], [])
        assert len(model["groq"]) == 2

    def test_not_merged_by_same_login_title(self):
        pa = [
            {"id": "pa_ang", "provider_id": "groq", "identity_id": _ID.format("ang_example_com"),
             "omniroute_account_id": "conn_ang"},
            {"id": "pa_lazy", "provider_id": "groq", "identity_id": _ID.format("lazy_gmail"),
             "omniroute_account_id": "conn_lazy"},
        ]
        idents = [
            {"id": _ID.format("ang_example_com"), "type": "email", "value": "ang@example.com"},
            {"id": _ID.format("lazy_gmail"), "type": "email", "value": "lazymause@gmail.com"},
        ]
        omni = [
            {"provider_id": "groq", "connection_id": "conn_ang", "display_name": "ang@example.com"},
            {"provider_id": "groq", "connection_id": "conn_lazy", "display_name": "lazymause@gmail.com"},
        ]
        op_items = [
            {"item_id": "li_ang", "title": "Groq Account", "username": "ang@example.com", "vault": "Private"},
            {"item_id": "li_lazy", "title": "Groq Account", "username": "lazymause@gmail.com", "vault": "Private"},
        ]
        model = build_account_model(state_with(pa, idents), omni, op_items)
        assert len(model["groq"]) == 2
        login_ids = {a.login_ref["item_id"] for a in model["groq"] if a.login_ref}
        assert login_ids == {"li_ang", "li_lazy"}


# ── Duplicate detection ─────────────────────────────────────────────────────

class TestDuplicateDetection:

    def test_duplicate_same_identity(self):
        pa = [
            {"id": "pa1", "provider_id": "groq", "identity_id": _ID.format("ang_example_com"),
             "omniroute_account_id": "conn_ang"},
            {"id": "pa2", "provider_id": "groq", "identity_id": _ID.format("ang_example_com"),
             "omniroute_account_id": "conn_ang2"},
        ]
        idents = [{"id": _ID.format("ang_example_com"), "type": "email", "value": "ang@example.com"}]
        omni = [
            {"provider_id": "groq", "connection_id": "conn_ang", "display_name": "ang@example.com"},
            {"provider_id": "groq", "connection_id": "conn_ang2", "display_name": "ang@example.com"},
        ]
        model = build_account_model(state_with(pa, idents), omni, [])
        dups = find_duplicate_accounts(model)
        assert len(dups) == 1
        assert dups[0]["provider_id"] == "groq"
        assert dups[0]["duplicate_count"] == 2

    def test_duplicate_same_omniroute_connection(self):
        # Two accounts sharing one OmniRoute connection id with DIFFERENT
        # identities is a CONFLICT (same connection, ambiguous ownership),
        # surfaced via find_conflicting_identities, not a plain duplicate.
        pa = [
            {"id": "pa1", "provider_id": "groq", "identity_id": _ID.format("a"), "omniroute_account_id": "conn_x"},
            {"id": "pa2", "provider_id": "groq", "identity_id": _ID.format("b"), "omniroute_account_id": "conn_x"},
        ]
        idents = [
            {"id": _ID.format("a"), "type": "email", "value": "a@example.com"},
            {"id": _ID.format("b"), "type": "email", "value": "b@example.com"},
        ]
        omni = [{"provider_id": "groq", "connection_id": "conn_x", "display_name": "a@example.com"}]
        model = build_account_model(state_with(pa, idents), omni, [])
        conflicts = find_conflicting_identities(model)
        assert len(conflicts) == 1
        assert conflicts[0]["provider_id"] == "groq"


# ── Conflicting identity ────────────────────────────────────────────────────

class TestConflictingIdentity:

    def test_conflict_same_connection_different_identity(self):
        pa = [
            {"id": "pa1", "provider_id": "groq", "identity_id": _ID.format("a"), "omniroute_account_id": "conn_x"},
            {"id": "pa2", "provider_id": "groq", "identity_id": _ID.format("b"), "omniroute_account_id": "conn_x"},
        ]
        idents = [
            {"id": _ID.format("a"), "type": "email", "value": "a@example.com"},
            {"id": _ID.format("b"), "type": "email", "value": "b@example.com"},
        ]
        omni = [{"provider_id": "groq", "connection_id": "conn_x", "display_name": "a@example.com"}]
        model = build_account_model(state_with(pa, idents), omni, [])
        conflicts = find_conflicting_identities(model)
        assert len(conflicts) == 1
        assert set(conflicts[0]["conflicting_emails"]) == {"a@example.com", "b@example.com"}
        assert any(a.reconciliation_state == STATE_CONFLICTING_IDENTITY for a in model["groq"])


# ── API-key value never used as identifier ──────────────────────────────────

class TestApiKeyNotIdentifier:

    def test_api_key_value_absent_from_model(self):
        pa = [{"id": "pa1", "provider_id": "groq", "identity_id": _ID.format("ang_example_com"),
               "omniroute_account_id": "conn_ang",
               "credential_ref": {"backend": "1password", "item_id": "ak1",
                                  "reference": "op://Private/x/password"}}]
        idents = [{"id": _ID.format("ang_example_com"), "type": "email", "value": "ang@example.com"}]
        omni = [{"provider_id": "groq", "connection_id": "conn_ang", "display_name": "ang@example.com"}]
        op_items = [{"item_id": "ak1", "title": "OmniRoute groq Api Key", "vault": "Private"}]
        model = build_account_model(state_with(pa, idents), omni, op_items)
        blob = json.dumps(model["groq"][0].to_dict())
        assert "sk-" not in blob
        assert "op://" in blob


# ── Secret-free output ──────────────────────────────────────────────────────

class TestSecretFree:

    def test_account_view_has_no_value_field(self):
        av = AccountView(provider_id="groq", account_id="groq::x")
        assert "value" not in av.to_dict()


# ── Groq production-shaped multi-account example ────────────────────────────

class TestGroqProductionShaped:

    def test_groq_multi_account_summary(self):
        pa = [
            {"id": "pa_ang", "provider_id": "groq", "omniroute_account_id": "conn_ang",
             "identity_id": _ID.format("ang_example_com"), "ownership_status": "known",
             "credential_ref": {"backend": "1password", "item_id": "ak_ang",
                                "reference": "op://Private/OmniRoute groq ang/password"}},
            {"id": "pa_lazy", "provider_id": "groq", "omniroute_account_id": "conn_lazy",
             "identity_id": _ID.format("lazy_gmail"), "ownership_status": "known",
             "credential_ref": {"backend": "1password", "item_id": "ak_lazy",
                                "reference": "op://Private/OmniRoute groq lazy/password"}},
        ]
        idents = [
            {"id": _ID.format("ang_example_com"), "type": "email", "value": "ang@example.com"},
            {"id": _ID.format("lazy_gmail"), "type": "email", "value": "lazymause@gmail.com"},
        ]
        omni = [
            {"provider_id": "groq", "connection_id": "conn_ang", "display_name": "ang@example.com"},
            {"provider_id": "groq", "connection_id": "conn_lazy", "display_name": "lazymause@gmail.com"},
        ]
        op_items = [
            {"item_id": "ak_ang", "title": "OmniRoute groq ang Api Key", "vault": "Private"},
            {"item_id": "ak_lazy", "title": "OmniRoute groq lazy Api Key", "vault": "Private"},
        ]
        model = build_account_model(state_with(pa, idents), omni, op_items)
        summary = account_summary(model)
        assert summary["total_accounts"] == 2
        assert "groq" in summary["multi_account_providers"]
        assert summary["duplicate_findings"] == []
        assert summary["conflict_findings"] == []
        refs = {a.api_key_ref["item_id"] for a in model["groq"] if a.api_key_ref}
        assert refs == {"ak_ang", "ak_lazy"}

    def test_does_not_modify_real_production_state(self):
        prod = json.load(open(SKILL_ROOT / "provider_state.json"))
        snap = copy.deepcopy(prod)
        build_account_model(prod, [], [])
        assert prod == snap  # read-only
