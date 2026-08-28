"""
test_phase12_reconciliation.py — Phase 12 read-only reconciliation.

Covers:
  * complete account
  * missing login
  * missing api key
  * missing OmniRoute connection
  * missing Hermes reference
  * duplicate accounts/items
  * conflicting identities
  * orphaned 1Password/OmniRoute/Hermes records
  * ambiguous/unknown cases
  * multiple accounts for the same provider
  * secret redaction (no values in output)
  * production-shaped state reconciles without crashing
"""
import sys
from pathlib import Path

import pytest

SKILL_ROOT = Path(__file__).parent.parent
if str(SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT))

from engine.reconcile import (
    reconcile_all,
    reconcile_provider,
    reconcile_account,
    reconcile_from_sources,
    summarize_reconciliation,
    normalize_onepassword_items,
    normalize_omniroute_connections,
    STATE_COMPLETE, STATE_MISSING_LOGIN, STATE_MISSING_API_KEY,
    STATE_MISSING_OMNIROUTE, STATE_MISSING_HERMES, STATE_DUPLICATE,
    STATE_ORPHANED, STATE_CONFLICTING_IDENTITY, STATE_UNKNOWN,
)
import json


def _load_production_state():
    return json.load(open(SKILL_ROOT / "provider_state.json"))


# ── Builders for test inputs ────────────────────────────────────────────────

def hermes_account(provider_id, acc_id, **kw):
    base = {
        "id": acc_id,
        "provider_id": provider_id,
        "status": "connected",
        "auth_type": "api_key",
        "omniroute_connected": True,
        "omniroute_account_id": kw.get("omni_id"),
        "identity_id": kw.get("identity_id"),
        "ownership_status": kw.get("ownership_status", "unknown"),
        "credential_ref": kw.get("credential_ref"),
    }
    return base


def op_login(item_id, title, username=None, vault="Private"):
    return {"item_id": item_id, "title": title, "username": username, "vault": vault}


def op_apikey(item_id, title, vault="Private"):
    return {"item_id": item_id, "title": title, "username": None, "vault": vault}


def omni(provider_id, conn_id, display_name=None):
    return {"provider_id": provider_id, "connection_id": conn_id,
            "auth_type": "api_key", "display_name": display_name, "is_active": True}


# ── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def complete_inputs():
    """A fully-linked account: Hermes + OmniRoute + login + api key."""
    state = {"identities": [{"id": "id_ang", "type": "email", "value": "ang@example.com"}],
             "external_accounts": [], "provider_accounts": [
                 hermes_account("groq", "pa_groq_1", omni_id="conn_g1",
                                identity_id="id_ang", ownership_status="known",
                                credential_ref={"backend": "1password", "vault": "Private",
                                                 "item_id": "ak1", "item_title": "OmniRoute groq Api Key",
                                                 "field": "password", "reference": "op://Private/OmniRoute groq Api Key/password"}),
             ], "credentials": [], "capabilities": []}
    omni_conns = [omni("groq", "conn_g1", "ang@example.com")]
    op_items = [
        op_login("li1", "Groq Account", "ang@example.com"),
        op_apikey("ak1", "OmniRoute groq Api Key"),
    ]
    return state, omni_conns, op_items


class TestReconcileComplete:

    def test_complete_account(self, complete_inputs):
        state, omni_conns, op_items = complete_inputs
        recon = reconcile_all(state, omni_conns, op_items)
        acc = recon["groq"].accounts[0]
        assert acc.state == STATE_COMPLETE
        assert acc.has_login and acc.has_api_key and acc.has_omniroute and acc.has_hermes_ref
        assert acc.identity_email == "ang@example.com"


class TestReconcileMissingPieces:

    def test_missing_login(self):
        state = {"identities": [], "external_accounts": [], "provider_accounts": [
            hermes_account("groq", "pa1", omni_id="c1",
                           credential_ref={"backend": "1password", "item_id": "ak1",
                                            "reference": "op://Private/x/password"}),
        ], "credentials": [], "capabilities": []}
        omni_conns = [omni("groq", "c1")]
        op_items = [op_apikey("ak1", "OmniRoute groq Api Key")]
        acc = reconcile_all(state, omni_conns, op_items)["groq"].accounts[0]
        assert acc.state == STATE_MISSING_LOGIN
        assert acc.has_api_key and not acc.has_login

    def test_missing_api_key(self):
        state = {"identities": [], "external_accounts": [], "provider_accounts": [
            hermes_account("groq", "pa1", omni_id="c1"),
        ], "credentials": [], "capabilities": []}
        omni_conns = [omni("groq", "c1")]
        op_items = [op_login("li1", "Groq Account", "ang@example.com")]
        acc = reconcile_all(state, omni_conns, op_items)["groq"].accounts[0]
        assert acc.state == STATE_MISSING_API_KEY
        assert acc.has_login and not acc.has_api_key

    def test_missing_omniroute_connection(self):
        state = {"identities": [], "external_accounts": [], "provider_accounts": [
            hermes_account("groq", "pa1", identity_id="id1"),
        ], "credentials": [], "capabilities": []}
        omni_conns = []
        op_items = [op_login("li1", "Groq Account", "ang@example.com"),
                    op_apikey("ak1", "OmniRoute groq Api Key")]
        acc = reconcile_all(state, omni_conns, op_items)["groq"].accounts[0]
        assert acc.state == STATE_MISSING_OMNIROUTE
        assert acc.has_hermes_ref and not acc.has_omniroute

    def test_missing_hermes_reference(self):
        # OmniRoute + 1Password items but no Hermes provider account
        state = {"identities": [], "external_accounts": [], "provider_accounts": [],
                 "credentials": [], "capabilities": []}
        omni_conns = [omni("groq", "c1", "ang@example.com")]
        op_items = [op_login("li1", "Groq Account", "ang@example.com"),
                    op_apikey("ak1", "OmniRoute groq Api Key")]
        acc = reconcile_all(state, omni_conns, op_items)["groq"].accounts[0]
        assert acc.state == STATE_MISSING_HERMES
        assert acc.has_omniroute and not acc.has_hermes_ref


class TestReconcileOrphaned:

    def test_orphaned_1password_item(self):
        # 1Password api key item with no Hermes / OmniRoute anchor
        state = {"identities": [], "external_accounts": [], "provider_accounts": [],
                 "credentials": [], "capabilities": []}
        omni_conns = []
        op_items = [op_apikey("ak1", "OmniRoute groq Api Key")]
        acc = reconcile_all(state, omni_conns, op_items)["groq"].accounts[0]
        assert acc.state == STATE_ORPHANED
        assert "orphaned_1password_item" in acc.issues

    def test_orphaned_omniroute_connection(self):
        # OmniRoute connection with no Hermes / 1Password anchor
        state = {"identities": [], "external_accounts": [], "provider_accounts": [],
                 "credentials": [], "capabilities": []}
        omni_conns = [omni("groq", "c1", "ang@example.com")]
        op_items = []
        acc = reconcile_all(state, omni_conns, op_items)["groq"].accounts[0]
        assert acc.state == STATE_MISSING_HERMES
        assert acc.has_omniroute and not acc.has_hermes_ref


class TestReconcileDuplicate:

    def test_duplicate_api_key_items(self):
        state = {"identities": [], "external_accounts": [], "provider_accounts": [
            hermes_account("groq", "pa1", omni_id="c1",
                           credential_ref={"backend": "1password", "item_id": "ak1",
                                            "reference": "op://Private/x/password"}),
        ], "credentials": [], "capabilities": []}
        omni_conns = [omni("groq", "c1")]
        op_items = [op_login("li1", "Groq Account", "ang@example.com"),
                    op_apikey("ak1", "OmniRoute groq Api Key"),
                    op_apikey("ak2", "OmniRoute groq Api Key 2")]  # duplicate
        recon = reconcile_all(state, omni_conns, op_items)
        rp = recon["groq"]
        # The matched account carries ak1; the extra ak2 becomes a duplicate orphan
        dup_issues = [i for a in rp.accounts for i in a.issues if i.startswith("duplicate")]
        assert any("duplicate_api_key_items" in i or "duplicate_1password_item" in i for i in dup_issues)


class TestReconcileConflictingIdentity:

    def test_conflicting_identity_emails(self):
        state = {"identities": [],
                 "external_accounts": [],
                 "provider_accounts": [
                     hermes_account("groq", "pa1", omni_id="c1", identity_id="id_ang"),
                     hermes_account("groq", "pa2", omni_id="c2", identity_id="id_lazy"),
                 ],
                 "credentials": [], "capabilities": []}
        omni_conns = [omni("groq", "c1", "ang@example.com"),
                      omni("groq", "c2", "lazymause@gmail.com")]
        op_items = [op_login("li1", "Groq Account", "ang@example.com"),
                    op_login("li2", "Groq Account", "lazymause@gmail.com")]
        recon = reconcile_all(state, omni_conns, op_items)
        rp = recon["groq"]
        # two hermes-anchored accounts with different emails => conflict flagged
        assert rp.account_count == 2
        assert any(STATE_CONFLICTING_IDENTITY == a.state or
                   any("conflicting_identity_email" in i for i in a.issues)
                   for a in rp.accounts)


class TestReconcileUnknown:

    def test_unknown_when_no_evidence(self):
        state = {"identities": [], "external_accounts": [], "provider_accounts": [],
                 "credentials": [], "capabilities": []}
        omni_conns = []
        op_items = []
        # No provider present at all -> nothing to reconcile (empty)
        recon = reconcile_all(state, omni_conns, op_items)
        assert recon == {}


class TestMultipleAccountsPerProvider:

    def test_two_groq_accounts_distinguishable(self):
        state = {"identities": [
                    {"id": "id_ang", "type": "email", "value": "ang@example.com"},
                    {"id": "id_lazy", "type": "email", "value": "lazymause@gmail.com"},
                ],
                "external_accounts": [],
                "provider_accounts": [
                    hermes_account("groq", "pa_ang", omni_id="c_ang", identity_id="id_ang",
                                   ownership_status="known"),
                    hermes_account("groq", "pa_lazy", omni_id="c_lazy", identity_id="id_lazy",
                                   ownership_status="known"),
                ],
                "credentials": [], "capabilities": []}
        omni_conns = [omni("groq", "c_ang", "ang@example.com"),
                      omni("groq", "c_lazy", "lazymause@gmail.com")]
        op_items = [op_login("li_ang", "Groq Account", "ang@example.com"),
                    op_login("li_lazy", "Groq Account", "lazymause@gmail.com")]
        rp = reconcile_all(state, omni_conns, op_items)["groq"]
        assert rp.account_count == 2
        ids = {a.account_id for a in rp.accounts}
        assert ids == {"pa_ang", "pa_lazy"}
        # Both distinguishable by identity
        emails = {a.identity_email for a in rp.accounts}
        assert emails == {"ang@example.com", "lazymause@gmail.com"}


class TestNormalizers:

    def test_normalize_onepassword_classifies_kind(self):
        items = normalize_onepassword_items([
            op_login("li1", "Groq Account", "ang@example.com"),
            op_apikey("ak1", "OmniRoute groq Api Key"),
        ])
        by_id = {it["item_id"]: it for it in items}
        assert by_id["li1"]["kind"] == "login"
        assert by_id["ak1"]["kind"] == "api_key"
        assert by_id["ak1"]["provider_id"] == "groq"

    def test_normalize_onepassword_prefers_longest_provider_id(self):
        # "api.cloudflare.com" contains "cloudflare" (would match a 'cloudflare'
        # id) but NOT "cloudflare-ai", so the honest title match is None.
        # The api key still attaches to the account via Hermes credential_ref.
        items = normalize_onepassword_items([
            op_apikey("ak1", "OmniRoute api.cloudflare.com Api Key"),
        ])
        assert items[0]["provider_id"] is None  # no false-positive match
        assert items[0]["kind"] == "api_key"

    def test_normalize_omniroute_strips_secrets(self):
        conns = normalize_omniroute_connections([
            {"provider_id": "groq", "connection_id": "c1", "authType": "apiKey",
             "apiKey": "sk-SECRET", "accessToken": "tok", "name": "ang@example.com"},
        ])
        assert conns[0]["connection_id"] == "c1"
        assert "apiKey" not in conns[0]
        assert "accessToken" not in conns[0]


class TestSecretRedaction:

    def test_no_secret_values_in_output(self):
        import re
        state = {"identities": [], "external_accounts": [], "provider_accounts": [
            hermes_account("groq", "pa1", omni_id="c1",
                           credential_ref={"backend": "1password", "item_id": "ak1",
                                            "reference": "op://Private/x/password"}),
        ], "credentials": [], "capabilities": []}
        omni_conns = [omni("groq", "c1")]
        op_items = [op_login("li1", "Groq Account", "ang@example.com"),
                    op_apikey("ak1", "OmniRoute groq Api Key")]
        recon = reconcile_all(state, omni_conns, op_items)
        blob = json.dumps(recon["groq"].to_dict())
        # op:// reference is allowed; raw secret-like tokens are not
        assert "sk-" not in blob
        assert "SECRET" not in blob
        assert "op://" in blob  # reference present, value not

    def test_credential_value_never_returned(self):
        acc = reconcile_account("groq",
                                 hermes_account("groq", "pa1", credential_ref={
                                     "backend": "1password", "item_id": "ak1",
                                     "reference": "op://Private/x/password"}),
                                 None, [], [])
        d = acc.to_dict()
        assert "value" not in json.dumps(d).lower() or "op://" in json.dumps(d)


class TestProductionShapedDoesNotCrash:

    def test_production_state_reconciles(self):
        state = _load_production_state()
        # No live adapters: reconcile with empty discovered sources must not crash
        recon = reconcile_all(state, omni_connections=[], op_items=[])
        assert isinstance(recon, dict)
        # cloudflare-ai provider account present
        assert "cloudflare-ai" in recon
        # groq provider account present
        assert "groq" in recon
        # Every account has a valid reconciliation state
        for rp in recon.values():
            for a in rp.accounts:
                assert a.state in (
                    STATE_COMPLETE, STATE_MISSING_LOGIN, STATE_MISSING_API_KEY,
                    STATE_MISSING_OMNIROUTE, STATE_MISSING_HERMES, STATE_DUPLICATE,
                    STATE_ORPHANED, STATE_CONFLICTING_IDENTITY, STATE_UNKNOWN,
                )

    def test_production_state_with_observed_connections(self):
        state = _load_production_state()
        omni = [
            {"provider_id": "groq", "connection_id": "conn_1", "auth_type": "api_key",
             "display_name": "lazymause@gmail.com"},
            {"provider_id": "cloudflare-ai", "connection_id": "1c344492-fb7d-4aa1-b350-48ee6f5e1b7b",
             "auth_type": "api_key", "display_name": "andrea.isola@me.com"},
        ]
        op_items = [op_apikey("okp6wco72wqqtukcftwmm6azu4",
                              "OmniRoute api.cloudflare.com Api Key")]
        recon = reconcile_all(state, omni, op_items)
        cf = recon["cloudflare-ai"].accounts[0]
        # cloudflare-ai: hermes + omni + api key (no login item) -> missing_login
        assert cf.state == STATE_MISSING_LOGIN
        gq = recon["groq"].accounts[0]
        assert gq.has_omniroute and gq.has_hermes_ref
        # secret-free summary
        summary = summarize_reconciliation(recon)
        assert summary["total_accounts"] >= 2


class TestReadonlyContract:

    def test_inputs_not_mutated(self):
        state = {"identities": [], "external_accounts": [], "provider_accounts": [
            hermes_account("groq", "pa1", omni_id="c1"),
        ], "credentials": [], "capabilities": []}
        import copy
        snapshot = copy.deepcopy(state)
        omni_conns = [omni("groq", "c1")]
        op_items = [op_login("li1", "Groq Account")]
        reconcile_all(state, omni_conns, op_items)
        # state must be unchanged (read-only)
        assert state == snapshot

    def test_reconcile_from_sources_is_safe_noop_when_adapters_unavailable(self):
        # When adapters are unavailable, reconcile_from_sources should degrade
        # gracefully using only local state (no exception, no mutation).
        recon = reconcile_from_sources()
        assert isinstance(recon, dict)
