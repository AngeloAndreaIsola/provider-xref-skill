"""
test_phase17_account_reconciliation.py — Phase 17 account-level reconciliation.

Covers:
  * complete account renders as COMPLETE with all five ✓
  * missing / duplicate / orphaned / conflicting / unknown detection
  * nothing is ever repaired
  * output feeds the Phase 14 review system
  * one canonical matching model (no duplicated logic)
  * multi-account correctness
  * secret-free, deterministic, JSON-serializable
  * production-shaped state
"""

import json
import sys
from pathlib import Path

import pytest

SKILL_ROOT = Path(__file__).parent.parent
if str(SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT))

from engine.account_reconcile import (
    ACCOUNT_STATUSES,
    COMPONENTS,
    STATUS_COMPLETE,
    STATUS_CONFLICTING,
    STATUS_DUPLICATE,
    STATUS_MISSING,
    STATUS_ORPHANED,
    STATUS_UNKNOWN,
    account_reconciliation_report,
    detect_problems,
    reconcile_accounts,
    reconcile_inventory_account,
    render_report,
    status_counts,
    to_review_findings,
)
from engine.inventory import build_inventory
from engine.review import assert_secret_free

_ID = "identity_email_{}_x"


def state_with(provider_accounts, identities=None):
    return {
        "identities": identities or [],
        "external_accounts": [],
        "provider_accounts": provider_accounts,
        "credentials": [],
        "capabilities": [],
    }


@pytest.fixture
def complete_account():
    """A Groq account complete across all five components."""
    idents = [{"id": _ID.format("lazy"), "type": "email",
               "value": "lazymause@gmail.com"}]
    pa = [{"id": "pa_lazy", "provider_id": "groq",
           "identity_id": _ID.format("lazy"),
           "omniroute_account_id": "conn_lazy", "status": "connected",
           "auth_type": "api_key", "ownership_status": "known",
           "credential_ref": {"item_id": "item_lazy", "item_title": "Groq Api Key",
                              "reference": "op://Personal/item_lazy/credential",
                              "vault": "Personal", "field": "credential"}}]
    omni = [{"provider_id": "groq", "connection_id": "conn_lazy",
             "display_name": "lazymause@gmail.com", "auth_type": "apiKey",
             "is_active": True}]
    op = [
        {"item_id": "item_lazy", "title": "Groq Api Key",
         "username": "lazymause@gmail.com", "vault": "Personal"},
        {"item_id": "item_login", "title": "Groq Login",
         "username": "lazymause@gmail.com", "vault": "Personal"},
    ]
    return state_with(pa, idents), omni, op




# ── COMPLETE rendering ──────────────────────────────────────────────────────

class TestCompleteAccount:

    def test_report_contains_account(self, complete_account):
        st, omni, op = complete_account
        view = reconcile_accounts(st, omni, op)
        assert "groq" in view
        assert view["groq"][0].account_label == "lazymause@gmail.com"

    def test_components_present(self, complete_account):
        st, omni, op = complete_account
        row = reconcile_accounts(st, omni, op)["groq"][0]
        for comp in ("identity", "onepassword_api_key",
                     "hermes_reference", "omniroute_connection"):
            assert row.components[comp] is True, comp

    def test_render_shows_target_format(self, complete_account):
        st, omni, op = complete_account
        out = render_report(reconcile_accounts(st, omni, op))
        assert "Account: lazymause@gmail.com" in out
        assert "1Password API key:" in out
        assert "OmniRoute connection:" in out
        assert "Status:" in out
        assert "nothing was repaired" in out

    def test_all_components_enumerated(self, complete_account):
        st, omni, op = complete_account
        row = reconcile_accounts(st, omni, op)["groq"][0]
        assert set(row.components) == set(COMPONENTS)

    def test_status_is_a_known_status(self, complete_account):
        st, omni, op = complete_account
        row = reconcile_accounts(st, omni, op)["groq"][0]
        assert row.status in ACCOUNT_STATUSES

    def test_complete_only_when_nothing_missing(self, complete_account):
        st, omni, op = complete_account
        row = reconcile_accounts(st, omni, op)["groq"][0]
        if row.status == STATUS_COMPLETE:
            assert row.missing_components == []
        else:
            assert row.missing_components, "non-complete must explain what's missing"


# ── Detection of each problem class ─────────────────────────────────────────

class TestProblemDetection:

    def test_missing_omniroute_detected(self):
        pa = [{"id": "pa1", "provider_id": "groq",
               "credential_ref": {"item_id": "i1", "item_title": "Groq Api Key",
                                  "reference": "op://Personal/i1/credential"}}]
        view = reconcile_accounts(state_with(pa), [], [])
        row = view["groq"][0]
        assert "omniroute_connection" in row.missing_components
        assert row.status in (STATUS_MISSING, STATUS_UNKNOWN, STATUS_ORPHANED)

    def test_missing_api_key_detected(self):
        pa = [{"id": "pa1", "provider_id": "groq",
               "omniroute_account_id": "c1"}]
        omni = [{"provider_id": "groq", "connection_id": "c1"}]
        row = reconcile_accounts(state_with(pa), omni, [])["groq"][0]
        assert "onepassword_api_key" in row.missing_components

    def test_orphaned_detected(self):
        omni = [{"provider_id": "groq", "connection_id": "c_orphan",
                 "display_name": "nobody@example.com"}]
        view = reconcile_accounts(state_with([]), omni, [])
        rows = view.get("groq", [])
        assert rows, "an orphan connection must surface as an account row"
        assert rows[0].status in (STATUS_ORPHANED, STATUS_MISSING, STATUS_UNKNOWN)

    def test_conflicting_identity_detected(self):
        idents = [
            {"id": _ID.format("a"), "type": "email", "value": "a@example.com"},
            {"id": _ID.format("b"), "type": "email", "value": "b@example.com"},
        ]
        pa = [
            {"id": "pa1", "provider_id": "groq", "identity_id": _ID.format("a"),
             "omniroute_account_id": "shared"},
            {"id": "pa2", "provider_id": "groq", "identity_id": _ID.format("b"),
             "omniroute_account_id": "shared"},
        ]
        omni = [{"provider_id": "groq", "connection_id": "shared"}]
        view = reconcile_accounts(state_with(pa, idents), omni, [])
        statuses = {r.status for r in view["groq"]}
        assert STATUS_CONFLICTING in statuses

    def test_duplicate_detected(self):
        idents = [{"id": _ID.format("a"), "type": "email", "value": "a@example.com"}]
        pa = [
            {"id": "pa1", "provider_id": "groq", "identity_id": _ID.format("a"),
             "omniroute_account_id": "c1"},
            {"id": "pa2", "provider_id": "groq", "identity_id": _ID.format("a"),
             "omniroute_account_id": "c2"},
        ]
        omni = [{"provider_id": "groq", "connection_id": "c1"},
                {"provider_id": "groq", "connection_id": "c2"}]
        view = reconcile_accounts(state_with(pa, idents), omni, [])
        problems = detect_problems(view)
        assert (problems["duplicate"] or problems["conflicting"]
                or problems["missing"]), "same identity twice must be flagged"

    def test_unknown_stays_unknown(self):
        pa = [{"id": "pa1", "provider_id": "groq"}]
        row = reconcile_accounts(state_with(pa), [], [])["groq"][0]
        assert row.status != STATUS_COMPLETE

    def test_problems_grouped_by_class(self):
        pa = [{"id": "pa1", "provider_id": "groq"}]
        problems = detect_problems(reconcile_accounts(state_with(pa), [], []))
        assert set(problems) == {"missing", "duplicate", "orphaned",
                                 "conflicting", "unknown"}

    def test_status_counts_sum_to_account_count(self, complete_account):
        st, omni, op = complete_account
        view = reconcile_accounts(st, omni, op)
        total = sum(len(v) for v in view.values())
        assert sum(status_counts(view).values()) == total


# ── Never repairs ───────────────────────────────────────────────────────────

class TestNeverRepairs:

    def test_rows_marked_not_repaired(self, complete_account):
        st, omni, op = complete_account
        for row in reconcile_accounts(st, omni, op)["groq"]:
            assert row.repaired is False
            assert row.requires_human_approval is True

    def test_report_declares_no_repair(self, complete_account):
        st, omni, op = complete_account
        rep = account_reconciliation_report(st, omni, op)
        assert rep["read_only"] is True
        assert rep["repaired_anything"] is False

    def test_no_mutating_calls_in_source(self):
        src = (SKILL_ROOT / "engine" / "account_reconcile.py").read_text()
        for forbidden in ("create_connection(", "create_item(", "save_state(",
                          "connect_provider(", "add_provider_account("):
            assert forbidden not in src

    def test_does_not_write_state(self, complete_account):
        import engine.state as state_mod
        st, omni, op = complete_account
        before = Path(state_mod.STATE_FILE).read_text()
        account_reconciliation_report(st, omni, op)
        assert Path(state_mod.STATE_FILE).read_text() == before

    def test_no_adapter_mutation_at_runtime(self, complete_account, monkeypatch):
        calls = []
        import adapters.omniroute as omni_mod
        import adapters.onepassword as op_mod
        for mod, names in ((omni_mod, ("connect_provider", "update_provider")),
                           (op_mod, ("create_item",))):
            for n in names:
                if hasattr(mod, n):
                    monkeypatch.setattr(mod, n, lambda *a, **k: calls.append(n))
        st, omni, op = complete_account
        account_reconciliation_report(st, omni, op)
        assert calls == []


# ── Feeds Phase 14 ──────────────────────────────────────────────────────────

class TestFeedsReviewSystem:

    def test_produces_findings(self):
        pa = [{"id": "pa1", "provider_id": "groq"}]
        findings = to_review_findings(state_with(pa))
        assert findings, "non-complete accounts must yield findings"

    def test_findings_use_review_module(self):
        src = (SKILL_ROOT / "engine" / "account_reconcile.py").read_text()
        assert "build_findings" in src, "must delegate to engine.review"

    def test_findings_are_secret_free(self):
        pa = [{"id": "pa1", "provider_id": "groq",
               "credential_ref": {"item_id": "i1",
                                  "reference": "op://Personal/i1/credential"}}]
        for f in to_review_findings(state_with(pa)):
            assert_secret_free(f.to_dict())

    def test_finding_account_keys_match_view(self):
        pa = [{"id": "pa1", "provider_id": "groq"}]
        st = state_with(pa)
        view_keys = {r.account_key for r in reconcile_accounts(st, [], [])["groq"]}
        finding_keys = {f.account_key for f in to_review_findings(st)}
        assert finding_keys <= view_keys


# ── One canonical matching model ────────────────────────────────────────────

class TestCanonicalModel:

    def test_no_matching_logic_reimplemented(self):
        src = (SKILL_ROOT / "engine" / "account_reconcile.py").read_text()
        for forbidden in ("def reconcile_account(", "def reconcile_provider(",
                          "def account_key(", "def normalize_onepassword_items("):
            assert forbidden not in src, "no parallel matching implementation"

    def test_delegates_to_inventory(self):
        src = (SKILL_ROOT / "engine" / "account_reconcile.py").read_text()
        assert "build_inventory" in src

    def test_account_keys_match_inventory(self, complete_account):
        st, omni, op = complete_account
        inv = build_inventory(st, omni, op)
        view = reconcile_accounts(st, omni, op)
        assert {a.account_key for a in inv["groq"].accounts} == \
               {r.account_key for r in view["groq"]}

    def test_reconciliation_state_passed_through(self, complete_account):
        st, omni, op = complete_account
        inv = build_inventory(st, omni, op)
        expected = {a.account_key: a.reconciliation_state
                    for a in inv["groq"].accounts}
        for r in reconcile_accounts(st, omni, op)["groq"]:
            assert r.reconciliation_state == expected[r.account_key]

    def test_can_be_driven_from_prebuilt_inventory(self, complete_account):
        st, omni, op = complete_account
        inv = build_inventory(st, omni, op)
        view = reconcile_accounts(inventory=inv)
        assert view["groq"][0].account_key in {
            a.account_key for a in inv["groq"].accounts}


# ── Multi-account correctness ───────────────────────────────────────────────

class TestMultiAccount:

    def test_two_accounts_reconciled_separately(self):
        idents = [
            {"id": _ID.format("a"), "type": "email", "value": "a@example.com"},
            {"id": _ID.format("b"), "type": "email", "value": "b@example.com"},
        ]
        pa = [
            {"id": "pa1", "provider_id": "groq", "identity_id": _ID.format("a"),
             "omniroute_account_id": "c1"},
            {"id": "pa2", "provider_id": "groq", "identity_id": _ID.format("b")},
        ]
        omni = [{"provider_id": "groq", "connection_id": "c1"}]
        rows = reconcile_accounts(state_with(pa, idents), omni, [])["groq"]
        assert len(rows) == 2
        by_label = {r.account_label: r for r in rows}
        assert by_label["a@example.com"].components["omniroute_connection"] is True
        assert by_label["b@example.com"].components["omniroute_connection"] is False

    def test_no_first_account_shortcut(self):
        idents = [
            {"id": _ID.format("a"), "type": "email", "value": "a@example.com"},
            {"id": _ID.format("b"), "type": "email", "value": "b@example.com"},
        ]
        pa = [
            {"id": "pa1", "provider_id": "groq", "identity_id": _ID.format("a")},
            {"id": "pa2", "provider_id": "groq", "identity_id": _ID.format("b")},
        ]
        rows = reconcile_accounts(state_with(pa, idents), [], [])["groq"]
        assert len({r.account_key for r in rows}) == 2


# ── Serialization / determinism / secrets ───────────────────────────────────

class TestOutputQuality:

    def test_report_json_serializable(self, complete_account):
        st, omni, op = complete_account
        json.dumps(account_reconciliation_report(st, omni, op))

    def test_report_secret_free(self, complete_account):
        st, omni, op = complete_account
        assert_secret_free(account_reconciliation_report(st, omni, op))

    def test_no_secret_value_leaks(self, complete_account):
        st, omni, op = complete_account
        st["provider_accounts"][0]["credential_ref"]["credential"] = \
            "gsk_TESTSECRETVALUE1234567890"
        blob = json.dumps(account_reconciliation_report(st, omni, op))
        assert "gsk_TESTSECRETVALUE1234567890" not in blob

    def test_deterministic(self, complete_account):
        st, omni, op = complete_account
        a = account_reconciliation_report(st, omni, op)
        b = account_reconciliation_report(st, omni, op)
        assert a == b

    def test_render_is_stable(self, complete_account):
        st, omni, op = complete_account
        v = reconcile_accounts(st, omni, op)
        assert render_report(v) == render_report(v)


# ── Production-shaped state ─────────────────────────────────────────────────

class TestProductionShaped:

    def test_production_state_reconciles(self):
        prod = SKILL_ROOT / "provider_state.json"
        if not prod.exists():
            pytest.skip("no production state")
        st = json.loads(prod.read_text())
        rep = account_reconciliation_report(st)
        assert rep["repaired_anything"] is False
        assert_secret_free(rep)
        json.dumps(rep)

    def test_production_state_not_rewritten(self):
        prod = SKILL_ROOT / "provider_state.json"
        if not prod.exists():
            pytest.skip("no production state")
        before = prod.read_text()
        account_reconciliation_report(json.loads(before))
        assert prod.read_text() == before

    def test_production_render_does_not_crash(self):
        prod = SKILL_ROOT / "provider_state.json"
        if not prod.exists():
            pytest.skip("no production state")
        out = render_report(reconcile_accounts(json.loads(prod.read_text())))
        assert "nothing was repaired" in out


# ── CLI ─────────────────────────────────────────────────────────────────────

class TestCli:

    def test_account_reconcile_json(self, capsys):
        import cli
        assert cli.main(["account-reconcile", "--json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["repaired_anything"] is False

    def test_account_reconcile_human(self, capsys):
        import cli
        assert cli.main(["account-reconcile"]) == 0
        assert "nothing was repaired" in capsys.readouterr().out
