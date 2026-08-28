"""
test_phase14_review.py — Phase 14 read-only inconsistency review system.

Covers:
  * every reconciliation state maps to a finding category
  * severity assignment
  * deterministic finding IDs
  * deduplication
  * multiple accounts per provider
  * conflicting identities
  * orphaned records
  * missing credentials
  * unknown / ambiguous cases
  * JSON serialization
  * secret redaction
  * review state persistence (separate file, no external mutation)
  * production-shaped state
  * zero mutations to external systems
"""

import json
import sys
from pathlib import Path

import pytest

SKILL_ROOT = Path(__file__).parent.parent
if str(SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT))

from engine import review as review_mod
from engine.accounts import AccountView, build_account_model
from engine.review import (
    CATEGORIES,
    CATEGORY_CONFLICTING_IDENTITY,
    CATEGORY_DUPLICATE,
    CATEGORY_MISSING_API_KEY,
    CATEGORY_MISSING_HERMES,
    CATEGORY_MISSING_LOGIN,
    CATEGORY_MISSING_OMNIROUTE,
    CATEGORY_ORPHANED,
    CATEGORY_UNKNOWN,
    REVIEW_ACKNOWLEDGED,
    REVIEW_IGNORED,
    REVIEW_OPEN,
    REVIEW_RESOLVED,
    SEVERITIES,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    Finding,
    apply_review_state,
    assert_secret_free,
    build_findings,
    finding_from_account,
    finding_id,
    get_review_queue,
    get_review_status,
    load_review_state,
    proposed_actions,
    set_review_status,
    sort_findings,
)
from engine.reconcile import (
    RECON_STATES,
    STATE_COMPLETE,
    STATE_CONFLICTING_IDENTITY,
    STATE_DUPLICATE,
    STATE_MISSING_API_KEY,
    STATE_MISSING_HERMES,
    STATE_MISSING_LOGIN,
    STATE_MISSING_OMNIROUTE,
    STATE_ORPHANED,
    STATE_UNKNOWN,
)

_ID = "identity_email_{}_x"


def av(provider="groq", key=None, state=STATE_UNKNOWN, **kw):
    """Build an AccountView for a specific reconciliation state."""
    return AccountView(
        provider_id=provider,
        account_id=key or f"{provider}::identity_email_ang_x",
        reconciliation_state=state,
        **kw,
    )


def state_with(provider_accounts, identities=None):
    return {
        "identities": identities or [],
        "external_accounts": [],
        "provider_accounts": provider_accounts,
        "credentials": [],
        "capabilities": [],
    }


@pytest.fixture
def review_path(tmp_path):
    return tmp_path / "review_state.json"


# ── Every reconciliation state is covered ───────────────────────────────────

class TestStateCoverage:

    def test_every_reconciliation_state_maps_to_a_category(self):
        for st in RECON_STATES:
            f = finding_from_account(av(state=st))
            if st == STATE_COMPLETE:
                assert f is None, "complete must not produce a finding"
            else:
                assert f is not None
                assert f.category in CATEGORIES
                assert f.severity in SEVERITIES

    def test_complete_produces_no_finding(self):
        assert finding_from_account(av(state=STATE_COMPLETE)) is None

    @pytest.mark.parametrize("st,cat", [
        (STATE_MISSING_LOGIN, CATEGORY_MISSING_LOGIN),
        (STATE_MISSING_API_KEY, CATEGORY_MISSING_API_KEY),
        (STATE_MISSING_OMNIROUTE, CATEGORY_MISSING_OMNIROUTE),
        (STATE_MISSING_HERMES, CATEGORY_MISSING_HERMES),
        (STATE_DUPLICATE, CATEGORY_DUPLICATE),
        (STATE_ORPHANED, CATEGORY_ORPHANED),
        (STATE_CONFLICTING_IDENTITY, CATEGORY_CONFLICTING_IDENTITY),
        (STATE_UNKNOWN, CATEGORY_UNKNOWN),
    ])
    def test_state_to_category_mapping(self, st, cat):
        assert finding_from_account(av(state=st)).category == cat

    def test_unrecognized_state_becomes_unknown_not_success(self):
        f = finding_from_account(av(state="some_new_state_we_dont_know"))
        assert f is not None
        assert f.category == CATEGORY_UNKNOWN
        assert any("unrecognized_reconciliation_state" in n for n in f.notes)


# ── Severity ────────────────────────────────────────────────────────────────

class TestSeverity:

    def test_conflicting_identity_is_critical(self):
        assert finding_from_account(
            av(state=STATE_CONFLICTING_IDENTITY)).severity == SEVERITY_CRITICAL

    def test_missing_api_key_is_high(self):
        assert finding_from_account(
            av(state=STATE_MISSING_API_KEY)).severity == SEVERITY_HIGH

    def test_missing_omniroute_is_high(self):
        assert finding_from_account(
            av(state=STATE_MISSING_OMNIROUTE)).severity == SEVERITY_HIGH

    def test_severity_sort_puts_critical_first(self):
        fs = [
            finding_from_account(av(provider="a", state=STATE_MISSING_HERMES)),
            finding_from_account(av(provider="b", state=STATE_CONFLICTING_IDENTITY)),
            finding_from_account(av(provider="c", state=STATE_MISSING_API_KEY)),
        ]
        ordered = sort_findings(fs)
        assert ordered[0].severity == SEVERITY_CRITICAL


# ── Deterministic IDs ───────────────────────────────────────────────────────

class TestFindingIds:

    def test_id_is_deterministic(self):
        a = finding_id("groq", "groq::identity_email_ang_x", CATEGORY_MISSING_API_KEY)
        b = finding_id("groq", "groq::identity_email_ang_x", CATEGORY_MISSING_API_KEY)
        assert a == b

    def test_id_varies_by_account(self):
        a = finding_id("groq", "groq::one", CATEGORY_MISSING_API_KEY)
        b = finding_id("groq", "groq::two", CATEGORY_MISSING_API_KEY)
        assert a != b

    def test_id_varies_by_category(self):
        a = finding_id("groq", "groq::one", CATEGORY_MISSING_API_KEY)
        b = finding_id("groq", "groq::one", CATEGORY_MISSING_LOGIN)
        assert a != b

    def test_id_contains_no_secret(self):
        fid = finding_id("groq", "groq::identity_email_ang_x", CATEGORY_MISSING_API_KEY)
        assert "sk-" not in fid
        assert "SECRET" not in fid

    def test_ids_stable_across_two_queue_builds(self):
        st = state_with([{"id": "pa1", "provider_id": "groq"}])
        q1 = get_review_queue(st)
        q2 = get_review_queue(st)
        assert [f["finding_id"] for f in q1["findings"]] == \
               [f["finding_id"] for f in q2["findings"]]


# ── Deduplication ───────────────────────────────────────────────────────────

class TestDeduplication:

    def test_identical_findings_deduplicated(self):
        accs = [
            av(state=STATE_MISSING_API_KEY, issues=["x"]),
            av(state=STATE_MISSING_API_KEY, issues=["y"]),
        ]
        fs = build_findings(model={"groq": accs})
        assert len(fs) == 1
        # merged evidence, not two rows
        assert fs[0].evidence["issues"] == ["x", "y"]

    def test_distinct_accounts_not_deduplicated(self):
        accs = [
            av(key="groq::a", state=STATE_MISSING_API_KEY),
            av(key="groq::b", state=STATE_MISSING_API_KEY),
        ]
        fs = build_findings(model={"groq": accs})
        assert len(fs) == 2


# ── Multi-account awareness ─────────────────────────────────────────────────

class TestMultipleAccounts:

    def test_two_accounts_produce_separate_findings(self):
        pa = [
            {"id": "pa_ang", "provider_id": "groq",
             "identity_id": _ID.format("ang"), "omniroute_account_id": None},
            {"id": "pa_lazy", "provider_id": "groq",
             "identity_id": _ID.format("lazy"), "omniroute_account_id": None},
        ]
        idents = [
            {"id": _ID.format("ang"), "type": "email", "value": "ang@example.com"},
            {"id": _ID.format("lazy"), "type": "email", "value": "lazymause@gmail.com"},
        ]
        q = get_review_queue(state_with(pa, idents))
        keys = {f["account_key"] for f in q["findings"]}
        assert len(keys) == 2, "must not collapse provider → first account"

    def test_provider_never_reduced_to_first_account(self):
        model = {
            "groq": [
                av(key="groq::a", state=STATE_MISSING_API_KEY),
                av(key="groq::b", state=STATE_MISSING_OMNIROUTE),
            ],
        }
        cats = {f.category for f in build_findings(model=model)}
        assert cats == {CATEGORY_MISSING_API_KEY, CATEGORY_MISSING_OMNIROUTE}


# ── Conflicting identity / orphaned / missing credentials ───────────────────

class TestConflictsOrphansMissing:

    def test_conflicting_identity_finding(self):
        model = {"groq": [av(state=STATE_CONFLICTING_IDENTITY,
                             identity_email="a@example.com")]}
        f = build_findings(model=model)[0]
        assert f.category == CATEGORY_CONFLICTING_IDENTITY
        assert f.severity == SEVERITY_CRITICAL
        assert f.automation_safe is False, "conflicts are never auto-safe"

    def test_orphaned_finding(self):
        model = {"groq": [av(state=STATE_ORPHANED, has_api_key=True)]}
        f = build_findings(model=model)[0]
        assert f.category == CATEGORY_ORPHANED
        assert f.automation_safe is False

    def test_missing_api_key_finding_has_action(self):
        model = {"groq": [av(state=STATE_MISSING_API_KEY, has_login=True)]}
        f = build_findings(model=model)[0]
        assert f.recommended_action == "acquire_api_key"
        assert f.action_status == "proposed"
        assert f.requires_human_approval is True

    def test_missing_login_action(self):
        model = {"groq": [av(state=STATE_MISSING_LOGIN)]}
        assert build_findings(model=model)[0].recommended_action == "acquire_login"

    def test_missing_omniroute_action(self):
        model = {"groq": [av(state=STATE_MISSING_OMNIROUTE)]}
        assert build_findings(model=model)[0].recommended_action == "connect_omniroute"

    def test_unknown_is_manual_investigation(self):
        model = {"groq": [av(state=STATE_UNKNOWN)]}
        f = build_findings(model=model)[0]
        assert f.recommended_action == "manual_investigation"
        assert f.automation_safe is False


# ── Systems / evidence ──────────────────────────────────────────────────────

class TestEvidence:

    def test_systems_listed_deterministically(self):
        f = finding_from_account(av(state=STATE_MISSING_OMNIROUTE,
                                    has_login=True, has_hermes_ref=True))
        assert f.systems == ["1password", "hermes"]

    def test_evidence_keeps_only_reference_metadata(self):
        ref = {"item_id": "i1", "title": "Groq Api Key",
               "reference": "op://Personal/i1/credential",
               "password": "SHOULD_NOT_SURVIVE"}
        f = finding_from_account(av(state=STATE_MISSING_OMNIROUTE, api_key_ref=ref))
        assert f.evidence["api_key_ref"]["reference"].startswith("op://")
        assert "password" not in f.evidence["api_key_ref"]


# ── JSON serialization + secret redaction ───────────────────────────────────

class TestSerializationAndSecrets:

    def test_queue_is_json_serializable(self):
        q = get_review_queue(state_with([{"id": "pa1", "provider_id": "groq"}]))
        s = json.dumps(q)
        assert isinstance(s, str)
        assert json.loads(s)["read_only"] is True

    def test_queue_is_secret_free(self):
        pa = [{
            "id": "pa1", "provider_id": "groq",
            "credential_ref": {
                "item_id": "i1", "item_title": "Groq Api Key",
                "reference": "op://Personal/i1/credential",
            },
        }]
        q = get_review_queue(state_with(pa))
        assert_secret_free(q)
        blob = json.dumps(q)
        for bad in ("sk-", "gsk_", "SECRET", "DO_NOT_LEAK"):
            assert bad not in blob

    def test_op_reference_is_allowed(self):
        ref = {"item_id": "i1", "reference": "op://Personal/i1/credential"}
        f = finding_from_account(av(state=STATE_MISSING_OMNIROUTE, api_key_ref=ref))
        assert_secret_free(f.to_dict())
        assert f.evidence["api_key_ref"]["reference"] == "op://Personal/i1/credential"

    def test_forbidden_key_detected(self):
        with pytest.raises(AssertionError):
            assert_secret_free({"findings": [{"api_key_value": "gsk_live"}]})

    def test_finding_dataclass_roundtrips(self):
        f = Finding(finding_id="finding_x", severity="high",
                    category=CATEGORY_MISSING_API_KEY,
                    provider_id="groq", account_key="groq::a")
        assert json.loads(json.dumps(f.to_dict()))["finding_id"] == "finding_x"


# ── Review status persistence ───────────────────────────────────────────────

class TestReviewStatePersistence:

    def test_default_status_is_open(self, review_path):
        assert get_review_status("finding_x", review_path) == REVIEW_OPEN

    def test_status_persists(self, review_path):
        set_review_status("finding_x", REVIEW_ACKNOWLEDGED, path=review_path)
        assert get_review_status("finding_x", review_path) == REVIEW_ACKNOWLEDGED
        assert review_path.exists()

    def test_all_statuses_accepted(self, review_path):
        for st in (REVIEW_OPEN, REVIEW_ACKNOWLEDGED, REVIEW_RESOLVED, REVIEW_IGNORED):
            set_review_status("f1", st, path=review_path)
            assert get_review_status("f1", review_path) == st

    def test_invalid_status_rejected(self, review_path):
        with pytest.raises(ValueError):
            set_review_status("f1", "repaired", path=review_path)

    def test_review_state_is_separate_from_provider_state(self, review_path):
        import engine.state as state_mod
        before = json.loads(Path(state_mod.STATE_FILE).read_text())
        set_review_status("f1", REVIEW_RESOLVED, path=review_path)
        after = json.loads(Path(state_mod.STATE_FILE).read_text())
        assert before == after, "review status must not touch provider_state.json"

    def test_resolved_does_not_mutate_external_systems(self, review_path, monkeypatch):
        """Marking resolved must not call any adapter."""
        calls = []
        import adapters.omniroute as omni
        import adapters.onepassword as op
        for mod, name in ((omni, "create_connection"), (op, "create_item")):
            if hasattr(mod, name):
                monkeypatch.setattr(mod, name,
                                    lambda *a, **k: calls.append(name))
        set_review_status("f1", REVIEW_RESOLVED, path=review_path)
        assert calls == []

    def test_status_overlaid_on_queue(self, review_path):
        st = state_with([{"id": "pa1", "provider_id": "groq"}])
        q = get_review_queue(st, review_state_path=review_path)
        fid = q["findings"][0]["finding_id"]
        set_review_status(fid, REVIEW_IGNORED, path=review_path)
        q2 = get_review_queue(st, review_state_path=review_path)
        target = [f for f in q2["findings"] if f["finding_id"] == fid][0]
        assert target["review_status"] == REVIEW_IGNORED

    def test_status_filter(self, review_path):
        st = state_with([{"id": "pa1", "provider_id": "groq"}])
        q = get_review_queue(st, review_state_path=review_path)
        fid = q["findings"][0]["finding_id"]
        set_review_status(fid, REVIEW_IGNORED, path=review_path)
        filtered = get_review_queue(st, review_state_path=review_path,
                                    include_statuses=(REVIEW_OPEN,))
        assert fid not in [f["finding_id"] for f in filtered["findings"]]

    def test_apply_review_state_adds_notes(self, review_path):
        set_review_status("finding_x", REVIEW_ACKNOWLEDGED,
                          note="checked by hand", path=review_path)
        f = Finding(finding_id="finding_x", severity="high",
                    category=CATEGORY_MISSING_API_KEY,
                    provider_id="groq", account_key="groq::a")
        apply_review_state([f], review_path)
        assert f.review_status == REVIEW_ACKNOWLEDGED
        assert "checked by hand" in f.notes

    def test_load_review_state_handles_missing_file(self, tmp_path):
        data = load_review_state(tmp_path / "nope.json")
        assert data["findings"] == {}


# ── Proposed actions are never executed ─────────────────────────────────────

class TestProposedActionsOnly:

    def test_all_actions_require_approval(self):
        st = state_with([{"id": "pa1", "provider_id": "groq"}])
        for a in proposed_actions(get_review_queue(st)):
            assert a["status"] == "proposed"
            assert a["requires_human_approval"] is True

    def test_review_module_has_no_mutating_adapter_calls(self):
        src = (SKILL_ROOT / "engine" / "review.py").read_text()
        for forbidden in ("create_connection", "create_item", "save_state(",
                          "add_provider_account", "register_provider"):
            assert forbidden not in src, f"review.py must not call {forbidden}"

    def test_building_queue_does_not_write_provider_state(self):
        import engine.state as state_mod
        before = Path(state_mod.STATE_FILE).read_text()
        get_review_queue(state_with([{"id": "pa1", "provider_id": "groq"}]))
        assert Path(state_mod.STATE_FILE).read_text() == before


# ── Production-shaped state ─────────────────────────────────────────────────

class TestProductionShapedState:

    def test_production_state_reviewable(self):
        prod = SKILL_ROOT / "provider_state.json"
        if not prod.exists():
            pytest.skip("no production state present")
        st = json.loads(prod.read_text())
        q = get_review_queue(st)
        assert q["read_only"] is True
        assert isinstance(q["findings"], list)
        assert_secret_free(q)
        json.dumps(q)

    def test_production_state_not_rewritten(self):
        prod = SKILL_ROOT / "provider_state.json"
        if not prod.exists():
            pytest.skip("no production state present")
        before = prod.read_text()
        get_review_queue(json.loads(before))
        assert prod.read_text() == before

    def test_empty_state_yields_empty_queue(self):
        q = get_review_queue(state_with([]))
        assert q["total_findings"] == 0
        assert q["findings"] == []


# ── CLI read-only surface ───────────────────────────────────────────────────

class TestCli:

    def test_review_json_output(self, capsys):
        import cli
        rc = cli.main(["review", "--json"])
        out = capsys.readouterr().out
        assert rc == 0
        assert json.loads(out)["read_only"] is True

    def test_reconcile_json_output(self, capsys):
        import cli
        assert cli.main(["reconcile", "--json"]) == 0
        assert "summary" in json.loads(capsys.readouterr().out)

    def test_accounts_json_output(self, capsys):
        import cli
        assert cli.main(["accounts", "--json"]) == 0
        assert "summary" in json.loads(capsys.readouterr().out)

    def test_audit_json_output(self, capsys):
        import cli
        assert cli.main(["audit", "--json"]) == 0
        assert isinstance(json.loads(capsys.readouterr().out), dict)

    def test_review_human_output(self, capsys):
        import cli
        assert cli.main(["review"]) == 0
        assert "read-only" in capsys.readouterr().out.lower()
