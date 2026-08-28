"""
test_phase19_discovery.py — Phase 19 provider discovery pipeline.

Covers:
  * discovery → candidate → classification → feasibility → review → approved
  * discovery NEVER registers an account
  * discovery NEVER writes provider_catalog.json
  * discovery/classification/approval/registration are separate steps
  * unknown providers stay unknown until evidence is sufficient
  * a signup page alone does NOT make a provider supported
  * no periodic discovery / scheduled scan hooks
  * deterministic candidate ids, JSON serialization, secret-free
"""

import json
import sys
from pathlib import Path

import pytest

SKILL_ROOT = Path(__file__).parent.parent
if str(SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT))

from engine.discovery import (
    MIN_STRONG_SIGNALS_TO_CLASSIFY,
    SIGNAL_AUTH_TYPE_DOCUMENTED,
    SIGNAL_DOCS_PAGE,
    SIGNAL_KEY_FORMAT_KNOWN,
    SIGNAL_OMNIROUTE_SUPPORT,
    SIGNAL_SIGNUP_PAGE,
    SIGNAL_TOS_REVIEWED,
    STATE_APPROVED,
    STATE_AWAITING_REVIEW,
    STATE_CANDIDATE,
    STATE_CLASSIFIED,
    STATE_FEASIBLE,
    STATE_INFEASIBLE,
    STATE_REJECTED,
    STATE_UNKNOWN,
    CandidateProvider,
    Evidence,
    approve_candidate,
    candidate_id,
    classify_candidate,
    discover_candidates,
    discovery_review_queue,
    draft_catalog_entry,
    load_discovery_state,
    make_candidate,
    normalize_provider_id,
    reject_candidate,
    request_review,
    run_discovery_pipeline,
    save_discovery_state,
)
from engine.review import assert_secret_free


def raw(name="Brand New AI", **kw):
    d = {"name": name, "homepage": "https://brandnew.ai",
         "signup_url": "https://brandnew.ai/signup"}
    d.update(kw)
    return d


def strong_evidence():
    return [
        {"signal": SIGNAL_AUTH_TYPE_DOCUMENTED, "source": "https://docs.brandnew.ai"},
        {"signal": SIGNAL_KEY_FORMAT_KNOWN, "source": "https://docs.brandnew.ai/keys"},
    ]


# ── Discovery step ──────────────────────────────────────────────────────────

class TestDiscovery:

    def test_candidate_created(self):
        cands = discover_candidates([raw()])
        assert len(cands) == 1
        assert cands[0].name == "Brand New AI"
        assert cands[0].state == STATE_CANDIDATE

    def test_candidate_id_deterministic(self):
        a = candidate_id("Brand New AI", "https://brandnew.ai")
        b = candidate_id("Brand New AI", "https://brandnew.ai")
        assert a == b

    def test_candidate_id_varies_by_host(self):
        a = candidate_id("Brand New AI", "https://brandnew.ai")
        b = candidate_id("Brand New AI", "https://other.ai")
        assert a != b

    def test_provider_id_suggested_not_applied(self):
        c = make_candidate("Brand New AI!")
        assert c.suggested_provider_id == "brand-new-ai"
        assert c.catalog_promoted is False

    def test_known_provider_flagged(self):
        c = make_candidate("Groq")
        assert c.already_in_catalog is True

    def test_duplicates_deduplicated(self):
        cands = discover_candidates([raw(), raw()])
        assert len(cands) == 1

    def test_invalid_raw_ignored(self):
        # Malformed entries (empty dict, missing name, non-dict) are skipped.
        assert discover_candidates([{}, {"homepage": "x"}]) == []
        assert discover_candidates([None]) == []  # type: ignore[list-item]

    def test_discovery_is_deterministic(self):
        a = [c.candidate_id for c in discover_candidates([raw("A"), raw("B")])]
        b = [c.candidate_id for c in discover_candidates([raw("B"), raw("A")])]
        assert a == b == sorted(a)

    def test_no_classification_during_discovery(self):
        c = discover_candidates([raw(evidence=strong_evidence())])[0]
        assert c.state == STATE_CANDIDATE
        assert c.support_classification == "unknown"
        assert c.policy_classification == "unknown"


# ── Signup page is not evidence of support ──────────────────────────────────

class TestSignupPageIsNotEvidence:

    def test_signup_page_recorded_as_weak_signal(self):
        c = make_candidate("Brand New AI", signup_url="https://brandnew.ai/signup")
        ev = [e for e in c.evidence if e.signal == SIGNAL_SIGNUP_PAGE]
        assert ev and ev[0].is_strong is False

    def test_signup_page_alone_stays_unknown(self):
        c = classify_candidate(discover_candidates([raw()])[0])
        assert c.state == STATE_CANDIDATE
        assert c.support_classification == "unknown"
        assert c.feasibility == STATE_UNKNOWN

    def test_signup_plus_docs_still_insufficient(self):
        c = classify_candidate(discover_candidates(
            [raw(docs_url="https://brandnew.ai/docs")])[0])
        assert c.support_classification == "unknown"
        assert c.state == STATE_CANDIDATE

    def test_docs_page_is_weak(self):
        e = Evidence(SIGNAL_DOCS_PAGE, "https://x/docs")
        assert e.is_strong is False

    def test_no_supported_shortcut_exists(self):
        """No promotion shortcut may be *defined or called*.

        The module docstring deliberately mentions `mark_supported` to state
        that no such shortcut exists, so match on definition/call syntax
        rather than on the bare name appearing anywhere in the file.
        """
        import engine.discovery as disc
        src = (SKILL_ROOT / "engine" / "discovery.py").read_text()
        assert "def mark_supported" not in src
        assert "mark_supported(" not in src
        assert not hasattr(disc, "mark_supported")
        # A candidate is never classified as fully "supported" by discovery.
        assert 'support_classification = "supported"' not in src
        assert 'support_classification="supported"' not in src

    def test_full_evidence_still_not_fully_supported(self):
        """Even maximal evidence yields at most 'partial' support."""
        ev = strong_evidence() + [
            {"signal": SIGNAL_OMNIROUTE_SUPPORT, "source": "https://omniroute/docs"},
            {"signal": SIGNAL_TOS_REVIEWED, "source": "https://brandnew.ai/tos"},
        ]
        c = classify_candidate(discover_candidates([raw(evidence=ev)])[0])
        assert c.support_classification in ("unknown", "partial")
        assert c.support_classification != "supported"


# ── Classification step ─────────────────────────────────────────────────────

class TestClassification:

    def test_insufficient_evidence_stays_unknown(self):
        c = classify_candidate(make_candidate("X"))
        assert c.feasibility == STATE_UNKNOWN
        assert c.state == STATE_CANDIDATE

    def test_two_strong_signals_classify(self):
        c = discover_candidates([raw(evidence=strong_evidence())])[0]
        c = classify_candidate(c)
        assert c.strong_signal_count >= MIN_STRONG_SIGNALS_TO_CLASSIFY
        assert c.state == STATE_CLASSIFIED

    def test_missing_omniroute_makes_infeasible(self):
        c = classify_candidate(discover_candidates(
            [raw(evidence=strong_evidence())])[0])
        assert c.feasibility == STATE_INFEASIBLE
        assert any("OmniRoute" in r for r in c.feasibility_reasons)

    def test_full_evidence_is_feasible(self):
        ev = strong_evidence() + [
            {"signal": SIGNAL_OMNIROUTE_SUPPORT, "source": "https://omniroute/docs"},
            {"signal": SIGNAL_TOS_REVIEWED, "source": "https://brandnew.ai/tos"},
        ]
        c = classify_candidate(discover_candidates([raw(evidence=ev)])[0])
        assert c.feasibility == STATE_FEASIBLE
        assert c.state == STATE_CLASSIFIED

    def test_policy_never_becomes_allowed_automatically(self):
        ev = strong_evidence() + [
            {"signal": SIGNAL_TOS_REVIEWED, "source": "https://brandnew.ai/tos"},
        ]
        c = classify_candidate(discover_candidates([raw(evidence=ev)])[0])
        assert c.policy_classification != "allowed"

    def test_policy_unknown_without_tos_review(self):
        c = classify_candidate(discover_candidates(
            [raw(evidence=strong_evidence())])[0])
        assert c.policy_classification == "unknown"

    def test_credential_format_unknown_blocks_extraction(self):
        ev = [{"signal": SIGNAL_AUTH_TYPE_DOCUMENTED, "source": "x"},
              {"signal": SIGNAL_OMNIROUTE_SUPPORT, "source": "y"}]
        c = classify_candidate(discover_candidates([raw(evidence=ev)])[0])
        assert any("extraction" in r for r in c.feasibility_reasons)

    def test_already_in_catalog_noted(self):
        c = classify_candidate(make_candidate("Groq"))
        assert any("already present" in r for r in c.feasibility_reasons)

    def test_unknown_signal_ignored(self):
        c = discover_candidates([raw(evidence=[{"signal": "made_up", "source": "x"}])])[0]
        assert all(e.signal != "made_up" for e in c.evidence)


# ── Separation of stages ────────────────────────────────────────────────────

class TestStageSeparation:

    def test_cannot_approve_unclassified(self):
        c = make_candidate("Brand New AI")
        with pytest.raises(ValueError):
            approve_candidate(c, "angelo")

    def test_approval_requires_approver(self):
        c = classify_candidate(discover_candidates(
            [raw(evidence=strong_evidence())])[0])
        with pytest.raises(ValueError):
            approve_candidate(c, "")

    def test_approval_does_not_register(self):
        c = classify_candidate(discover_candidates(
            [raw(evidence=strong_evidence())])[0])
        c = approve_candidate(c, "angelo")
        assert c.state == STATE_APPROVED
        assert c.registered is False
        assert c.catalog_promoted is False

    def test_review_request_is_its_own_step(self):
        c = classify_candidate(discover_candidates(
            [raw(evidence=strong_evidence())])[0])
        c = request_review(c)
        assert c.state == STATE_AWAITING_REVIEW
        assert c.registered is False

    def test_rejection_recorded(self):
        c = classify_candidate(discover_candidates(
            [raw(evidence=strong_evidence())])[0])
        c = reject_candidate(c, "angelo", "ToS forbids automation")
        assert c.state == STATE_REJECTED
        assert any("ToS forbids" in n for n in c.notes)

    def test_classification_does_not_approve(self):
        c = classify_candidate(discover_candidates(
            [raw(evidence=strong_evidence())])[0])
        assert c.approved_by is None
        assert c.state != STATE_APPROVED


# ── Never registers, never activates, never edits the catalog ───────────────

class TestNoAutomaticAction:

    def test_pipeline_declares_no_automation(self):
        r = run_discovery_pipeline([raw()])
        assert r["automatic_signup"] is False
        assert r["automatic_activation"] is False
        assert r["registered_anything"] is False
        assert r["catalog_modified"] is False

    def test_catalog_file_untouched(self):
        cat = SKILL_ROOT / "provider_catalog.json"
        before = cat.read_text()
        run_discovery_pipeline([raw(evidence=strong_evidence())])
        assert cat.read_text() == before

    def test_provider_state_untouched(self):
        import engine.state as state_mod
        before = Path(state_mod.STATE_FILE).read_text()
        run_discovery_pipeline([raw(evidence=strong_evidence())])
        assert Path(state_mod.STATE_FILE).read_text() == before

    def test_no_adapter_calls(self, monkeypatch):
        calls = []
        import adapters.omniroute as omni
        import adapters.onepassword as op
        for mod, names in ((omni, ("connect_provider", "update_provider")),
                           (op, ("create_item",))):
            for n in names:
                if hasattr(mod, n):
                    monkeypatch.setattr(mod, n, lambda *a, **k: calls.append(n))
        run_discovery_pipeline([raw(evidence=strong_evidence())])
        assert calls == []

    def test_no_mutating_calls_in_source(self):
        src = (SKILL_ROOT / "engine" / "discovery.py").read_text()
        for forbidden in ("create_connection(", "create_item(", "save_state(",
                          "connect_provider(", "execute_approved_action(",
                          "plan_registration("):
            assert forbidden not in src

    def test_draft_entry_is_data_only(self):
        c = approve_candidate(classify_candidate(discover_candidates(
            [raw(evidence=strong_evidence())])[0]), "angelo")
        draft = draft_catalog_entry(c)
        assert draft["_draft"] is True
        assert draft["_requires_human_review"] is True
        assert draft["policy"]["automation_allowed"] == "unknown"

    def test_draft_does_not_guess_unknowns(self):
        c = approve_candidate(classify_candidate(discover_candidates(
            [raw(evidence=strong_evidence())])[0]), "angelo")
        draft = draft_catalog_entry(c)
        assert draft["omniroute_support"]["supported"] is False
        assert draft["signup_difficulty"] == "unknown"


# ── No periodic discovery ───────────────────────────────────────────────────

class TestNoPeriodicDiscovery:

    def test_pipeline_flags_periodic_disabled(self):
        assert run_discovery_pipeline([raw()])["periodic_discovery_enabled"] is False
        assert run_discovery_pipeline([raw()])["scheduled_scans"] is False

    def test_no_scheduler_hooks_in_source(self):
        src = (SKILL_ROOT / "engine" / "discovery.py").read_text()
        for forbidden in ("cronjob", "schedule(", "APScheduler", "while True",
                          "time.sleep", "threading.Timer"):
            assert forbidden not in src

    def test_no_network_scanning_in_source(self):
        src = (SKILL_ROOT / "engine" / "discovery.py").read_text()
        for forbidden in ("requests.get", "urlopen(", "web_search",
                          "httpx.get", "subprocess."):
            assert forbidden not in src

    def test_candidates_must_be_supplied(self):
        assert run_discovery_pipeline(None)["candidates"] == []
        assert run_discovery_pipeline([])["candidates"] == []


# ── Persistence (own file) ──────────────────────────────────────────────────

class TestPersistence:

    def test_saves_to_own_file(self, tmp_path):
        p = tmp_path / "discovery.json"
        cands = discover_candidates([raw()])
        save_discovery_state(cands, p)
        assert p.exists()
        data = load_discovery_state(p)
        assert cands[0].candidate_id in data["candidates"]

    def test_persistence_does_not_touch_catalog(self, tmp_path):
        cat = SKILL_ROOT / "provider_catalog.json"
        before = cat.read_text()
        save_discovery_state(discover_candidates([raw()]), tmp_path / "d.json")
        assert cat.read_text() == before

    def test_missing_file_returns_empty(self, tmp_path):
        assert load_discovery_state(tmp_path / "nope.json")["candidates"] == {}

    def test_saved_state_marks_periodic_disabled(self, tmp_path):
        data = save_discovery_state(discover_candidates([raw()]),
                                    tmp_path / "d.json")
        assert data["periodic_discovery_enabled"] is False


# ── Output quality ──────────────────────────────────────────────────────────

class TestOutputQuality:

    def test_pipeline_json_serializable(self):
        json.dumps(run_discovery_pipeline([raw(evidence=strong_evidence())]))

    def test_pipeline_secret_free(self):
        assert_secret_free(run_discovery_pipeline([raw(evidence=strong_evidence())]))

    def test_review_queue_shape(self):
        q = discovery_review_queue(run_discovery_pipeline(
            [raw(evidence=strong_evidence())]))
        assert q and q[0]["requires_human_review"] is True
        assert q[0]["approved"] is False
        assert q[0]["registered"] is False

    def test_review_queue_json_safe(self):
        q = discovery_review_queue(run_discovery_pipeline([raw()]))
        json.dumps(q)
        assert_secret_free(q)

    def test_normalize_provider_id(self):
        assert normalize_provider_id("  Silicon Flow!! ") == "silicon-flow"

    def test_candidate_to_dict_roundtrips(self):
        c = discover_candidates([raw(evidence=strong_evidence())])[0]
        d = c.to_dict()
        assert json.loads(json.dumps(d))["candidate_id"] == c.candidate_id
        assert d["strong_signal_count"] == 2
