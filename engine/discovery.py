"""
discovery.py — Provider discovery pipeline (Phase 19).

Pipeline:

    provider discovery
           ↓
    candidate provider
           ↓
    catalog entry (draft — never merged automatically)
           ↓
    policy classification
           ↓
    capability detection
           ↓
    registration feasibility
           ↓
    human review
           ↓
    approved provider

Hard scope restrictions for this phase:
  * NO periodic discovery and NO scheduled scans (there is deliberately no
    scheduler hook, no cron entry, no timer).
  * NO automatic signup and NO automatic account creation.
  * NO automatic provider activation: a candidate is never written into
    `provider_catalog.json` by this module.

Evidence discipline: a candidate stays `unknown` until there is sufficient
evidence. The existence of a signup page is NOT evidence of support — it is
one weak signal. `mark_supported`-style shortcuts do not exist here.

Discovery, classification, approval and registration are strictly separate:
  discover_candidates()      → candidates (no classification)
  classify_candidate()       → classification (no approval)
  request_approval()/approve → approval record (no registration)
  registration is Phase 15/18 territory and requires the candidate to have
  been promoted into the catalog by a human first.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from urllib.parse import urlparse

from .capability import (
    POLICY_UNKNOWN,
    SUPPORT_UNKNOWN,
)
from .catalog import load_catalog
from .utils import load_json, now_iso, save_json_atomic, SKILL_ROOT


# ── Vocabulary ───────────────────────────────────────────────────────────────

STATE_CANDIDATE = "candidate"          # seen, nothing verified
STATE_CLASSIFIED = "classified"        # policy + capability assessed
STATE_FEASIBLE = "feasible"            # registration looks possible
STATE_INFEASIBLE = "infeasible"        # cannot register with current tooling
STATE_AWAITING_REVIEW = "awaiting_review"
STATE_APPROVED = "approved"            # human approved for catalog promotion
STATE_REJECTED = "rejected"
STATE_UNKNOWN = "unknown"

DISCOVERY_STATES = (
    STATE_CANDIDATE, STATE_CLASSIFIED, STATE_FEASIBLE, STATE_INFEASIBLE,
    STATE_AWAITING_REVIEW, STATE_APPROVED, STATE_REJECTED, STATE_UNKNOWN,
)

# Evidence signal kinds, weakest first.
SIGNAL_SIGNUP_PAGE = "signup_page_exists"
SIGNAL_DOCS_PAGE = "api_docs_exist"
SIGNAL_FREE_TIER_CLAIM = "free_tier_claimed"
SIGNAL_AUTH_TYPE_DOCUMENTED = "auth_type_documented"
SIGNAL_KEY_FORMAT_KNOWN = "credential_format_known"
SIGNAL_OMNIROUTE_SUPPORT = "omniroute_support_documented"
SIGNAL_TOS_REVIEWED = "tos_reviewed"

SIGNALS = (
    SIGNAL_SIGNUP_PAGE, SIGNAL_DOCS_PAGE, SIGNAL_FREE_TIER_CLAIM,
    SIGNAL_AUTH_TYPE_DOCUMENTED, SIGNAL_KEY_FORMAT_KNOWN,
    SIGNAL_OMNIROUTE_SUPPORT, SIGNAL_TOS_REVIEWED,
)

# Signals that are meaningful enough to justify leaving `unknown`.
# A signup page alone is deliberately NOT sufficient.
_STRONG_SIGNALS = (
    SIGNAL_AUTH_TYPE_DOCUMENTED,
    SIGNAL_KEY_FORMAT_KNOWN,
    SIGNAL_OMNIROUTE_SUPPORT,
    SIGNAL_TOS_REVIEWED,
)

MIN_STRONG_SIGNALS_TO_CLASSIFY = 2

DISCOVERY_FILE = SKILL_ROOT / "data" / "discovery.json"

_ID_RE = re.compile(r"[^a-z0-9]+")


# ── Data model ───────────────────────────────────────────────────────────────

@dataclass
class Evidence:
    """One piece of discovery evidence. Never a credential."""
    signal: str
    source: str                    # URL or description
    observed_at: str = ""
    detail: str = ""

    def __post_init__(self):
        if not self.observed_at:
            self.observed_at = now_iso()

    @property
    def is_strong(self) -> bool:
        return self.signal in _STRONG_SIGNALS

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CandidateProvider:
    """A discovered provider candidate. NOT a catalog provider."""
    candidate_id: str
    suggested_provider_id: str
    name: str
    homepage: str | None = None
    signup_url: str | None = None
    docs_url: str | None = None
    source: str = "manual"
    state: str = STATE_CANDIDATE
    already_in_catalog: bool = False
    evidence: list[Evidence] = field(default_factory=list)
    policy_classification: str = POLICY_UNKNOWN
    support_classification: str = SUPPORT_UNKNOWN
    feasibility: str = STATE_UNKNOWN
    feasibility_reasons: list[str] = field(default_factory=list)
    auth_type: str | None = None
    requires_human_review: bool = True
    approved_by: str | None = None
    approved_at: str | None = None
    registered: bool = False          # always False in Phase 19
    catalog_promoted: bool = False    # always False here — humans promote
    notes: list[str] = field(default_factory=list)
    discovered_at: str = ""

    def __post_init__(self):
        if not self.discovered_at:
            self.discovered_at = now_iso()

    @property
    def strong_signal_count(self) -> int:
        return sum(1 for e in self.evidence if e.is_strong)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["evidence"] = [e.to_dict() for e in self.evidence]
        d["strong_signal_count"] = self.strong_signal_count
        return d


def candidate_id(name: str, homepage: str | None = None) -> str:
    """Deterministic candidate id from stable, non-secret attributes."""
    host = ""
    if homepage:
        host = (urlparse(homepage).netloc or "").lower()
    basis = f"{normalize_provider_id(name)}|{host}"
    return f"cand_{hashlib.sha256(basis.encode()).hexdigest()[:12]}"


def normalize_provider_id(name: str) -> str:
    """Suggest a catalog-style provider id. Suggestion only — never applied."""
    return _ID_RE.sub("-", (name or "").strip().lower()).strip("-")


# ── 1. Discovery ─────────────────────────────────────────────────────────────

def make_candidate(
    name: str,
    homepage: str | None = None,
    signup_url: str | None = None,
    docs_url: str | None = None,
    source: str = "manual",
    catalog: dict | None = None,
) -> CandidateProvider:
    """Create a candidate. Performs NO classification and NO registration."""
    if catalog is None:
        catalog = load_catalog()
    pid = normalize_provider_id(name)
    known = {p["id"] for p in catalog.get("providers", [])}
    cand = CandidateProvider(
        candidate_id=candidate_id(name, homepage),
        suggested_provider_id=pid,
        name=name,
        homepage=homepage,
        signup_url=signup_url,
        docs_url=docs_url,
        source=source,
        already_in_catalog=pid in known,
    )
    # A signup page is recorded as a WEAK signal only.
    if signup_url:
        cand.evidence.append(Evidence(
            SIGNAL_SIGNUP_PAGE, signup_url,
            detail="signup page exists — weak signal, not evidence of support"))
    if docs_url:
        cand.evidence.append(Evidence(SIGNAL_DOCS_PAGE, docs_url))
    return cand


def discover_candidates(
    raw_candidates: list[dict] | None = None,
    catalog: dict | None = None,
) -> list[CandidateProvider]:
    """Turn raw observations into candidates. Deterministic, no side effects.

    `raw_candidates` is supplied by the caller (a human, a research pass, an
    import file). There is intentionally NO built-in scanner and NO scheduler:
    periodic discovery is out of scope for this phase.
    """
    if catalog is None:
        catalog = load_catalog()
    out: list[CandidateProvider] = []
    seen: set[str] = set()
    for raw in (raw_candidates or []):
        if not isinstance(raw, dict) or not raw.get("name"):
            continue
        cand = make_candidate(
            name=raw["name"],
            homepage=raw.get("homepage"),
            signup_url=raw.get("signup_url"),
            docs_url=raw.get("docs_url"),
            source=raw.get("source", "manual"),
            catalog=catalog,
        )
        if cand.candidate_id in seen:
            continue
        seen.add(cand.candidate_id)
        for ev in raw.get("evidence", []) or []:
            if isinstance(ev, dict) and ev.get("signal") in SIGNALS:
                cand.evidence.append(Evidence(
                    signal=ev["signal"],
                    source=ev.get("source", ""),
                    detail=ev.get("detail", ""),
                ))
        out.append(cand)
    return sorted(out, key=lambda c: (c.suggested_provider_id, c.candidate_id))


# ── 2. Classification (separate from discovery) ─────────────────────────────

def classify_candidate(cand: CandidateProvider,
                       catalog: dict | None = None) -> CandidateProvider:
    """Assess policy + capability + feasibility from EVIDENCE only.

    Insufficient evidence ⇒ everything stays `unknown` and the state remains
    `candidate`. A signup page never promotes a candidate.
    """
    signals = {e.signal for e in cand.evidence}

    # Policy: only an actual ToS review can move policy off unknown, and even
    # then only to "restricted" pending human confirmation.
    if SIGNAL_TOS_REVIEWED in signals:
        cand.policy_classification = "restricted"
        cand.notes.append("ToS reviewed — human confirmation still required")
    else:
        cand.policy_classification = POLICY_UNKNOWN
        cand.notes.append("policy unknown — ToS not reviewed")

    # Capability: needs documented auth AND a known credential format.
    if SIGNAL_AUTH_TYPE_DOCUMENTED in signals and SIGNAL_KEY_FORMAT_KNOWN in signals:
        cand.support_classification = "partial"
        cand.auth_type = cand.auth_type or "api_key"
    else:
        cand.support_classification = SUPPORT_UNKNOWN

    # Feasibility.
    reasons: list[str] = []
    if cand.already_in_catalog:
        reasons.append("already present in catalog — no discovery action needed")
    if SIGNAL_AUTH_TYPE_DOCUMENTED not in signals:
        reasons.append("auth type not documented")
    if SIGNAL_KEY_FORMAT_KNOWN not in signals:
        reasons.append("credential format unknown — extraction rules impossible")
    if SIGNAL_OMNIROUTE_SUPPORT not in signals:
        reasons.append("OmniRoute support undocumented")
    cand.feasibility_reasons = reasons

    strong = cand.strong_signal_count
    if strong < MIN_STRONG_SIGNALS_TO_CLASSIFY:
        cand.state = STATE_CANDIDATE
        cand.feasibility = STATE_UNKNOWN
        cand.notes.append(
            f"insufficient evidence ({strong} strong signal(s)) — remains unknown")
        return cand

    cand.state = STATE_CLASSIFIED
    cand.feasibility = STATE_INFEASIBLE if reasons else STATE_FEASIBLE
    return cand


def classify_all(candidates: list[CandidateProvider],
                 catalog: dict | None = None) -> list[CandidateProvider]:
    return [classify_candidate(c, catalog) for c in candidates]


# ── 3. Human review (separate from classification) ──────────────────────────

def request_review(cand: CandidateProvider) -> CandidateProvider:
    """Move a classified candidate into the human review queue."""
    if cand.state == STATE_CLASSIFIED:
        cand.state = STATE_AWAITING_REVIEW
    cand.requires_human_review = True
    return cand


def approve_candidate(cand: CandidateProvider, approved_by: str,
                      note: str | None = None) -> CandidateProvider:
    """Record an explicit human approval.

    Approval means "a human may now write a catalog entry" — it does NOT
    promote the candidate, register an account or activate a provider.
    """
    if not approved_by:
        raise ValueError("approved_by is required — approval must be explicit")
    if cand.state not in (STATE_CLASSIFIED, STATE_AWAITING_REVIEW):
        raise ValueError(
            f"cannot approve a candidate in state {cand.state!r}: classify first")
    cand.state = STATE_APPROVED
    cand.approved_by = approved_by
    cand.approved_at = now_iso()
    if note:
        cand.notes.append(note)
    # Explicitly unchanged:
    cand.registered = False
    cand.catalog_promoted = False
    return cand


def reject_candidate(cand: CandidateProvider, rejected_by: str,
                     reason: str = "") -> CandidateProvider:
    if not rejected_by:
        raise ValueError("rejected_by is required")
    cand.state = STATE_REJECTED
    if reason:
        cand.notes.append(f"rejected: {reason}")
    return cand


def draft_catalog_entry(cand: CandidateProvider) -> dict:
    """Produce a DRAFT catalog entry for human review.

    Returned as data only. This function never writes provider_catalog.json.
    Unknown fields stay `unknown` rather than being guessed.
    """
    return {
        "_draft": True,
        "_requires_human_review": True,
        "_approved_by": cand.approved_by,
        "id": cand.suggested_provider_id,
        "name": cand.name,
        "category": "llm",
        "auth_type": cand.auth_type or "unknown",
        "signup_url": cand.signup_url or "",
        "login_url": "",
        "free_tier": {"enabled": False, "quota": "", "type": "none"},
        "identity_requirements": [],
        "omniroute_support": {"supported": False, "type": "unknown"},
        "policy": {
            "multiple_accounts": "unknown",
            "duplicate_account_policy": "unknown",
            "automation_allowed": "unknown",
            "third_party_proxy_allowed": "unknown",
            "phone_reuse_allowed": "unknown",
        },
        "signup_difficulty": "unknown",
        "verification_requirements": [],
        "tos_notes": {"personal_use_only": False, "proxy_clause": False,
                      "multi_account_clause": False},
        "metadata": {"discovered_via": cand.source,
                     "candidate_id": cand.candidate_id},
    }


# ── Persistence (candidates only; never the catalog) ────────────────────────

def load_discovery_state(path: Path | str | None = None) -> dict:
    p = Path(path) if path else DISCOVERY_FILE
    data = load_json(p, default=None)
    if not isinstance(data, dict) or "candidates" not in data:
        return {"schema_version": 1, "updated_at": None, "candidates": {}}
    return data


def save_discovery_state(candidates: list[CandidateProvider],
                         path: Path | str | None = None) -> dict:
    """Persist candidates to their OWN file (never provider_catalog.json)."""
    p = Path(path) if path else DISCOVERY_FILE
    p.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "schema_version": 1,
        "updated_at": now_iso(),
        "periodic_discovery_enabled": False,
        "candidates": {c.candidate_id: c.to_dict() for c in candidates},
    }
    save_json_atomic(p, data)
    return data


# ── Pipeline / reporting ────────────────────────────────────────────────────

def run_discovery_pipeline(
    raw_candidates: list[dict] | None = None,
    catalog: dict | None = None,
) -> dict:
    """Run discovery → classification → review-queueing. Registers nothing."""
    candidates = classify_all(discover_candidates(raw_candidates, catalog), catalog)
    for c in candidates:
        request_review(c)
    counts: dict[str, int] = {s: 0 for s in DISCOVERY_STATES}
    for c in candidates:
        counts[c.state] = counts.get(c.state, 0) + 1
    return {
        "schema_version": 1,
        "periodic_discovery_enabled": False,
        "scheduled_scans": False,
        "automatic_signup": False,
        "automatic_activation": False,
        "registered_anything": False,
        "catalog_modified": False,
        "state_counts": counts,
        "candidates": [c.to_dict() for c in candidates],
    }


def discovery_review_queue(pipeline_result: dict) -> list[dict]:
    """The human-review view of discovery. Approval is not implied."""
    out = []
    for c in pipeline_result.get("candidates", []):
        out.append({
            "candidate_id": c["candidate_id"],
            "name": c["name"],
            "suggested_provider_id": c["suggested_provider_id"],
            "state": c["state"],
            "policy_classification": c["policy_classification"],
            "support_classification": c["support_classification"],
            "feasibility": c["feasibility"],
            "feasibility_reasons": c["feasibility_reasons"],
            "strong_signal_count": c["strong_signal_count"],
            "already_in_catalog": c["already_in_catalog"],
            "requires_human_review": True,
            "approved": c["state"] == STATE_APPROVED,
            "registered": False,
        })
    return out
