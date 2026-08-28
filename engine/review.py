"""
review.py — Read-only inconsistency / review system (Phase 14).

Phase 12 gave us three-system reconciliation, Phase 13 gave us the
multi-account identity model. Phase 14 turns those into a normalized,
human- and agent-readable REVIEW QUEUE.

Strictly read-only with respect to providers, 1Password, OmniRoute and
Hermes `provider_state.json`. The ONLY thing this module may persist is
review STATUS metadata, and that lives in its own file
(`data/review_state.json`) — never in `provider_state.json`.

Layering (no duplicated matching logic):

    catalog → capability → reconcile → accounts → review(this module)

`review.py` consumes `engine.accounts.build_account_model()` output and
`engine.capability` classifications. It never re-implements identity
matching or reconciliation.

Findings are secret-free: only `op://...` references, item ids, titles,
emails and connection ids appear — never credential values.

Every recommended action is PROPOSED ONLY. Phase 14 executes nothing.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from pathlib import Path

from .accounts import build_account_model, AccountView
from .capability import build_capability
from .reconcile import (
    STATE_COMPLETE,
    STATE_MISSING_LOGIN,
    STATE_MISSING_API_KEY,
    STATE_MISSING_OMNIROUTE,
    STATE_MISSING_HERMES,
    STATE_DUPLICATE,
    STATE_ORPHANED,
    STATE_CONFLICTING_IDENTITY,
    STATE_UNKNOWN,
)
from .utils import load_json, save_json_atomic, now_iso, SKILL_ROOT


# ── Vocabulary ───────────────────────────────────────────────────────────────

CATEGORY_MISSING_LOGIN = "missing_login"
CATEGORY_MISSING_API_KEY = "missing_api_key"
CATEGORY_MISSING_OMNIROUTE = "missing_omniroute_connection"
CATEGORY_MISSING_HERMES = "missing_hermes_reference"
CATEGORY_DUPLICATE = "duplicate"
CATEGORY_ORPHANED = "orphaned"
CATEGORY_CONFLICTING_IDENTITY = "conflicting_identity"
CATEGORY_UNKNOWN = "unknown"

CATEGORIES = (
    CATEGORY_MISSING_LOGIN,
    CATEGORY_MISSING_API_KEY,
    CATEGORY_MISSING_OMNIROUTE,
    CATEGORY_MISSING_HERMES,
    CATEGORY_DUPLICATE,
    CATEGORY_ORPHANED,
    CATEGORY_CONFLICTING_IDENTITY,
    CATEGORY_UNKNOWN,
)

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
SEVERITY_INFO = "info"

SEVERITIES = (
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM,
    SEVERITY_LOW, SEVERITY_INFO,
)

_SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITIES)}

REVIEW_OPEN = "open"
REVIEW_ACKNOWLEDGED = "acknowledged"
REVIEW_RESOLVED = "resolved"
REVIEW_IGNORED = "ignored"

REVIEW_STATUSES = (REVIEW_OPEN, REVIEW_ACKNOWLEDGED, REVIEW_RESOLVED, REVIEW_IGNORED)

# Proposed action vocabulary (never executed in Phase 14).
ACTION_ACQUIRE_LOGIN = "acquire_login"
ACTION_ACQUIRE_API_KEY = "acquire_api_key"
ACTION_CONNECT_OMNIROUTE = "connect_omniroute"
ACTION_RECORD_HERMES_REFERENCE = "record_hermes_reference"
ACTION_REVIEW_DUPLICATE = "review_duplicate"
ACTION_REVIEW_ORPHAN = "review_orphan"
ACTION_RESOLVE_IDENTITY_CONFLICT = "resolve_identity_conflict"
ACTION_MANUAL_INVESTIGATION = "manual_investigation"

# reconciliation state → (category, severity, proposed action)
_STATE_MAP: dict[str, tuple[str, str, str]] = {
    STATE_MISSING_LOGIN: (CATEGORY_MISSING_LOGIN, SEVERITY_MEDIUM, ACTION_ACQUIRE_LOGIN),
    STATE_MISSING_API_KEY: (CATEGORY_MISSING_API_KEY, SEVERITY_HIGH, ACTION_ACQUIRE_API_KEY),
    STATE_MISSING_OMNIROUTE: (CATEGORY_MISSING_OMNIROUTE, SEVERITY_HIGH, ACTION_CONNECT_OMNIROUTE),
    STATE_MISSING_HERMES: (CATEGORY_MISSING_HERMES, SEVERITY_LOW, ACTION_RECORD_HERMES_REFERENCE),
    STATE_DUPLICATE: (CATEGORY_DUPLICATE, SEVERITY_MEDIUM, ACTION_REVIEW_DUPLICATE),
    STATE_ORPHANED: (CATEGORY_ORPHANED, SEVERITY_MEDIUM, ACTION_REVIEW_ORPHAN),
    STATE_CONFLICTING_IDENTITY: (
        CATEGORY_CONFLICTING_IDENTITY, SEVERITY_CRITICAL, ACTION_RESOLVE_IDENTITY_CONFLICT,
    ),
    STATE_UNKNOWN: (CATEGORY_UNKNOWN, SEVERITY_LOW, ACTION_MANUAL_INVESTIGATION),
}

REVIEW_STATE_FILE = SKILL_ROOT / "data" / "review_state.json"

# Keys that must never appear in a finding payload.
_FORBIDDEN_KEYS = (
    "password", "secret", "api_key_value", "value", "token",
    "credential_value", "cookie", "session", "magic_link",
)


# ── Finding model ────────────────────────────────────────────────────────────

@dataclass
class Finding:
    """One normalized, secret-free inconsistency.

    `recommended_action` is PROPOSED ONLY. `automation_safe` says whether the
    action would *theoretically* be safe to automate given the provider's
    Phase 11 capability/policy classification — it is NOT an approval.
    """
    finding_id: str
    severity: str
    category: str
    provider_id: str
    account_key: str
    identity: dict = field(default_factory=dict)
    systems: list[str] = field(default_factory=list)
    reconciliation_state: str = STATE_UNKNOWN
    evidence: dict = field(default_factory=dict)
    recommended_action: str = ACTION_MANUAL_INVESTIGATION
    action_status: str = "proposed"
    review_status: str = REVIEW_OPEN
    automation_safe: bool = False
    requires_human_approval: bool = True
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def finding_id(provider_id: str, account_key: str, category: str) -> str:
    """Stable, deterministic finding id.

    Derived only from non-secret structural identifiers so the same
    inconsistency always yields the same id across runs.
    """
    basis = f"{provider_id}|{account_key}|{category}"
    digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()[:12]
    return f"finding_{category}_{digest}"


def severity_for(category: str, reconciliation_state: str = "") -> str:
    """Deterministic severity for a category."""
    for state, (cat, sev, _) in _STATE_MAP.items():
        if cat == category:
            return sev
    return SEVERITY_LOW


def proposed_action_for(category: str) -> str:
    """The PROPOSED (never executed) action for a category."""
    for state, (cat, _, action) in _STATE_MAP.items():
        if cat == category:
            return action
    return ACTION_MANUAL_INVESTIGATION


# ── Evidence / identity extraction (secret-free) ─────────────────────────────

def _safe_ref(ref: dict | None) -> dict | None:
    """Keep only reference metadata from a credential ref. Never a value."""
    if not ref:
        return None
    out = {
        "item_id": ref.get("item_id"),
        "title": ref.get("title") or ref.get("item_title"),
        "reference": ref.get("reference"),   # op://... is acceptable
        "vault": ref.get("vault"),
        "field": ref.get("field"),
    }
    return {k: v for k, v in out.items() if v is not None}


def _systems_for(acc: AccountView) -> list[str]:
    """Which systems hold evidence for this account (deterministic order)."""
    systems = []
    if acc.has_login or acc.has_api_key:
        systems.append("1password")
    if acc.has_omniroute:
        systems.append("omniroute")
    if acc.has_hermes_ref:
        systems.append("hermes")
    return systems


def _identity_metadata(acc: AccountView) -> dict:
    out = {
        "identity_id": acc.identity_id,
        "identity_email": acc.identity_email,
        "identity_type": acc.identity_type,
        "ownership_status": acc.ownership_status,
    }
    return {k: v for k, v in out.items() if v is not None}


def _evidence_for(acc: AccountView) -> dict:
    return {
        "has_login": acc.has_login,
        "has_api_key": acc.has_api_key,
        "has_omniroute": acc.has_omniroute,
        "has_hermes_reference": acc.has_hermes_ref,
        "login_ref": _safe_ref(acc.login_ref),
        "api_key_ref": _safe_ref(acc.api_key_ref),
        "omniroute_connection_id": acc.omniroute_connection_id,
        "hermes_account_id": acc.hermes_account_id,
        "issues": sorted(set(acc.issues)),
    }


def _automation_safe(provider_id: str, category: str, catalog: dict | None = None) -> bool:
    """Would automating this action be *theoretically* safe?

    Reuses the Phase 11 capability/policy model. Ambiguous categories are
    never marked safe — ambiguity must not collapse into success.
    """
    if category in (CATEGORY_DUPLICATE, CATEGORY_ORPHANED,
                    CATEGORY_CONFLICTING_IDENTITY, CATEGORY_UNKNOWN):
        return False
    try:
        cap = build_capability(provider_id, catalog)
    except Exception:
        return False
    return bool(cap.is_ready_for_automation())


# ── Finding construction ─────────────────────────────────────────────────────

def finding_from_account(acc: AccountView, catalog: dict | None = None) -> Finding | None:
    """Convert one AccountView into a Finding, or None when complete.

    Never fabricates a success: an unrecognized state becomes `unknown`.
    """
    state = acc.reconciliation_state
    if state == STATE_COMPLETE:
        return None
    category, severity, action = _STATE_MAP.get(
        state, (CATEGORY_UNKNOWN, SEVERITY_LOW, ACTION_MANUAL_INVESTIGATION),
    )
    notes = []
    if state not in _STATE_MAP:
        notes.append(f"unrecognized_reconciliation_state:{state}")
    safe = _automation_safe(acc.provider_id, category, catalog)
    return Finding(
        finding_id=finding_id(acc.provider_id, acc.account_id, category),
        severity=severity,
        category=category,
        provider_id=acc.provider_id,
        account_key=acc.account_id,
        identity=_identity_metadata(acc),
        systems=_systems_for(acc),
        reconciliation_state=state,
        evidence=_evidence_for(acc),
        recommended_action=action,
        action_status="proposed",
        review_status=REVIEW_OPEN,
        automation_safe=safe,
        requires_human_approval=True,
        notes=notes,
    )


def build_findings(
    model: dict[str, list[AccountView]] | None = None,
    state: dict | None = None,
    omni_connections: list[dict] | None = None,
    op_items: list[dict] | None = None,
    catalog: dict | None = None,
) -> list[Finding]:
    """Build the deduplicated, deterministically-sorted finding list.

    Read-only. Reuses the Phase 13 account model (which itself reuses the
    Phase 12 reconciliation) — no parallel matching logic here.
    """
    if model is None:
        model = build_account_model(state, omni_connections, op_items)

    by_id: dict[str, Finding] = {}
    for pid in sorted(model):
        for acc in model[pid]:
            f = finding_from_account(acc, catalog)
            if f is None:
                continue
            existing = by_id.get(f.finding_id)
            if existing is None:
                by_id[f.finding_id] = f
            else:
                # Deduplicate: merge evidence/notes rather than emit twice.
                for note in f.notes:
                    if note not in existing.notes:
                        existing.notes.append(note)
                merged = sorted(set(existing.evidence.get("issues", []))
                                | set(f.evidence.get("issues", [])))
                existing.evidence["issues"] = merged
    return sort_findings(list(by_id.values()))


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Deterministic ordering: severity desc, then provider, account, id."""
    return sorted(
        findings,
        key=lambda f: (
            _SEVERITY_ORDER.get(f.severity, len(SEVERITIES)),
            f.provider_id,
            f.account_key,
            f.category,
            f.finding_id,
        ),
    )


# ── Review status persistence (SEPARATE from provider_state.json) ────────────

def _empty_review_state() -> dict:
    return {"schema_version": 1, "updated_at": None, "findings": {}}


def load_review_state(path: Path | str | None = None) -> dict:
    """Load review STATUS metadata. Never touches provider_state.json."""
    p = Path(path) if path else REVIEW_STATE_FILE
    data = load_json(p, default=None)
    if not isinstance(data, dict) or "findings" not in data:
        return _empty_review_state()
    return data


def save_review_state(data: dict, path: Path | str | None = None) -> None:
    p = Path(path) if path else REVIEW_STATE_FILE
    p.parent.mkdir(parents=True, exist_ok=True)
    data = dict(data)
    data["updated_at"] = now_iso()
    save_json_atomic(p, data)


def set_review_status(
    fid: str,
    status: str,
    note: str | None = None,
    path: Path | str | None = None,
) -> dict:
    """Record review status for a finding.

    This is METADATA ONLY. It mutates NOTHING in 1Password, OmniRoute,
    Hermes provider state, or at the provider. Marking `resolved` does not
    repair anything.
    """
    if status not in REVIEW_STATUSES:
        raise ValueError(f"invalid review status: {status!r}")
    data = load_review_state(path)
    entry = data["findings"].get(fid, {})
    entry["status"] = status
    entry["updated_at"] = now_iso()
    if note:
        notes = entry.setdefault("notes", [])
        if note not in notes:
            notes.append(note)
    data["findings"][fid] = entry
    save_review_state(data, path)
    return entry


def get_review_status(fid: str, path: Path | str | None = None) -> str:
    data = load_review_state(path)
    entry = data["findings"].get(fid) or {}
    return entry.get("status", REVIEW_OPEN)


def apply_review_state(findings: list[Finding], path: Path | str | None = None) -> list[Finding]:
    """Overlay persisted review status onto findings (in place)."""
    data = load_review_state(path)
    stored = data.get("findings", {})
    for f in findings:
        entry = stored.get(f.finding_id)
        if entry:
            f.review_status = entry.get("status", REVIEW_OPEN)
            for n in entry.get("notes", []):
                if n not in f.notes:
                    f.notes.append(n)
    return findings


# ── Public entry point ───────────────────────────────────────────────────────

def get_review_queue(
    state: dict | None = None,
    omni_connections: list[dict] | None = None,
    op_items: list[dict] | None = None,
    catalog: dict | None = None,
    review_state_path: Path | str | None = None,
    include_statuses: tuple[str, ...] | None = None,
) -> dict:
    """The Phase 14 review queue: secret-free, deterministic, read-only.

    Suitable for both humans and future agents. Contains no credential
    values and executes no actions.
    """
    findings = build_findings(
        state=state, omni_connections=omni_connections,
        op_items=op_items, catalog=catalog,
    )
    apply_review_state(findings, review_state_path)
    if include_statuses is not None:
        findings = [f for f in findings if f.review_status in include_statuses]
    findings = sort_findings(findings)

    severity_counts: dict[str, int] = {s: 0 for s in SEVERITIES}
    category_counts: dict[str, int] = {c: 0 for c in CATEGORIES}
    status_counts: dict[str, int] = {s: 0 for s in REVIEW_STATUSES}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        category_counts[f.category] = category_counts.get(f.category, 0) + 1
        status_counts[f.review_status] = status_counts.get(f.review_status, 0) + 1

    return {
        "schema_version": 1,
        "read_only": True,
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "category_counts": category_counts,
        "review_status_counts": status_counts,
        "findings": [f.to_dict() for f in findings],
    }


def proposed_actions(queue: dict) -> list[dict]:
    """Extract the proposed actions from a queue. Nothing is executed."""
    out = []
    for f in queue.get("findings", []):
        out.append({
            "finding_id": f["finding_id"],
            "provider_id": f["provider_id"],
            "account_key": f["account_key"],
            "category": f["category"],
            "action": f["recommended_action"],
            "status": "proposed",
            "requires_human_approval": True,
            "automation_safe": f["automation_safe"],
        })
    return out


# ── Secret-safety self-check (used by tests and the CLI) ─────────────────────

def assert_secret_free(payload) -> None:
    """Raise AssertionError if a payload contains a forbidden secret-ish key.

    `op://` references and item ids are explicitly allowed.
    """
    def walk(node, trail=""):
        if isinstance(node, dict):
            for k, v in node.items():
                kl = str(k).lower()
                if kl in _FORBIDDEN_KEYS:
                    raise AssertionError(f"forbidden key {trail}.{k} in review payload")
                walk(v, f"{trail}.{k}")
        elif isinstance(node, (list, tuple)):
            for i, v in enumerate(node):
                walk(v, f"{trail}[{i}]")
    walk(payload)
