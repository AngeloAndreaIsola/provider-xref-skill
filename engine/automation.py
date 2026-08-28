"""
automation.py — Approval-gated reconciliation automation (Phase 18).

This is the FIRST module in the layered architecture that is allowed to
mutate anything. The mandatory workflow is:

    finding
       ↓
    proposed action
       ↓
    explicit user approval          ← hard gate, no default, no inference
       ↓
    preconditions
       ↓
    execution
       ↓
    postcondition verification
       ↓
    reconciliation
       ↓
    resolved

The forbidden pattern is:

    detect inconsistency → silently repair it

Hard rules enforced here:
  * An action never executes without a matching, explicit `Approval`.
  * Approval is per (finding_id, action) and is single-use.
  * If a postcondition cannot be VERIFIED, the action is left UNRESOLVED —
    never reported as success.
  * Secrets are stripped from every result, log line and record.
  * Browser interaction uses the visible (headed) browser and the existing
    Phase 9 checkpoint architecture; checkpoints are surfaced, never bypassed.
  * Arbitrary provider signup is not performed here.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict

from .accounts import build_account_model
from .capability import build_capability
from .review import (
    ACTION_ACQUIRE_API_KEY,
    ACTION_ACQUIRE_LOGIN,
    ACTION_CONNECT_OMNIROUTE,
    ACTION_MANUAL_INVESTIGATION,
    ACTION_RECORD_HERMES_REFERENCE,
    ACTION_RESOLVE_IDENTITY_CONFLICT,
    ACTION_REVIEW_DUPLICATE,
    ACTION_REVIEW_ORPHAN,
    Finding,
    REVIEW_RESOLVED,
    assert_secret_free,
    build_findings,
    set_review_status,
)
from .state import load_state
from .utils import now_iso, uuid_id


# ── Outcome vocabulary ───────────────────────────────────────────────────────

OUTCOME_RESOLVED = "resolved"
OUTCOME_UNRESOLVED = "unresolved"
OUTCOME_BLOCKED = "blocked"
OUTCOME_AWAITING_APPROVAL = "awaiting_approval"
OUTCOME_AWAITING_CHECKPOINT = "awaiting_human_checkpoint"
OUTCOME_FAILED = "failed"
OUTCOME_UNVERIFIED = "unverified"

OUTCOMES = (
    OUTCOME_RESOLVED, OUTCOME_UNRESOLVED, OUTCOME_BLOCKED,
    OUTCOME_AWAITING_APPROVAL, OUTCOME_AWAITING_CHECKPOINT,
    OUTCOME_FAILED, OUTCOME_UNVERIFIED,
)

# Actions that may ever be executed by automation (with approval).
EXECUTABLE_ACTIONS = (
    ACTION_ACQUIRE_API_KEY,
    ACTION_ACQUIRE_LOGIN,
    ACTION_CONNECT_OMNIROUTE,
    ACTION_RECORD_HERMES_REFERENCE,
)

# Actions that are ALWAYS human-only — automation must refuse them.
HUMAN_ONLY_ACTIONS = (
    ACTION_REVIEW_DUPLICATE,
    ACTION_REVIEW_ORPHAN,
    ACTION_RESOLVE_IDENTITY_CONFLICT,
    ACTION_MANUAL_INVESTIGATION,
)

_SECRET_KEYS = (
    "password", "secret", "api_key", "apikey", "token", "credential",
    "value", "cookie", "session", "magic_link", "oauth_token",
)


def strip_secrets(payload):
    """Recursively REMOVE secret-bearing keys, keeping op:// references.

    The key itself is dropped (not merely blanked) so that a payload can never
    carry a forbidden key name — `engine.review.assert_secret_free` treats the
    presence of such a key as a failure regardless of its value. Dropped key
    names are recorded under `redacted_fields` so the redaction is visible.
    """
    if isinstance(payload, dict):
        out = {}
        dropped = []
        for k, v in payload.items():
            kl = str(k).lower()
            if kl in _SECRET_KEYS:
                if isinstance(v, str) and v.startswith("op://"):
                    out[f"{k}_reference"] = v      # reference is safe
                else:
                    dropped.append(str(k))
                continue
            out[k] = strip_secrets(v)
        if dropped:
            existing = out.get("redacted_fields") or []
            out["redacted_fields"] = sorted(set(existing) | set(dropped))
        return out
    if isinstance(payload, list):
        return [strip_secrets(v) for v in payload]
    return payload


# ── Approval ─────────────────────────────────────────────────────────────────

@dataclass
class Approval:
    """An explicit, single-use human approval for ONE action on ONE finding.

    There is deliberately no "approve all" and no default-true field. An
    Approval must be constructed by a human-driven caller.
    """
    finding_id: str
    action: str
    approved_by: str
    approved_at: str = ""
    scope_account_key: str | None = None
    note: str | None = None
    consumed: bool = False

    def __post_init__(self):
        if not self.approved_at:
            self.approved_at = now_iso()

    def matches(self, finding: Finding, action: str) -> bool:
        if self.consumed:
            return False
        if self.finding_id != finding.finding_id or self.action != action:
            return False
        if self.scope_account_key and self.scope_account_key != finding.account_key:
            return False
        return bool(self.approved_by)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ActionRecord:
    """The audit record of one attempted action. Secret-free."""
    action_id: str
    finding_id: str
    provider_id: str
    account_key: str
    action: str
    outcome: str
    approved_by: str | None = None
    dry_run: bool = False
    preconditions: list[dict] = field(default_factory=list)
    execution: dict = field(default_factory=dict)
    postconditions: list[dict] = field(default_factory=list)
    verified: bool = False
    reconciled: bool = False
    review_status_set: str | None = None
    checkpoint: dict | None = None
    errors: list[str] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""

    def to_dict(self) -> dict:
        return strip_secrets(asdict(self))


# ── Preconditions ────────────────────────────────────────────────────────────

def _check(name: str, ok: bool, detail: str = "") -> dict:
    return {"check": name, "ok": bool(ok), "detail": detail}


def check_preconditions(finding: Finding, action: str,
                        catalog: dict | None = None) -> list[dict]:
    """Structured preconditions. All must pass before any mutation."""
    checks: list[dict] = []

    checks.append(_check(
        "action_is_executable", action in EXECUTABLE_ACTIONS,
        f"{action} is human-only" if action in HUMAN_ONLY_ACTIONS
        else "action executable",
    ))
    checks.append(_check(
        "action_matches_finding", finding.recommended_action == action,
        f"finding proposes {finding.recommended_action}",
    ))
    checks.append(_check(
        "account_key_present", bool(finding.account_key),
        "an account key is required — never operate provider-wide",
    ))

    cap = build_capability(finding.provider_id, catalog)
    checks.append(_check(
        "provider_known", cap.source == "catalog",
        "provider must be described in the catalog",
    ))
    if action == ACTION_CONNECT_OMNIROUTE:
        checks.append(_check(
            "omniroute_supported", bool(cap.omniroute_supported),
            "catalog must declare OmniRoute support",
        ))
    if action in (ACTION_ACQUIRE_API_KEY, ACTION_ACQUIRE_LOGIN):
        checks.append(_check(
            "credential_acquisition_understood",
            cap.credential_state in ("extractable", "manual"),
            f"credential_state={cap.credential_state}",
        ))
    return checks


def preconditions_ok(checks: list[dict]) -> bool:
    return all(c["ok"] for c in checks)


# ── Execution adapters (approval already verified by the caller) ─────────────

def _headed_browser_required(provider_id: str, catalog: dict | None = None) -> bool:
    cap = build_capability(provider_id, catalog)
    return bool(cap.browser_required or cap.human_checkpoint_possible)


def _execute_connect_omniroute(finding: Finding, executor=None,
                               dry_run: bool = False) -> dict:
    """Create an OmniRoute connection for ONE account. Never bulk."""
    if dry_run:
        return {"performed": False, "dry_run": True,
                "would_connect": finding.provider_id,
                "account_key": finding.account_key}
    if executor is None:
        return {"performed": False,
                "error": "no execution adapter supplied — refusing to guess"}
    result = executor(finding)
    return strip_secrets({"performed": True, **(result or {})})


def _execute_acquire_credential(finding: Finding, action: str, executor=None,
                                dry_run: bool = False,
                                catalog: dict | None = None) -> dict:
    """Acquire a login or API key. Uses the visible browser when required.

    Human checkpoints (CAPTCHA, email/phone verification, OAuth consent) are
    surfaced by the executor and NEVER bypassed here.
    """
    headed = _headed_browser_required(finding.provider_id, catalog)
    base = {
        "action": action,
        "headed_browser_required": headed,
        "browser_headed": headed,
        "checkpoints_bypassed": False,
    }
    if dry_run:
        return {**base, "performed": False, "dry_run": True}
    if executor is None:
        return {**base, "performed": False,
                "error": "no execution adapter supplied — refusing to guess"}
    result = executor(finding) or {}
    return strip_secrets({**base, "performed": True, **result})


def _execute_record_hermes_reference(finding: Finding, executor=None,
                                     dry_run: bool = False) -> dict:
    if dry_run:
        return {"performed": False, "dry_run": True,
                "would_record": finding.account_key}
    if executor is None:
        return {"performed": False,
                "error": "no execution adapter supplied — refusing to guess"}
    return strip_secrets({"performed": True, **(executor(finding) or {})})


_EXECUTORS = {
    ACTION_CONNECT_OMNIROUTE: "_execute_connect_omniroute",
    ACTION_ACQUIRE_API_KEY: "_execute_acquire_credential",
    ACTION_ACQUIRE_LOGIN: "_execute_acquire_credential",
    ACTION_RECORD_HERMES_REFERENCE: "_execute_record_hermes_reference",
}


# ── Postcondition verification ───────────────────────────────────────────────

def verify_postconditions(
    finding: Finding,
    action: str,
    state: dict | None = None,
    omni_connections: list[dict] | None = None,
    op_items: list[dict] | None = None,
) -> list[dict]:
    """Verify the action actually took effect, via the canonical model.

    Re-runs the Phase 13 account model and inspects the SAME account. If the
    expected component is not observably present, verification FAILS.
    """
    if state is None:
        state = load_state()
    model = build_account_model(state, omni_connections or [], op_items or [])
    target = None
    for acc in model.get(finding.provider_id, []):
        if acc.account_id == finding.account_key:
            target = acc
            break

    if target is None:
        return [_check("account_still_identifiable", False,
                       "account not found after execution — cannot verify")]

    expectations = {
        ACTION_CONNECT_OMNIROUTE: ("has_omniroute", "OmniRoute connection present"),
        ACTION_ACQUIRE_API_KEY: ("has_api_key", "1Password API key reference present"),
        ACTION_ACQUIRE_LOGIN: ("has_login", "1Password login reference present"),
        ACTION_RECORD_HERMES_REFERENCE: ("has_hermes_ref", "Hermes reference present"),
    }
    checks = [_check("account_still_identifiable", True, target.account_id)]
    attr, detail = expectations.get(action, (None, ""))
    if attr is None:
        checks.append(_check("known_postcondition", False,
                             f"no postcondition defined for {action}"))
        return checks
    checks.append(_check(f"postcondition:{attr}", bool(getattr(target, attr)), detail))
    return checks


def _reconcile_after(state: dict | None = None,
                     omni_connections: list[dict] | None = None,
                     op_items: list[dict] | None = None) -> dict:
    """Read-only reconciliation after execution (Phase 12/13 canonical)."""
    from .reconcile import reconcile_all, summarize_reconciliation
    if state is None:
        state = load_state()
    recon = reconcile_all(state, omni_connections or [], op_items or [])
    return summarize_reconciliation(recon)


# ── The single entry point for mutation ──────────────────────────────────────

def execute_approved_action(
    finding: Finding,
    action: str,
    approval: Approval | None = None,
    executor=None,
    state: dict | None = None,
    omni_connections: list[dict] | None = None,
    op_items: list[dict] | None = None,
    catalog: dict | None = None,
    dry_run: bool = False,
    review_state_path=None,
) -> ActionRecord:
    """Execute ONE approved action against ONE account.

    Refuses without a matching explicit Approval. Leaves the finding
    UNRESOLVED when verification does not succeed.
    """
    record = ActionRecord(
        action_id=uuid_id("act"),
        finding_id=finding.finding_id,
        provider_id=finding.provider_id,
        account_key=finding.account_key,
        action=action,
        outcome=OUTCOME_UNRESOLVED,
        dry_run=dry_run,
        started_at=now_iso(),
    )

    # 1. Approval gate — hard, explicit, single-use.
    if approval is None or not approval.matches(finding, action):
        record.outcome = OUTCOME_AWAITING_APPROVAL
        record.errors.append("no matching explicit approval — refusing to execute")
        record.finished_at = now_iso()
        return record
    record.approved_by = approval.approved_by

    # 2. Human-only actions are never automated.
    if action in HUMAN_ONLY_ACTIONS:
        record.outcome = OUTCOME_BLOCKED
        record.errors.append(f"{action} requires human handling — automation refused")
        record.finished_at = now_iso()
        return record

    # 3. Preconditions.
    record.preconditions = check_preconditions(finding, action, catalog)
    if not preconditions_ok(record.preconditions):
        record.outcome = OUTCOME_BLOCKED
        record.errors.append("preconditions failed — no mutation attempted")
        record.finished_at = now_iso()
        return record

    approval.consumed = True   # single-use

    # 4. Execution (with failure handling).
    try:
        if action == ACTION_CONNECT_OMNIROUTE:
            exec_result = _execute_connect_omniroute(finding, executor, dry_run)
        elif action in (ACTION_ACQUIRE_API_KEY, ACTION_ACQUIRE_LOGIN):
            exec_result = _execute_acquire_credential(
                finding, action, executor, dry_run, catalog)
        elif action == ACTION_RECORD_HERMES_REFERENCE:
            exec_result = _execute_record_hermes_reference(finding, executor, dry_run)
        else:
            exec_result = {"performed": False, "error": f"unsupported action {action}"}
    except Exception as exc:
        record.execution = {"performed": False, "error": f"{type(exc).__name__}"}
        record.outcome = OUTCOME_FAILED
        record.errors.append(f"execution raised {type(exc).__name__}")
        record.finished_at = now_iso()
        return record

    record.execution = strip_secrets(exec_result)

    # A surfaced human checkpoint is not a failure and not a success.
    if exec_result.get("human_checkpoint_required") or exec_result.get("checkpoint"):
        record.checkpoint = strip_secrets(
            exec_result.get("checkpoint") or {"checkpoint_type": "manual_verification"})
        record.outcome = OUTCOME_AWAITING_CHECKPOINT
        record.finished_at = now_iso()
        return record

    if dry_run:
        record.outcome = OUTCOME_UNRESOLVED
        record.errors.append("dry run — nothing executed")
        record.finished_at = now_iso()
        return record

    if not exec_result.get("performed"):
        record.outcome = OUTCOME_FAILED
        record.errors.append(exec_result.get("error", "execution did not run"))
        record.finished_at = now_iso()
        return record

    # 5. Postcondition verification — the gate on claiming success.
    record.postconditions = verify_postconditions(
        finding, action, state, omni_connections, op_items)
    record.verified = all(c["ok"] for c in record.postconditions)

    # 6. Reconciliation afterwards (read-only).
    try:
        record.execution["reconciliation_summary"] = _reconcile_after(
            state, omni_connections, op_items)
        record.reconciled = True
    except Exception:
        record.reconciled = False

    # 7. Resolve ONLY when verified.
    if record.verified and record.reconciled:
        record.outcome = OUTCOME_RESOLVED
        try:
            set_review_status(finding.finding_id, REVIEW_RESOLVED,
                              note=f"resolved by {action} (verified)",
                              path=review_state_path)
            record.review_status_set = REVIEW_RESOLVED
        except Exception:
            record.errors.append("could not persist review status")
    else:
        record.outcome = OUTCOME_UNVERIFIED
        record.errors.append(
            "postcondition verification did not succeed — left unresolved")

    record.finished_at = now_iso()
    assert_secret_free(record.to_dict())
    return record


# ── Planning helper (no mutation) ────────────────────────────────────────────

def plan_remediation(
    state: dict | None = None,
    omni_connections: list[dict] | None = None,
    op_items: list[dict] | None = None,
    catalog: dict | None = None,
) -> dict:
    """List what COULD be remediated, and what each needs. Executes nothing."""
    if state is None:
        state = load_state()
    model = build_account_model(state, omni_connections or [], op_items or [])
    findings = build_findings(model=model, catalog=catalog)
    items = []
    for f in findings:
        action = f.recommended_action
        checks = check_preconditions(f, action, catalog)
        items.append({
            "finding_id": f.finding_id,
            "provider_id": f.provider_id,
            "account_key": f.account_key,
            "category": f.category,
            "proposed_action": action,
            "executable": action in EXECUTABLE_ACTIONS,
            "human_only": action in HUMAN_ONLY_ACTIONS,
            "preconditions": checks,
            "preconditions_ok": preconditions_ok(checks),
            "approval_required": True,
            "approved": False,
        })
    return {
        "read_only": True,
        "executed_anything": False,
        "total": len(items),
        "items": items,
    }
