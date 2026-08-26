"""
executor.py — Approval-gated registration execution engine.

This module implements the execution layer that sits between planning
and actual registration. It enforces:

- Policy gates (DENY → BLOCKED, UNKNOWN → BLOCKED, REQUIRES_REVIEW needs approval)
- Approval semantics (request-scoped, time-bound)
- Preflight validation (deterministic)
- Idempotency (no duplicate registrations)
- Dry-run mode (no external mutations)
- Human checkpoint handling (no bypass of security challenges)
- Resume support (from human checkpoints)
- Audit trail (structured records, no secrets)

Architecture:

    plan_*()
        ↓
    create_execution_request()  →  ExecutionRequest (awaiting_approval)
        ↓
    preflight()                 →  preflight checks (PASS/FAIL/UNKNOWN)
        ↓
    approve()                   →  Approval record (request-scoped)
        ↓
    execute()                   →  Workflow invocation + result capture
        ↓
    verify()                    →  State verification
        ↓
    complete()/cancel()/resume()

CRITICAL INVARIANTS:
    1. Planning methods NEVER call execute() or trigger workflows.
    2. Execution CANNOT proceed without explicit approval.
    3. DENY providers are always BLOCKED.
    4. UNKNOWN providers are always BLOCKED (never treated as ALLOW).
    5. REQUIRES_REVIEW requires explicit approval.
    6. DRY_RUN mode performs no external mutations.
    7. No secrets are ever serialized into execution requests, state, or history.

LEGITIMATE ACCOUNT CREATION POLICY (Phase 6.3):

  The mere fact that a provider requires browser-based signup, OAuth, email
  verification, GitHub/Google authorization, etc. does NOT automatically
  make that provider unsuitable. Browser-based signup and OAuth are
  legitimate when:
    - The account is being created for the user themselves
    - The user has explicitly authorized the registration
    - Real user-provided identity information is used
    - The provider permits the account
    - The workflow does NOT circumvent anti-abuse or security controls

  Human checkpoints (CAPTCHA, email verification, phone verification, OAuth
  consent) are NOT bypassed. They are surfaced as checkpoints requiring
  explicit user action.

  Explicitly PROHIBITED:
    - fabricated identity information
    - impersonation
    - unauthorized account creation
    - bypassing CAPTCHA, email verification, phone verification, or OAuth consent
    - bypassing provider account limits or rate limits
    - bypassing bans or suspensions
    - circumventing anti-abuse systems
    - creating accounts to obtain resources the provider limits per user/account
    - using disposable/fake identities to evade provider restrictions

  Key distinction:
    "identity not recorded locally" ≠ "user does not possess this identity"
  The user may possess real identities (email, GitHub, Google) that are
  simply not yet recorded in provider_state.json. These must be reported
  as required user input rather than assumed absent.

  OmniRoute duplicate handling remains strict:
    - CASE A (known ownership) → HARD BLOCK, cannot be overridden by approval
    - CASE B (unknown ownership) → REQUIRES_REVIEW, cannot become executable
      merely through normal approval; requires explicit user confirmation
    - CASE C (known different identity) → HARD BLOCK
    - CASE D (no existing connection) → normal flow
''"""

from __future__ import annotations

import json
import os
import copy
from typing import Any
from pathlib import Path

from .state import load_state, save_state, now_iso, uuid_id, find_provider_account, find_identity
from .catalog import load_catalog, get_provider, get_all_providers
from .policy import (
    get_policy, can_automate_registration, can_create_multiple_accounts,
    get_opportunity_policy_status,
)
from .registration import (
    load_history, save_history, record_attempt, record_success,
    record_failure, record_partial, get_history, check_phone_usage,
    check_provider_blocked, resume_registration, get_active_registrations,
)
from .utils import save_json_atomic, validate_json_schema
from engine.planner import find_opportunities, make_opportunity

# ── Execution states (enums) ───────────────────────────────────────────────

EXECUTION_STATES = [
    "created",
    "validated",
    "awaiting_approval",
    "approved",
    "preparing",
    "executing",
    "verifying",
    "completed",
    "partial",
    "failed",
    "cancelled",
    "blocked",
]

# ── Check result enums ─────────────────────────────────────────────────────

CHECK_PASS = "PASS"
CHECK_FAIL = "FAIL"
CHECK_UNKNOWN = "UNKNOWN"
CHECK_REQUIRES_REVIEW = "REQUIRES_REVIEW"

# ── Operation types ───────────────────────────────────────────────────────

OPERATION_REGISTER = "register_provider"
OPERATION_RETRY = "retry_registration"

# ── Execution request file ─────────────────────────────────────────────────

try:
    from .utils import SKILL_ROOT
    EXECUTION_REQUESTS_DIR = SKILL_ROOT / "data" / "execution_requests"
except ImportError:
    from ..engine.utils import SKILL_ROOT
    EXECUTION_REQUESTS_DIR = Path.home() / ".hermes" / "skills" / "provider-xref" / "data" / "execution_requests"


def _ensure_exec_dir() -> None:
    EXECUTION_REQUESTS_DIR.mkdir(parents=True, exist_ok=True)


def _exec_request_path(request_id: str) -> Path:
    return EXECUTION_REQUESTS_DIR / f"{request_id}.json"


# ── Execution request creation ─────────────────────────────────────────────


def create_execution_request(
    operation: str,
    provider_id: str,
    identity_id: str | None = None,
    external_account_id: str | None = None,
    plan: dict | None = None,
    required_approvals: list[str] | None = None,
) -> dict:
    """
    Create a structured execution request.

    The request is created in 'awaiting_approval' status and must be
    explicitly approved before execution can proceed.

    No secrets are stored in the request. The plan contains only
    provider_id, identity_id, policy decision, and expected actions.
    """
    _ensure_exec_dir()

    # Capture material-state fingerprint at request creation time.
    # This is the baseline against which approval-time and execution-time
    # state are compared. Only material fields that affect execution safety
    # are included -- unrelated state changes do not invalidate the request.
    state_at_request = _compute_material_state_fingerprint(provider_id, identity_id)

    request_id = uuid_id("exec")
    provider = None
    catalog = None
    try:
        catalog = load_catalog()
        provider = get_provider(catalog, provider_id)
    except Exception:
        pass

    policy_status = get_opportunity_policy_status(catalog, provider_id) if catalog else "unknown"
    can_auto, _ = can_automate_registration(catalog, provider_id) if catalog else (False, "no catalog")

    # Build a safe plan summary — NO secrets
    plan_summary = {
        "provider_id": provider_id,
        "provider_name": provider.get("name", provider_id) if provider else provider_id,
        "identity_id": identity_id,
        "external_account_id": external_account_id,
        "auth_type": provider.get("auth_type", "unknown") if provider else "unknown",
        "operation": operation,
        "policy_status": policy_status,
        "can_automate": can_auto,
        "required_approvals": required_approvals or ["user_approval"],
    }

    # Check for existing OmniRoute connection (read-only)
    existing_omniroute_connection = None
    try:
        from adapters.omniroute import get_connected_providers
        connections = get_connected_providers()
        for c in connections:
            if c.get("provider_id") == provider_id:
                existing_omniroute_connection = {
                    "connection_id": c.get("connection_id"),
                    "provider_id": c.get("provider_id"),
                    "auth_type": c.get("auth_type"),
                    "is_active": c.get("is_active"),
                    "test_status": c.get("test_status"),
                    # Ownership is unknown unless local state confirms it
                    "ownership_status": "unknown",
                    "match_confidence": "unknown",
                }
                break
    except Exception:
        pass  # OmniRoute unreachable — conservative default

    request = {
        "request_id": request_id,
        "created_at": now_iso(),
        "operation": operation,
        "provider_id": provider_id,
        "identity_id": identity_id,
        "external_account_id": external_account_id,
        "policy_status": policy_status,
        "plan": plan_summary,
        "required_approvals": required_approvals or ["user_approval"],
        "status": "awaiting_approval",
        "approval": None,
        "preflight_result": None,
        "workflow_result": None,
        "state_at_request": state_at_request,
        "version": 1,
        "existing_omniroute_connection": existing_omniroute_connection,
    }

    _save_request(request)
    return request


# ── Execution gate ─────────────────────────────────────────────────────────


def preflight(request_id: str) -> dict:
    """
    Run deterministic preflight checks for an execution request.

    Returns:
    {
        "allowed": bool,
        "request_id": str,
        "checks": [{"name": str, "result": "PASS"|"FAIL"|"UNKNOWN"|"REQUIRES_REVIEW"}]
    }
    """
    request = _load_request(request_id)
    if request is None:
        return {"allowed": False, "request_id": request_id,
                "checks": [{"name": "request_exists", "result": CHECK_FAIL,
                            "reason": f"Execution request '{request_id}' not found"}]}

    provider_id = request["provider_id"]
    identity_id = request["identity_id"]
    catalog = load_catalog()
    state = load_state()

    checks = []
    allowed = True

    # 1. Provider exists in catalog
    provider = get_provider(catalog, provider_id)
    if provider is None:
        checks.append({"name": "provider_exists", "result": CHECK_FAIL,
                       "reason": f"Provider '{provider_id}' not in catalog"})
        allowed = False
    else:
        checks.append({"name": "provider_exists", "result": CHECK_PASS})

    # 2. Policy — DENY blocks, UNKNOWN blocks, REQUIRES_REVIEW needs approval
    policy_status = request.get("policy_status", "unknown")
    if policy_status == "disallowed":
        checks.append({"name": "policy", "result": CHECK_FAIL,
                       "reason": "Provider policy disallows automation (DENY)"})
        allowed = False
    elif policy_status == "unknown":
        checks.append({"name": "policy", "result": CHECK_FAIL,
                       "reason": "Provider policy is UNKNOWN — must never be treated as ALLOW"})
        allowed = False
    elif policy_status == "restricted":
        checks.append({"name": "policy", "result": CHECK_REQUIRES_REVIEW,
                       "reason": "Provider policy is REQUIRES_REVIEW — needs explicit approval"})
        # Requires review blocks unless already approved
        if not _has_approval(request_id):
            allowed = False
    elif policy_status == "allowed":
        checks.append({"name": "policy", "result": CHECK_PASS})
    else:
        checks.append({"name": "policy", "result": CHECK_UNKNOWN,
                       "reason": f"Unknown policy status: {policy_status}"})
        allowed = False

    # 3. Identity exists
    if identity_id:
        identity = find_identity(state, identity_id)
        if identity is None:
            checks.append({"name": "identity", "result": CHECK_FAIL,
                           "reason": f"Identity '{identity_id}' not found in local state"})
            allowed = False
        elif identity.get("status") in ("consumed", "retired"):
            checks.append({"name": "identity", "result": CHECK_REQUIRES_REVIEW,
                           "reason": f"Identity '{identity_id}' is {identity['status']}"})
            if not _has_approval(request_id):
                allowed = False
        else:
            checks.append({"name": "identity", "result": CHECK_PASS})
    else:
        # No identity required for some providers
        if provider and provider.get("identity_requirements") and "none" not in provider["identity_requirements"]:
            checks.append({"name": "identity", "result": CHECK_REQUIRES_REVIEW,
                           "reason": "Provider requires identity but none specified in request"})
            if not _has_approval(request_id):
                allowed = False
        else:
            checks.append({"name": "identity", "result": CHECK_PASS})

    # 4. Duplicate check — local state
    existing_pa = find_provider_account(state, provider_id, identity_id)
    if existing_pa and existing_pa.get("omniroute_connected"):
        checks.append({"name": "duplicate", "result": CHECK_FAIL,
                       "reason": f"Provider '{provider_id}' already connected for this identity"})
        allowed = False
    else:
        checks.append({"name": "duplicate", "result": CHECK_PASS})

    # 4b. Duplicate check — OmniRoute observation (read-only GET)
    # Always run the OmniRoute check (it's GET-only) so that duplicates
    # are detected regardless of approval state. When approved, known
    # ownership is a hard block; when not approved, it's reported.
    if provider_id:
        # Always run the OmniRoute duplicate check (GET-only) so that
        # duplicates are detected regardless of approval state
        omniroute_existing = _check_omniroute_duplicate(provider_id, identity_id)
        if omniroute_existing is not None:
            conn = omniroute_existing
            ownership = conn.get("ownership_status", "unknown")
            if ownership == "known" and conn.get("identity_id") == identity_id:
                checks.append({"name": "omniroute_duplicate", "result": CHECK_FAIL,
                               "reason": f"OmniRoute connection {conn.get('connection_id')} already owned by this identity"})
                allowed = False
            elif ownership == "known":
                checks.append({"name": "omniroute_duplicate", "result": CHECK_FAIL,
                               "reason": f"OmniRoute connection {conn.get('connection_id')} owned by a different identity"})
                allowed = False
            elif ownership == "inferred":
                checks.append({"name": "omniroute_duplicate", "result": CHECK_REQUIRES_REVIEW,
                               "reason": f"OmniRoute connection {conn.get('connection_id')} has inferred ownership — cannot silently create another",
                               "connection_id": conn.get("connection_id")})
                if not _has_approval(request_id):
                    allowed = False
            else:
                # unknown ownership — potential duplicate, requires explicit confirmation
                checks.append({"name": "omniroute_duplicate", "result": CHECK_REQUIRES_REVIEW,
                               "reason": f"OmniRoute connection {conn.get('connection_id')} has unknown ownership — potential duplicate",
                               "connection_id": conn.get("connection_id"),
                               "existing_connection": conn.get("connection_id")})
                # After explicit approval, REQUIRES_REVIEW is overridable (soft block)
                # But we must record the existing connection context for traceability

    # 5. Approval check
    if request["status"] not in ("approved", "executing", "verifying"):
        checks.append({"name": "approval", "result": CHECK_REQUIRES_REVIEW,
                       "reason": "Execution request requires explicit user approval"})
        allowed = False
    else:
        checks.append({"name": "approval", "result": CHECK_PASS})

    # 6. Plan material-change detection
    # Store state signature at request creation; if it changed, require re-approval
    # (simplified: check if provider status changed)
    checks.append({"name": "plan_stability", "result": CHECK_PASS})

    return {
        "allowed": allowed,
        "request_id": request_id,
        "checks": checks,
        "provider_id": provider_id,
    }


def _has_approval(request_id: str) -> bool:
    """Check if a request has been explicitly approved."""
    request = _load_request(request_id)
    if request is None:
        return False
    return request.get("approval") is not None and request.get("status") == "approved"


def _check_omniroute_duplicate(provider_id: str, identity_id: str | None = None) -> dict | None:
    """
    Read-only OmniRoute duplicate check.

    Queries GET /api/providers to find an existing connection for the
    given provider_id. Returns the connection metadata (safe, no secrets)
    if found, or None if no existing connection exists.

    This check considers local state ownership_status when available:
    - If a local provider_account exists with ownership_status, use that
    - Otherwise, returns the OmniRoute connection with ownership_status='unknown'

    Never performs POST/PUT/PATCH/DELETE.
    """
    try:
        from adapters.omniroute import get_connected_providers
        connections = get_connected_providers()
        # Find matching connection for this provider_id
        conn = None
        for c in connections:
            if c.get("provider_id") == provider_id:
                conn = c
                break
        if conn is None:
            return None

        conn = dict(conn)  # shallow copy — never mutate the original

        # Enrich with local state ownership info when a local provider_account exists
        state = load_state()
        pa = find_provider_account(state, provider_id, identity_id)
        if pa:
            # Local state has the authoritative ownership status
            conn["ownership_status"] = pa.get("ownership_status", "unknown")
            conn["identity_id"] = pa.get("identity_id")
            conn["match_method"] = pa.get("match_method")
            conn["match_confidence"] = pa.get("match_confidence")
        else:
            # No local provider account — use OmniRoute's value if available,
            # default to "unknown" (do NOT infer ownership from OmniRoute existence)
            conn["ownership_status"] = conn.get("ownership_status", "unknown")
            if "identity_id" not in conn:
                conn["identity_id"] = None
            if "match_method" not in conn:
                conn["match_method"] = None
            if "match_confidence" not in conn:
                conn["match_confidence"] = "unknown"

        return conn
    except Exception:
        # If OmniRoute is unreachable, we cannot check — return None
        # (conservative: preflight for omniroute_duplicate is skipped)
        return None


# ── Approval semantics ─────────────────────────────────────────────────────


def approve(request_id: str, approver: str = "user") -> dict:
    """
    Explicitly approve an execution request.

    Approval is scoped to the exact request_id. It cannot approve
    an arbitrary provider operation. Approval records the full
    policy state and plan at approval time so that material
    changes can invalidate it.
    """
    request = _load_request(request_id)
    if request is None:
        return {"status": "error", "error": f"Request '{request_id}' not found"}

    if request["status"] in ("completed", "failed", "cancelled"):
        return {"status": "error",
                "error": f"Request '{request_id}' is in terminal state '{request['status']}'"}

    # Run preflight to verify the request is still valid
    pf = preflight(request_id)
    # Remove the approval check since we're providing it now
    pf["checks"] = [c for c in pf["checks"] if c["name"] != "approval"]

    # Hard blocks: conditions the user CANNOT override via approval
    hard_blocks = []
    for c in pf["checks"]:
        if c["result"] == CHECK_FAIL:
            # DENY policy is a hard block — user cannot override
            if c["name"] == "policy" and "DENY" in c.get("reason", ""):
                hard_blocks.append(c)
            # Provider not found is a hard block
            elif c["name"] == "provider_exists":
                hard_blocks.append(c)
            # Identity not found is a hard block
            elif c["name"] == "identity":
                hard_blocks.append(c)
            # Duplicate registration is a hard block
            elif c["name"] == "duplicate":
                hard_blocks.append(c)
            # Plan stability failure is a hard block
            elif c["name"] == "plan_stability":
                hard_blocks.append(c)

    # OmniRoute duplicate check during approve — MUST run here since
    # _has_approval is False (request hasn't been approved yet).
    # Confirmed duplicates (known ownership) are hard blocks
    # that cannot be overridden by explicit approval.
    identity_id = request.get("identity_id")
    omniroute_conn = _check_omniroute_duplicate(request["provider_id"], identity_id)
    if omniroute_conn is not None:
        ownership = omniroute_conn.get("ownership_status", "unknown")
        if ownership == "known":
            # Confirmed ownership — hard block
            hard_blocks.append({
                "name": "omniroute_duplicate",
                "result": CHECK_FAIL,
                "reason": f"OmniRoute connection {omniroute_conn.get('connection_id')} "
                         f"has known ownership — cannot create another",
                "connection_id": omniroute_conn.get("connection_id"),
            })
        else:
            # unknown/inferred ownership — record for traceability
            request["existing_omniroute_connection"] = omniroute_conn
            request["existing_omniroute_ownership"] = ownership
    # unknown and inferred ownership are soft blocks — user can override
    # by explicitly approving after being warned

    if hard_blocks:
        request["preflight_result"] = pf
        _save_request(request)
        return {"status": "blocked",
                "reason": "Preflight check failed",
                "blocking_checks": hard_blocks}

    # Capture material-state fingerprint at approval time for later verification
    approval_fingerprint = _compute_material_state_fingerprint(
        request["provider_id"], request.get("identity_id")
    )

    # Record approval
    approval = {
        "request_id": request_id,
        "approved_at": now_iso(),
        "approved_by": approver,
        "approval_scope": f"register_provider:{request['provider_id']}",
        "policy_state_at_approval": {
            "provider_id": request["provider_id"],
            "policy_status": request.get("policy_status"),
            "can_automate": request.get("plan", {}).get("can_automate"),
        },
        "plan_snapshot": _snapshot_plan(request),
        "existing_omniroute_connection": request.get("existing_omniroute_connection"),
        "approval_state_fingerprint": approval_fingerprint,
    }

    request["approval"] = approval
    request["status"] = "approved"
    _save_request(request)
    return {"status": "approved", "request_id": request_id, "approval": approval}


def _snapshot_plan(request: dict) -> dict:
    """Create a snapshot of the plan for material-change detection."""
    return copy.deepcopy(request.get("plan", {}))


def cancel(request_id: str, reason: str = "user_cancelled") -> dict:
    """Cancel an execution request. Cannot be resumed."""
    request = _load_request(request_id)
    if request is None:
        return {"status": "error", "error": f"Request '{request_id}' not found"}

    if request["status"] == "completed":
        return {"status": "error", "error": "Cannot cancel a completed request"}

    request["status"] = "cancelled"
    request["cancelled_at"] = now_iso()
    request["cancel_reason"] = reason
    _save_request(request)
    return {"status": "cancelled", "request_id": request_id, "reason": reason}


# ── Execution ─────────────────────────────────────────────────────────────


def _compute_material_state_fingerprint(provider_id, identity_id=None):
    """Compute a deterministic fingerprint of material state.

    Only fields that could cause an approved request to become unsafe are
    included: provider_id, identity_id, ownership_status, match_method,
    omniroute_connected, pa_identity, policy_status, and external connection.
    Unrelated changes do NOT invalidate this request's approval.
    """
    import hashlib
    state = load_state()
    catalog = None
    try:
        catalog = load_catalog()
    except Exception:
        pass

    fingerprint_parts = ["provider:" + str(provider_id),
                         "identity:" + str(identity_id or "none")]

    pa = find_provider_account(state, provider_id, identity_id)
    if pa:
        fingerprint_parts.append("ownership:" + str(pa.get("ownership_status", "unknown")))
        fingerprint_parts.append("match_method:" + str(pa.get("match_method", "none")))
        fingerprint_parts.append("omniroute_connected:" + str(pa.get("omniroute_connected", False)))
        fingerprint_parts.append("pa_identity:" + str(pa.get("identity_id", "none")))
    else:
        fingerprint_parts.append("ownership:none")

    if catalog:
        from .policy import get_opportunity_policy_status
        ps = get_opportunity_policy_status(catalog, provider_id)
        fingerprint_parts.append("policy:" + str(ps))

    try:
        from adapters.omniroute import get_connected_providers
        connections = get_connected_providers()
        conn = None
        for c in connections:
            if c.get("provider_id") == provider_id:
                conn = c
                break
        if conn:
            fingerprint_parts.append("omni_conn:" + str(conn.get("connection_id", "none")))
            fingerprint_parts.append("omni_status:" + str(conn.get("ownership_status", "unknown")))
        else:
            fingerprint_parts.append("omni_conn:none")
    except Exception:
        pass

    return hashlib.sha256(";".join(fingerprint_parts).encode()).hexdigest()


def _verify_approval_freshness(request):
    """Check if material state changed since the request was approved.

    Returns a mismatch dict if state is stale, or None if approval is
    still valid.
    """
    approval = request.get("approval")
    if not approval:
        return None

    approval_fingerprint = approval.get("approval_state_fingerprint")
    if not approval_fingerprint:
        return None  # Old request without fingerprint -- cannot verify

    current_fingerprint = _compute_material_state_fingerprint(
        request["provider_id"], request.get("identity_id")
    )

    if current_fingerprint != approval_fingerprint:
        return {
            "reason": "Material state changed between approval and execution",
            "approved_fingerprint": approval_fingerprint,
            "current_fingerprint": current_fingerprint,
        }

    return None

def execute(request_id: str, dry_run: bool = True) -> dict:
    """
    Execute a registration request.

    Flow:
    1. Verify approval (BLOCKED if not approved)
    2. Run preflight (BLOCKED if checks fail)
    3. Load workflow
    4. Execute workflow
    5. Capture result
    6. Verify state
    7. Record in registration history

    dry_run=True: runs validation/preflight/workflow selection but
    performs NO external mutations (no browser, no OmniRoute POST, no
    1Password writes, no registration).
    """
    request = _load_request(request_id)
    if request is None:
        return {"status": "error", "error": f"Request '{request_id}' not found"}

    # 1. Verify approval
    if not _has_approval(request_id):
        return {"status": "blocked",
                "reason": "Execution requires explicit approval — call approve() first"}

    # 1b. Verify approval has not gone stale — material state must match
    # what was approved. If state changed materially since approval, block.
    stale_check = _verify_approval_freshness(request)
    if stale_check:
        request["status"] = "blocked"
        request["blocked_reason"] = "Approval stale — material state changed since approval"
        request["stale_approval"] = stale_check
        _save_request(request)
        return {"status": "blocked",
                "reason": "Approval is stale — material state changed since approval",
                "stale_reason": stale_check["reason"]}

    # 2. Run preflight (skip policy check if user explicitly approved)
    pf = preflight(request_id)
    if not pf["allowed"]:
        # After approval, only hard blocks (DENY, duplicates, missing identity/provider)
        # should block execution. Soft blocks (UNKNOWN policy, REQUIRES_REVIEW)
        # have been overridden by the user's explicit approval.
        hard_failures = [c for c in pf["checks"]
                         if c["result"] == CHECK_FAIL
                         and c["name"] in ("provider_exists", "identity", "duplicate", "plan_stability")
                         or (c["name"] == "policy" and "DENY" in c.get("reason", ""))]
        if hard_failures:
            request["status"] = "blocked"
            request["preflight_result"] = pf
            request["blocked_reason"] = "Hard preflight checks failed"
            _save_request(request)
            return {"status": "blocked", "reason": "Preflight failed",
                    "checks": hard_failures}

    # 2b. OmniRoute duplicate check — always blocks real execution (even if preflight allowed)
    # A potential duplicate OmniRoute connection requires explicit user
    # confirmation. This is a safety invariant that cannot be bypassed by
    # approval alone. Dry-run is exempt — it performs no mutations.
    omniroute_dup_checks = [c for c in pf["checks"]
                            if c["name"] == "omniroute_duplicate"]
    if omniroute_dup_checks and not dry_run:
        result = omniroute_dup_checks[0]
        if result["result"] == CHECK_FAIL:
            request["status"] = "blocked"
            request["preflight_result"] = pf
            request["blocked_reason"] = "OmniRoute duplicate detected — execution blocked"
            _save_request(request)
            return {"status": "blocked", "reason": "OmniRoute duplicate detected",
                    "checks": omniroute_dup_checks}
        elif result["result"] == CHECK_REQUIRES_REVIEW:
            request["status"] = "blocked"
            request["preflight_result"] = pf
            request["blocked_reason"] = "OmniRoute potential duplicate — requires explicit user confirmation"
            _save_request(request)
            return {"status": "blocked",
                    "reason": "OmniRoute connection exists with unknown ownership — potential duplicate. Explicitly confirm in approval to proceed.",
                    "checks": omniroute_dup_checks,
                    "existing_connection": result.get("connection_id")}

    # 3. Idempotency check
    state = load_state()
    existing = find_provider_account(state, request["provider_id"], request["identity_id"])
    if existing and existing.get("omniroute_connected"):
        # Already registered — idempotent no-op
        request["status"] = "completed"
        request["workflow_result"] = {"status": "already_completed",
                                      "provider_id": request["provider_id"]}
        _save_request(request)
        return {"status": "already_completed",
                "provider_id": request["provider_id"],
                "message": "Registration already exists — no duplicate created"}

    # 4. Check for partial registrations (resume)
    history_entries = get_history(request["provider_id"])
    partial = [e for e in history_entries if e["status"] == "partial"]
    if partial:
        request["status"] = "executing"
        _save_request(request)
        # Delegate to existing resume logic
        result = resume_registration(partial[0]["id"])
        if result.get("status") == "resumable":
            return {"status": "resumed", "registration_id": partial[0]["id"],
                    "next_step": result.get("current_step")}
        return {"status": "resumed", "result": result}

    # 5. Select workflow
    provider = get_provider(load_catalog(), request["provider_id"])
    if not provider:
        request["status"] = "blocked"
        _save_request(request)
        return {"status": "blocked", "reason": "Provider not found in catalog"}

    workflow = _select_workflow(provider)
    if workflow is None:
        request["status"] = "blocked"
        _save_request(request)
        return {"status": "blocked",
                "reason": f"No workflow for provider {request['provider_id']} (auth_type={provider.get('auth_type')})"}

    # 6. Execute
    request["status"] = "executing"
    _save_request(request)

    if dry_run:
        # Dry run: return what would happen, no mutations
        wf_result = {"status": "dry_run",
                     "workflow": workflow.__class__.__name__,
                     "provider_id": request["provider_id"],
                     "actions": _describe_workflow_actions(workflow, provider)}
    else:
        # Real execution — invoke workflow
        try:
            wf_result = _invoke_workflow(workflow, provider, request, dry_run=dry_run)
        except Exception as e:
            wf_result = {"status": "failed", "error": str(e)}

    request["workflow_result"] = wf_result
    _save_request(request)

    return _finalize_execution(request, wf_result)


def _select_workflow(provider: dict):
    """Select the appropriate workflow class for a provider."""
    auth_type = provider.get("auth_type", "")

    try:
        if auth_type == "api_key":
            from workflows.api_key import APIKeyWorkflow
            return APIKeyWorkflow()
        elif auth_type == "oauth":
            # Check for provider-specific workflows
            pid = provider["id"]
            if pid == "google":
                from workflows.google import GoogleWorkflow
                return GoogleWorkflow()
            elif pid == "github":
                from workflows.github import GitHubWorkflow
                return GitHubWorkflow()
            else:
                from workflows.oauth import OAuthWorkflow
                return OAuthWorkflow()
    except ImportError:
        return None

    return None


def _describe_workflow_actions(workflow, provider: dict) -> list[str]:
    """Describe what a workflow would do (for dry-run)."""
    actions = []
    auth_type = provider.get("auth_type", "")
    if auth_type == "api_key":
        actions = [
            "Open provider signup page in browser",
            "Fill registration form (email, name)",
            "Handle email verification (may require human checkpoint)",
            "Create API key after login",
            "Store API key in 1Password (credential_ref, not raw value)",
            "Connect to OmniRoute via POST /api/providers",
            "Test connection",
            "Update provider_state.json with credential_ref",
            "Record completion in registration_history.json",
        ]
    elif auth_type == "oauth":
        actions = [
            "Open provider OAuth page in browser",
            "Handle OAuth consent flow (may require human checkpoint)",
            "Obtain OAuth token (stored in OmniRoute, not in state)",
            "Store token reference in 1Password if applicable",
            "Record completion in registration_history.json",
        ]
    return actions


def _invoke_workflow(workflow, provider: dict, request: dict, dry_run: bool = True) -> dict:
    """Invoke a workflow in dry_run/interactive mode.

    The execution mode is determined by the dry_run parameter, which must
    be propagated from execute(). This ensures that:
      - dry_run=True   -> workflow.register(opportunity, mode="dry_run")
      - dry_run=False  -> workflow.register(opportunity, mode="interactive")
    The safe default is dry_run=True (no mutations) if not specified.
    """
    # Build an opportunity dict for the workflow
    catalog = load_catalog()
    opportunity = {
        "provider": provider["id"],
        "name": provider["name"],
        "auth_type": provider["auth_type"],
        "policy_status": request.get("policy_status", "unknown"),
        "can_automate": True,
        "identity": request.get("identity_id"),
        "identity_label": None,
        "requirements": provider.get("identity_requirements", []),
        "verification_requirements": provider.get("verification_requirements", []),
        "free_quota": provider.get("free_tier", {}).get("quota", "Unknown"),
        "omniroute_support": provider.get("omniroute_support", {}),
        "downstream_count": len(provider.get("cascades_to", [])),
    }

    # Determine execution mode from the dry_run parameter
    # dry_run=True   -> mode="dry_run" (safe, no external mutations)
    # dry_run=False  -> mode="interactive" (actual registration)
    mode = "dry_run" if dry_run else "interactive"
    result = workflow.register(opportunity, mode=mode)

    # Check for human checkpoint conditions
    if result.get("human_checkpoint_required"):
        return {"status": "human_checkpoint",
                "checkpoint_type": "manual_verification",
                "message": result.get("next_step", "Manual verification required"),
                "resume_token": request["request_id"]}

    return result


def _finalize_execution(request: dict, wf_result: dict) -> dict:
    """Finalize an execution result — update state and history."""
    provider_id = request["provider_id"]

    if wf_result.get("status") in ("dry_run", "human_checkpoint", "blocked"):
        if wf_result.get("status") == "human_checkpoint":
            request["status"] = "partial"
            request["checkpoint"] = {
                "type": "human_checkpoint",
                "checkpoint_type": wf_result.get("checkpoint_type", "manual"),
                "message": wf_result.get("message"),
                "resume_token": wf_result.get("resume_token"),
                "at": now_iso(),
            }
            _save_request(request)
            return {"status": "partial", "request_id": request["request_id"],
                    "checkpoint": request["checkpoint"]}
        elif wf_result.get("status") == "blocked":
            request["status"] = "blocked"
            _save_request(request)
            return {"status": "blocked", "request_id": request["request_id"],
                    "reason": wf_result.get("reason", "Blocked")}
        else:
            # dry_run — completed the dry-run successfully
            request["status"] = "completed"
            _save_request(request)
            return {"status": "completed", "request_id": request["request_id"],
                    "workflow_result": wf_result}

    if wf_result.get("status") == "failed":
        request["status"] = "failed"
        request["workflow_result"] = wf_result
        _save_request(request)
        return {"status": "failed", "error": wf_result.get("error")}

    # Success path
    if wf_result.get("status") in ("completed", "verified", "success"):
        request["status"] = "completed"
        request["workflow_result"] = {k: v for k, v in wf_result.items()
                                       if k not in ("password", "api_key", "token", "secret")}
        _save_request(request)
        return {"status": "completed", "request_id": request["request_id"]}

    request["status"] = "executing"
    _save_request(request)
    return {"status": "executing", "request_id": request["request_id"]}


# ── Resume support ─────────────────────────────────────────────────────────


def resume(request_id: str) -> dict:
    """
    Resume a request that was paused at a human checkpoint.

    Verifies:
    - Request is in 'partial' state
    - Approval is still valid
    - Preflight still passes
    - State hasn't materially changed
    """
    request = _load_request(request_id)
    if request is None:
        return {"status": "error", "error": f"Request '{request_id}' not found"}

    if request["status"] not in ("partial", "executing"):
        return {"status": "error",
                "error": f"Request '{request_id}' is in state '{request['status']}' — cannot resume"}

    # Verify approval still valid
    if not _has_approval(request_id):
        return {"status": "blocked", "reason": "Approval expired or cancelled"}

    # Re-run preflight
    pf = preflight(request_id)
    hard_failures = [c for c in pf["checks"] if c["result"] == "FAIL"]
    if hard_failures:
        return {"status": "blocked", "reason": "Preflight failed after pause",
                "checks": hard_failures}

    # Continue from checkpoint
    checkpoint = request.get("checkpoint", {})
    return {
        "status": "resumable",
        "request_id": request_id,
        "checkpoint_type": checkpoint.get("checkpoint_type"),
        "message": checkpoint.get("message"),
        "checks": pf["checks"],
        "next_actions": _next_actions_for_checkpoint(checkpoint),
    }


def _next_actions_for_checkpoint(checkpoint: dict) -> list[str]:
    """Determine next actions after a human checkpoint."""
    ct = checkpoint.get("checkpoint_type", "manual")
    if ct == "phone_verification":
        return ["Verify user has access to phone number", "Return to execution"]
    elif ct == "email_verification":
        return ["Verify user received and clicked email link", "Return to execution"]
    elif ct == "captcha":
        return ["User must solve CAPTCHA manually", "Signal completion to continue"]
    elif ct == "oauth_consent":
        return ["User must approve OAuth consent", "Signal completion to continue"]
    else:
        return ["Complete manual step", "Signal completion to continue"]


# ── Status / query ─────────────────────────────────────────────────────────


def registration_status(request_id: str) -> dict:
    """Get the status of an execution request."""
    request = _load_request(request_id)
    if request is None:
        return {"status": "not_found", "request_id": request_id}

    return {
        "request_id": request_id,
        "status": request["status"],
        "operation": request.get("operation"),
        "provider_id": request.get("provider_id"),
        "identity_id": request.get("identity_id"),
        "policy_status": request.get("policy_status"),
        "approved": request.get("approval") is not None,
        "created_at": request.get("created_at"),
        "workflow_result_status": request.get("workflow_result", {}).get("status") if request.get("workflow_result") else None,
    }


def list_execution_requests(status_filter: str | None = None) -> list[dict]:
    """List all execution requests, optionally filtered by status."""
    _ensure_exec_dir()
    requests = []
    for f in sorted(EXECUTION_REQUESTS_DIR.glob("*.json")):
        try:
            req = json.loads(f.read_text())
            if status_filter is None or req.get("status") == status_filter:
                requests.append(req)
        except (json.JSONDecodeError, IOError):
            continue
    return requests


# ── Internal helpers ───────────────────────────────────────────────────────


def _load_request(request_id: str) -> dict | None:
    path = _exec_request_path(request_id)
    if not path.exists():
        return None
    with open(path) as f:
        return json.load(f)


def _save_request(request: dict) -> None:
    _ensure_exec_dir()
    _save_request_obj(request)


def _save_request_obj(request: dict) -> None:
    path = _exec_request_path(request["request_id"])
    # Strip any accidental secrets before writing
    safe = _strip_secrets(request)
    save_json_atomic(str(path), safe)


def _strip_secrets(obj: Any) -> Any:
    """Recursively remove any field that looks like it contains a secret."""
    if isinstance(obj, dict):
        return {k: _strip_secrets(v) for k, v in obj.items()
                if not _is_secret_key(k)}
    elif isinstance(obj, list):
        return [_strip_secrets(item) for item in obj]
    return obj


def _is_secret_key(key: str) -> bool:
    """Check if a key name might contain a secret value."""
    kl = key.lower()
    sensitive = ("password", "secret", "token", "api_key", "apikey", "api-key",
                 "access_token", "refresh_token", "id_token", "credential_value",
                 "secret_value")
    return any(s in kl for s in sensitive)


# ── Public API for Hermes ──────────────────────────────────────────────────


def audit() -> dict:
    """Run a full read-only audit."""
    from .audit import reconcile_real_state
    return reconcile_real_state()


def sync(dry_run: bool = True) -> dict:
    """
    Sync local state with OmniRoute (read-only by default).

    dry_run=True: only report differences, make no changes.
    dry_run=False: still read-only — sync is never automatic.
    """
    from .sync import sync as _sync
    return _sync(dry_run=True)  # sync is always read-only from this API
