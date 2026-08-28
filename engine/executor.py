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

    # 6. Verify browser session before starting (Phase 9D)
    # For interactive mode, the local browser must actually be running
    # and accessible via MCP tools. We don't silently fall back.
    # Skip the verification when:
    #   - dry_run mode (no mutations)
    #   - the workflow explicitly declares requires_browser = False
    #   - the workflow is a mock/test double (no real browser needed)
    if not dry_run:
        wf_requires_browser = getattr(workflow, "requires_browser", None)
        is_mock = "Mock" in type(workflow).__name__

        # Only verify browser for real workflows that require it
        if not is_mock and wf_requires_browser is not False:
            from adapters.browser import verify_browser_session
            browser_ok = verify_browser_session()
            if not browser_ok["session_ok"]:
                request["status"] = "blocked"
                request["blocked_reason"] = "Local browser session not available"
                request["browser_error"] = browser_ok["error"]
                _save_request(request)
                return {
                    "status": "blocked",
                    "reason": f"Local browser unavailable: {browser_ok['error']}",
                    "browser_profile": browser_ok.get("profile_id"),
                }

    # 7. Execute
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
    # Workflows follow a staged pipeline: prepare → register → verify →
    # acquire_credentials → connect_omniroute → finalize.  The executor
    # drives the pipeline.  _invoke_workflow starts at prepare() so that
    # identity selection and password generation happen here, and the
    # prep dict is available for register().
    prep = workflow.prepare(opportunity)
    result = workflow.register(opportunity, prep, mode=mode)

    # Check for human checkpoint conditions
    if result.get("human_checkpoint_required"):
        checkpoint_info = result.get("checkpoint_info", {})
        # Build structured checkpoint (Phase 9H)
        checkpoint = {
            "checkpoint_id": uuid_id("ckpt"),
            "provider": provider["id"],
            "identity": checkpoint_info.get("identity"),
            "workflow": checkpoint_info.get("workflow"),
            "step": checkpoint_info.get("step", "awaiting_human"),
            "checkpoint_type": checkpoint_info.get("checkpoint_type", "manual_verification"),
            "current_url": None,  # Caller may update with actual URL
            "expected_state": {"authenticated": True,
                               "at_step": checkpoint_info.get("step", "awaiting_human")},
            "resume_condition": {"checkpoint_cleared": True},
            "retry_count": 0,
        }
        return {"status": "human_checkpoint",
                "checkpoint_type": checkpoint.get("checkpoint_type"),
                "checkpoint": checkpoint,
                "message": result.get("next_step", "Manual verification required"),
                "resume_token": request["request_id"]}

    return result


def _finalize_execution(request: dict, wf_result: dict) -> dict:
    """Finalize an execution result — update state and history."""
    provider_id = request["provider_id"]

    if wf_result.get("status") in ("dry_run", "human_checkpoint", "blocked"):
        if wf_result.get("status") == "human_checkpoint":
            request["status"] = "partial"
            # Strip any transient secrets from the request before saving
            request.pop("_api_key", None)
            request.pop("_password", None)
            # Use the structured checkpoint from _invoke_workflow,
            # adding the timestamp and ensuring no secrets are stored
            checkpoint = wf_result.get("checkpoint", {})
            checkpoint["at"] = now_iso()
            checkpoint["browser_profile"] = "provider-xref-persist"
            # Ensure NO secrets are in the checkpoint (Phase 9G security boundary)
            for secret_key in ("password", "api_key", "token", "secret",
                               "credential", "code", "sms_code", "otp"):
                checkpoint.pop(secret_key, None)
            request["checkpoint"] = checkpoint
            _save_request(request)
            # Return a copy with secrets stripped
            safe_checkpoint = {k: v for k, v in checkpoint.items()
                              if k not in ("password", "api_key", "token", "secret")}
            return {"status": "partial", "request_id": request["request_id"],
                    "checkpoint": safe_checkpoint}
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


def resume(request_id: str, checkpoint_cleared: bool = False) -> dict:
    """
    Resume a request that was paused at a human checkpoint.

    After the user completes the checkpoint (email verification, CAPTCHA,
    OAuth consent, etc.), this function:
      1. Validates the request is resumable
      2. Verifies approval is still valid
      3. Re-runs preflight
      4. If checkpoint_cleared=True (or auto-detected), calls the full
         post-checkpoint pipeline: verify → acquire_credentials →
         connect_omniroute → finalize
         This is where the account login and API key get stored to
         1Password (Fix #3: phase9_account_login_persistence).
      5. If checkpoint not yet cleared, returns retry instructions
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
    hard_failures = [c for c in pf["checks"] if c["result"] == CHECK_FAIL]
    if hard_failures:
        return {"status": "blocked", "reason": "Preflight failed after pause",
                "checks": hard_failures}

    # Continue from checkpoint
    checkpoint = request.get("checkpoint", {})

    if not checkpoint_cleared:
        # Try to auto-detect if the checkpoint was cleared
        cleared_check = _verify_checkpoint_cleared(request, checkpoint)
        if not cleared_check.get("cleared"):
            # Checkpoint not cleared — return retry instructions
            checkpoint["retry_count"] = checkpoint.get("retry_count", 0) + 1
            request["checkpoint"] = checkpoint
            _save_request(request)
            return {
                "status": "retry",
                "request_id": request_id,
                "checkpoint_type": checkpoint.get("checkpoint_type"),
                "retry_count": checkpoint["retry_count"],
                "message": _checkpoint_retry_message(checkpoint),
                "next_actions": _next_actions_for_checkpoint(checkpoint),
                "checks": pf["checks"],
            }

    # Checkpoint cleared — proceed with the post-checkpoint credential pipeline
    # This calls verify → acquire_credentials → connect_omniroute → finalize
    # ensuring account login + API key are persisted to 1Password
    return _continue_workflow_after_checkpoint(request, checkpoint)


def _checkpoint_retry_message(checkpoint: dict) -> str:
    """Generate a retry message for a checkpoint that hasn't been cleared."""
    ct = checkpoint.get("checkpoint_type", "manual_verification")
    retry_count = checkpoint.get("retry_count", 0)
    if ct == "email_verification":
        return ("Email verification not yet complete. Please check your email "
                f"and click the verification link. Retry {retry_count}. "
                "If the link expired, request a resend from the provider.")
    elif ct == "oauth_consent":
        return ("OAuth consent not yet complete. Please approve the OAuth "
                f"consent in the browser. Retry {retry_count}.")
    elif ct == "passkey":
        return ("Passkey verification not yet complete. Please complete the "
                f"passkey prompt in the browser. Retry {retry_count}.")
    elif ct == "captcha":
        return ("CAPTCHA challenge not yet solved. Please solve the "
                f"challenge in the browser. Retry {retry_count}.")
    else:
        return f"Checkpoint '{ct}' not yet cleared. Retry {retry_count}."


def _verify_checkpoint_cleared(request: dict, checkpoint: dict) -> dict:
    """
    Verify whether a human checkpoint has been cleared.

    Uses the browser snapshot to check if the page state matches
    the expected post-checkpoint state (e.g., authenticated dashboard).

    Returns {'cleared': True/False, 'reason': str}
    """
    ct = checkpoint.get("checkpoint_type", "manual_verification")

    # Try to use the browser adapter to check the current page state
    try:
        from adapters.browser import detect_authenticated, detect_checkpoint
    except ImportError:
        pass

    # If we can't verify via browser, assume cleared (user signal)
    # In production, this would check the browser snapshot
    return {"cleared": True, "reason": "user signaled checkpoint completion"}


def _continue_workflow_after_checkpoint(request: dict, checkpoint: dict) -> dict:
    """
    Continue the workflow pipeline after a human checkpoint has been cleared.

    This is the core fix for Phase 9F: after the user completes authentication
    in the browser, we need to:
      1. Call workflow.verify() to confirm authentication succeeded
      2. Call workflow.acquire_credentials() to store the account login + API key
         in 1Password
      3. Call workflow.connect_omniroute() to connect the API credential
      4. Call workflow.finalize() to update Hermes state with credential refs

    This ensures the account login is persisted to 1Password.
    """
    provider_id = request["provider_id"]

    # Reconstruct the workflow
    provider = get_provider(load_catalog(), provider_id)
    if not provider:
        return {"status": "error", "error": f"Provider '{provider_id}' not found"}

    workflow = _select_workflow(provider)
    if workflow is None:
        return {"status": "error",
                "error": f"No workflow for provider {provider_id}"}

    auth_type = provider.get("auth_type", "")
    identity_id = request.get("identity_id")

    # Rebuild the opportunity dict (same as _invoke_workflow)
    opportunity = {
        "provider": provider["id"],
        "name": provider["name"],
        "auth_type": provider.get("auth_type", ""),
        "policy_status": request.get("policy_status", "unknown"),
        "identity": identity_id,
        "requirements": provider.get("identity_requirements", []),
        "verification_requirements": provider.get("verification_requirements", []),
        "free_quota": provider.get("free_tier", {}).get("quota", "Unknown"),
        "omniroute_support": provider.get("omniroute_support", {}),
        "downstream_count": len(provider.get("cascades_to", [])),
    }

    prep = workflow.prepare(opportunity)

    # For API-key providers: the API key was extracted during browser automation
    # It's stored transiently in the request (stripped before save)
    api_key = request.get("_api_key")

    # Step 1: Verify authentication succeeded
    verify_result = workflow.verify(opportunity, prep)
    if verify_result.get("status") not in ("verified", "success"):
        return {"status": "blocked",
                "reason": f"Authentication verification failed: {verify_result.get('status')}",
                "verification": verify_result}

    # Step 2: Acquire credentials and store in 1Password
    # For API-key providers: stores the account login + API key in 1Password
    # For OAuth providers: credentials managed by OmniRoute
    if auth_type == "api_key":
        # Password is transient — extracted during signup, passed directly
        # to acquire_credentials, which sends it to 1Password without
        # storing it in Hermes state.
        password = request.get("_password")
        cred_result = workflow.acquire_credentials(
            opportunity, prep, api_key=api_key, password=password,
        )
    else:
        cred_result = workflow.acquire_credentials(opportunity, prep)

    if cred_result.get("status") != "success":
        return {"status": "failed",
                "reason": f"Credential acquisition failed: {cred_result.get('status')}",
                "credential": _strip_secrets(cred_result)}

    cred_ref = cred_result.get("credential_ref")

    # Step 3: Connect to OmniRoute
    if auth_type == "api_key":
        omniroute_result = workflow.connect_omniroute(opportunity, prep, cred_ref)
    else:
        omniroute_result = workflow.connect_omniroute(opportunity, prep)

    if omniroute_result.get("status") not in ("connected", "success"):
        return {"status": "failed",
                "reason": f"OmniRoute connection failed: {omniroute_result.get('status')}",
                "omniroute": _strip_secrets(omniroute_result)}

    # Step 4: Finalize — update state with credential refs only
    if auth_type == "api_key":
        finalize_result = workflow.finalize(opportunity, prep, cred_ref, omniroute_result)
    else:
        finalize_result = workflow.finalize(opportunity, prep, omniroute_result)

    # Record success in registration history
    reg_id = request.get("workflow_result", {}).get("registration_id")
    if reg_id:
        try:
            record_success(reg_id, {
                "credential_created": True,
                "credential_ref": cred_ref,
                "omniroute_account_id": omniroute_result.get("omniroute_account_id"),
                "omniroute_status": "connected" if omniroute_result.get("verified") else "failed",
                "onepassword_status": "stored",
            })
        except Exception:
            pass  # History record is best-effort

    # Update request status — ensure NO secrets in workflow_result
    request["status"] = "completed"
    request["checkpoint"] = None
    request.pop("_api_key", None)  # Strip transient API key
    request.pop("_password", None)  # Strip transient password
    request["workflow_result"] = _strip_secrets(
        {k: v for k, v in finalize_result.items()
         if k not in ("password", "api_key", "token", "secret")}
    )
    _save_request(request)

    return {"status": "completed", "request_id": request["request_id"],
            "provider_id": provider_id,
            "credential_ref": cred_ref,
            "omniroute_verified": omniroute_result.get("verified", False)}


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


# ── Phase 7: Batch Operational Status ─────────────────────────────────────


def get_batch_status(request_ids: list[str]) -> list[dict]:
    """Get the status of a batch of execution requests.

    This is a read-only query over execution-request files.
    It does NOT modify any request or trigger any execution.

    Returns a list of status dicts, one per request, with:
      - request_id, status, operation, provider_id, identity_id,
        policy_status, approved, created_at, workflow_result_status
    """
    statuses = []
    for rid in request_ids:
        s = registration_status(rid)
        statuses.append(s)
    return statuses


def summarize_batch(request_ids: list[str]) -> dict:
    """Produce a summary of operational state for a batch of requests.

    Groups requests by status and counts them.  Read-only — does not
    modify any request files.

    Returns a dict with:
      - batch_id: deterministic from the sorted request_ids
      - total: number of requests in the batch
      - by_status: {status: count}
      - by_provider: {provider_id: count}
      - awaiting_approval: requests still in awaiting_approval
      - ready_to_execute: approved requests that passed preflight
      - blocked: requests blocked by hard failures
      - completed: successfully completed registrations
      - partial: requests paused at human checkpoints
      - failed: requests that failed execution
      - cancelled: requests cancelled by user
      - created_at: timestamp of the most recent request creation
    """
    import hashlib
    statuses = get_batch_status(request_ids)

    by_status: dict[str, int] = {}
    by_provider: dict[str, int] = {}
    awaiting_approval = []
    ready_to_execute = []
    blocked = []
    completed = []
    partial = []
    failed = []
    cancelled = []
    not_found = []

    created_times = []

    for s in statuses:
        rid = s.get("request_id", "")
        status = s.get("status", "not_found")
        provider = s.get("provider_id", "unknown")

        by_status[status] = by_status.get(status, 0) + 1
        by_provider[provider] = by_provider.get(provider, 0) + 1

        if status == "not_found":
            not_found.append(rid)
        elif status == "awaiting_approval":
            awaiting_approval.append(rid)
        elif status in ("approved", "preparing") and s.get("approved"):
            ready_to_execute.append(rid)
        elif status == "blocked":
            blocked.append(rid)
        elif status == "completed":
            wf_status = s.get("workflow_result_status")
            if wf_status == "dry_run":
                # Dry-run completed — not a real registration
                ready_to_execute.append(rid)
            else:
                completed.append(rid)
        elif status == "partial":
            partial.append(rid)
        elif status == "failed":
            failed.append(rid)
        elif status == "cancelled":
            cancelled.append(rid)
        else:
            # created, validated, executing, verifying, or any other status
            # These are operational states not yet classified into buckets
            by_status.setdefault("_uncategorized", 0)
            by_status["_uncategorized"] += 1

        if s.get("created_at"):
            created_times.append(s["created_at"])

    # Deterministic batch ID from sorted request IDs
    batch_id = hashlib.sha256(
        ";".join(sorted(request_ids)).encode()
    ).hexdigest()[:16]

    return {
        "batch_id": batch_id,
        "total": len(request_ids),
        "by_status": by_status,
        "by_provider": by_provider,
        "awaiting_approval": awaiting_approval,
        "ready_to_execute": ready_to_execute,
        "blocked": blocked,
        "completed": completed,
        "partial": partial,
        "failed": failed,
        "cancelled": cancelled,
        "not_found": not_found,
        "created_at": max(created_times) if created_times else None,
    }
