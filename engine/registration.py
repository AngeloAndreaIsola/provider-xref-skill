"""
registration.py — Registration state machine and ledger.

Every registration must have a state.

States:
  DISCOVERED → ELIGIBILITY_CHECK → PLANNED → APPROVED → PREPARING →
  REGISTRATION → VERIFICATION → CREDENTIAL_ACQUISITION →
  OMNIROUTE_CONNECTION → 1PASSWORD_STORAGE → VERIFICATION → COMPLETE

Failure states: FAILED, BLOCKED, POLICY_BLOCKED, WAITING_FOR_USER, PARTIAL

The engine is resumable: if something fails halfway through,
the partial state is preserved and can be resumed.
"""

from __future__ import annotations

from typing import Any
from datetime import datetime, timezone

from .utils import now_iso, uuid_id, load_json, save_json_atomic, HISTORY_FILE
from .state import load_state, save_state
from .catalog import load_catalog, get_provider
from .policy import get_policy, get_opportunity_policy_status, can_automate_registration

import os

HISTORY_DIR = os.path.expanduser("~/.hermes/skills/provider-xref/data")
HISTORY_FILE = os.path.join(HISTORY_DIR, "registration_history.json")
PLANS_DIR = os.path.expanduser("~/.hermes/skills/provider-xref/data/plans")
ACTIVE_DIR = os.path.join(HISTORY_DIR, "active")
COMPLETED_DIR = os.path.join(HISTORY_DIR, "completed")
FAILED_DIR = os.path.join(HISTORY_DIR, "failed")


# ── Registration states ─────────────────────────────────────────────────

REGISTRATION_STATES = [
    "discovered",
    "eligibility_check",
    "planned",
    "approved",
    "preparing",
    "registration",
    "verification",
    "credential_acquisition",
    "omniroute_connection",
    "onepassword_storage",
    "verifying",
    "completed",
    "failed",
    "blocked",
    "policy_blocked",
    "waiting_for_user",
    "partial",
]

FAILURE_STATES = {"failed", "blocked", "policy_blocked", "waiting_for_user", "partial"}


# ── Ledger (registration_history.json) ──────────────────────────────────

def load_history() -> list[dict]:
    """Load registration history entries."""
    data = load_json(HISTORY_FILE, default=None)
    if data is None:
        return []
    if isinstance(data, list):
        return data
    return data.get("entries", [])


def save_history(entries: list[dict]) -> None:
    """Save registration history."""
    data = {"history_version": 1, "entries": entries}
    save_json_atomic(HISTORY_FILE, data)


def record_attempt(provider_id: str, method: str, trigger_event: str = "manual",
                   identity_id: str | None = None, provider_catalog_provider: dict | None = None) -> dict:
    """Record a new registration attempt in the ledger."""
    entries = load_history()
    entry = {
        "id": uuid_id("reg"),
        "provider_id": provider_id,
        "identity_id": identity_id,
        "method": method,
        "trigger_event": trigger_event,
        "started_at": now_iso(),
        "completed_at": None,
        "status": "planned",
        "steps": {},
        "credential_created": False,
        "credential_ref": None,
        "omniroute_status": "not_attempted",
        "omniroute_account_id": None,
        "onepassword_status": "not_attempted",
        "policy_status": get_opportunity_policy_status(None, provider_id) if provider_catalog_provider else "unknown",
        "phone_used": None,
        "email_used": None,
        "failure_reason": None,
        "metadata": provider_catalog_provider is not None and {"provider_name": provider_catalog_provider.get("name", provider_id)} or {},
    }
    entries.append(entry)
    save_history(entries)
    return entry


def record_success(reg_id: str, result: dict) -> dict:
    """Mark a registration as completed."""
    entries = load_history()
    for entry in entries:
        if entry["id"] == reg_id:
            entry["status"] = "completed"
            entry["completed_at"] = now_iso()
            entry["steps"] = result.get("steps", entry.get("steps", {}))
            entry["credential_created"] = result.get("credential_created", False)
            entry["credential_ref"] = result.get("credential_ref")
            entry["omniroute_status"] = result.get("omniroute_status", "connected")
            entry["omniroute_account_id"] = result.get("omniroute_account_id")
            entry["onepassword_status"] = result.get("onepassword_status", "stored")
            entry["phone_used"] = result.get("phone_used")
            entry["email_used"] = result.get("email_used")
            save_history(entries)
            return entry
    raise KeyError(f"Registration not found: {reg_id}")


def record_failure(reg_id: str, reason: str, step: str | None = None) -> dict:
    """Mark a registration as failed."""
    entries = load_history()
    for entry in entries:
        if entry["id"] == reg_id:
            entry["status"] = "failed"
            entry["completed_at"] = now_iso()
            entry["failure_reason"] = reason
            if step:
                entry["steps"][step] = "failed"
            save_history(entries)
            return entry
    raise KeyError(f"Registration not found: {reg_id}")


def record_partial(reg_id: str, steps_completed: dict, failure_reason: str | None = None) -> dict:
    """
    Record a partial registration.
    Preserves what succeeded so it can be resumed later.
    """
    entries = load_history()
    for entry in entries:
        if entry["id"] == reg_id:
            entry["status"] = "partial"
            entry["completed_at"] = now_iso()
            entry["steps"] = steps_completed
            entry["failure_reason"] = failure_reason
            save_history(entries)
            return entry
    raise KeyError(f"Registration not found: {reg_id}")


def get_history(provider_id: str | None = None) -> list[dict]:
    """Get history entries, optionally filtered by provider."""
    entries = load_history()
    if provider_id:
        entries = [e for e in entries if e["provider_id"] == provider_id]
    return sorted(entries, key=lambda e: e["started_at"], reverse=True)


def get_active_registrations() -> list[dict]:
    """Get all in-progress or partial registrations."""
    entries = load_history()
    active = [e for e in entries if e["status"] not in ("completed", "failed", "policy_blocked")]
    return sorted(active, key=lambda e: e["started_at"], reverse=True)


def resume_registration(reg_id: str | None = None) -> dict:
    """
    Resume a partial registration.

    If reg_id is provided, resume that specific registration.
    Otherwise, resume the most recent partial one.
    """
    entries = load_history()

    if reg_id:
        target = [e for e in entries if e["id"] == reg_id]
    else:
        target = [e for e in entries if e["status"] == "partial"]

    if not target:
        return {"status": "no_active_registration", "message": "No partial registration found to resume"}

    entry = target[0]
    return {
        "status": "resumable",
        "entry": entry,
        "last_completed_step": max(
            (k for k, v in entry.get("steps", {}).items() if v == "completed"),
            key=lambda k: list(entry.get("steps", {}).keys()).index(k),
            default=None
        ),
        "current_step": _next_step(entry.get("steps", {}), entry.get("failure_reason")),
    }


def _next_step(steps: dict, failure_reason: str | None = None) -> str | None:
    """Determine the next step to attempt after a partial registration."""
    # Find the first step that is not 'completed'
    all_steps = [
        "discover", "eligibility_check", "select_identity", "prepare_credentials",
        "open_provider", "registration", "email_verification", "phone_verification",
        "oauth", "api_key_extraction", "omniroute_connection", "onepassword_storage",
        "state_update", "verify", "complete"
    ]
    for step in all_steps:
        if step not in steps or steps[step] != "completed":
            return step
    return None


def check_phone_usage(phone_number: str | None = None) -> dict:
    """
    Check if a phone number has already been used for registration.
    Returns usage info from the historical ledger.
    """
    entries = load_history()
    usages = [e for e in entries if e.get("phone_used") == phone_number]

    google_verifications = sum(1 for e in usages if "google" in (e.get("provider_id") or ""))
    github_verifications = sum(1 for e in usages if "github" in (e.get("provider_id") or ""))

    return {
        "phone": phone_number,
        "total_usages": len(usages),
        "google_verifications": google_verifications,
        "github_verifications": github_verifications,
        "has_google_limit": google_verifications >= 2,
        "has_github_limit": github_verifications >= 1,
        "details": [{"provider_id": e["provider_id"], "status": e["status"], "started_at": e["started_at"]} for e in usages],
    }


def check_provider_blocked(provider_id: str) -> dict:
    """
    Check if a provider has previously rejected a second account for this identity.
    """
    entries = load_history()
    rejections = [e for e in entries
                  if e["provider_id"] == provider_id and e["status"] == "failed"
                  and "multiple account" in (e.get("failure_reason") or "").lower()]

    return {
        "provider_id": provider_id,
        "rejection_count": len(rejections),
        "has_rejection": len(rejections) > 0,
        "details": [{"failure_reason": e.get("failure_reason"), "started_at": e["started_at"]} for e in rejections],
    }
