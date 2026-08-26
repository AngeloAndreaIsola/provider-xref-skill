"""
state.py — Provider state loader, validator, and atomic saver.

The state is the local source of truth for what is currently true:
identities, external accounts, provider accounts, credentials, and
capabilities.  No secrets are ever stored in state — only credential
references (backend, vault, item_id, field).

Every modification must go through the load → validate → modify →
validate → atomic-save pipeline to prevent corruption from partial
or incomplete data sources (e.g. a truncated OmniRoute response).
"""

from __future__ import annotations

import copy
from typing import Any

from .utils import (
    STATE_FILE, load_json, save_json_atomic, now_iso,
    validate_json_schema, uuid_id,
)


# ── Defaults ────────────────────────────────────────────────────────────

def default_state() -> dict:
    """Return a minimal valid state structure."""
    return {
        "schema_version": 1,
        "updated_at": now_iso(),
        "identities": [],
        "external_accounts": [],
        "provider_accounts": [],
        "credentials": [],
        "capabilities": [],
    }


# ── Load / Save ─────────────────────────────────────────────────────────

def load_state() -> dict:
    """
    Load provider_state.json.

    If the file doesn't exist, returns a default empty state.
    If it exists but is invalid JSON, raises ValueError.
    """
    data = load_json(STATE_FILE, default=None)
    if data is None:
        return default_state()
    if not isinstance(data, dict):
        raise ValueError(f"provider_state.json is not a JSON object (got {type(data).__name__})")
    return data


def save_state(state: dict) -> None:
    """
    Validate and atomically save state.

    This is the *only* write path.  Never use json.dump directly.
    """
    ok, msg = validate_state(state)
    if not ok:
        raise ValueError(f"State validation failed: {msg}")

    state["updated_at"] = now_iso()
    state["schema_version"] = _ensure_schema_version(state)
    save_json_atomic(STATE_FILE, state)


def validate_state(state: dict) -> tuple[bool, str]:
    """Validate state against its JSON schema."""
    return validate_json_schema(state, "provider_state.schema.json")


def _ensure_schema_version(state: dict) -> int:
    """Bump or enforce the schema version."""
    sv = state.get("schema_version", 0)
    # Handle both int and str schema versions
    if isinstance(sv, str):
        try:
            sv = int(sv)
        except ValueError:
            sv = 0
    if sv < 1:
        state["schema_version"] = 1
        return 1
    return sv


# ── Convenience accessors ──────────────────────────────────────────────

def get_identities(state: dict | None = None) -> list[dict]:
    if state is None:
        state = load_state()
    return state.get("identities", [])


def get_external_accounts(state: dict | None = None) -> list[dict]:
    if state is None:
        state = load_state()
    return state.get("external_accounts", [])


def get_provider_accounts(state: dict | None = None) -> list[dict]:
    if state is None:
        state = load_state()
    return state.get("provider_accounts", [])


def get_credentials(state: dict | None = None) -> list[dict]:
    if state is None:
        state = load_state()
    return state.get("credentials", [])


def get_capabilities(state: dict | None = None) -> list[dict]:
    if state is None:
        state = load_state()
    return state.get("capabilities", [])


# ── Mutations (each goes through full pipeline) ─────────────────────────

def add_identity(identity: dict) -> dict:
    """Add a new identity to state.

    If the identity dict has no 'id', a canonical ID is generated from
    the identity type and value using canonical_identity_id(). This ensures
    that the same identity always produces the same ID across discovery,
    matching, and explicit addition.
    """
    if not identity.get("id"):
        # Generate canonical ID from type + value
        from engine.identity import canonical_identity_id
        id_type = identity.get("type", "email")
        id_value = identity.get("value", "")
        if id_value:
            identity["id"] = canonical_identity_id(id_type, id_value)
        else:
            identity["id"] = uuid_id("identity")
    if "created_at" not in identity:
        identity["created_at"] = now_iso()
    if "status" not in identity:
        identity["status"] = "active"
    if "source" not in identity:
        identity["source"] = "manual"
    if "verification" not in identity:
        identity["verification"] = {}
    if "constraints" not in identity:
        identity["constraints"] = []

    state = load_state()
    state["identities"].append(identity)
    save_state(state)
    return state


def add_external_account(account: dict) -> dict:
    """Add a new external (identity provider) account."""
    if not account.get("id"):
        account["id"] = uuid_id("ext")
    if "created_at" not in account:
        account["created_at"] = now_iso()
    if "status" not in account:
        account["status"] = "unknown"
    if "auth_method" not in account:
        account["auth_method"] = "oauth"

    state = load_state()
    state["external_accounts"].append(account)
    save_state(state)
    return state


def add_provider_account(account: dict) -> dict:
    """Add a new provider account."""
    if not account.get("id"):
        account["id"] = uuid_id("pa")
    if "created_at" not in account:
        account["created_at"] = now_iso()
    if "status" not in account:
        account["status"] = "unknown"
    if "auth_type" not in account:
        account["auth_type"] = "unknown"
    if "omniroute_connected" not in account:
        account["omniroute_connected"] = False
    if "ownership_status" not in account:
        account["ownership_status"] = "unknown"
    if "source" not in account:
        account["source"] = "manual"
    if "match_confidence" not in account:
        account["match_confidence"] = "unknown"

    state = load_state()
    state["provider_accounts"].append(account)
    save_state(state)
    return state


def add_credential(cred: dict) -> dict:
    """Add a new credential reference (never the actual secret)."""
    if not cred.get("id"):
        cred["id"] = uuid_id("cred")
    if "created_at" not in cred:
        cred["created_at"] = now_iso()
    if "status" not in cred:
        cred["status"] = "unknown"

    state = load_state()
    state["credentials"].append(cred)
    save_state(state)
    return state


def add_capability(cap: dict) -> dict:
    """Add a new capability."""
    if not cap.get("id"):
        cap["id"] = uuid_id("cap")
    if "status" not in cap:
        cap["status"] = "unknown"

    state = load_state()
    state["capabilities"].append(cap)
    save_state(state)
    return state


# ── Find helpers ────────────────────────────────────────────────────────

def find_identity(state: dict, identity_id: str) -> dict | None:
    for id in state.get("identities", []):
        if id["id"] == identity_id:
            return id
    return None


def find_provider_account(state: dict, provider_id: str, identity_id: str | None = None) -> dict | None:
    """Find a provider account, optionally filtered by identity."""
    for pa in state.get("provider_accounts", []):
        if pa["provider_id"] == provider_id:
            if identity_id is None or pa.get("identity_id") == identity_id:
                return pa
    return None


def find_credentials_for_provider(state: dict, provider_id: str) -> list[dict]:
    """Find all credential refs for a given provider."""
    results = []
    pids = [pa["id"] for pa in state.get("provider_accounts", []) if pa["provider_id"] == provider_id]
    for cred in state.get("credentials", []):
        if cred.get("provider_account_id") in pids:
            results.append(cred)
    return results


def mark_identity_consumed(state: dict, identity_id: str, consumed: bool = True) -> dict:
    """Mark an identity as consumed (e.g. phone used for verification)."""
    for id in state.get("identities", []):
        if id["id"] == identity_id:
            id["status"] = "consumed" if consumed else "available"
    save_state(state)
    return state


def deep_copy_state() -> dict:
    """Return a deep copy of the current state (for diffing/safe modification)."""
    return copy.deepcopy(load_state())
