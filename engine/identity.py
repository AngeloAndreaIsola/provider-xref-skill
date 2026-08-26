"""
identity.py — Identity discovery, ownership matching, and review queue.

This module provides:
  - Identity discovery from safe sources (local state, OmniRoute metadata, 1Password metadata)
  - Deterministic ownership matching (UUID > provider_id > 1Password evidence)
  - Structured review queue for ambiguous ownership
  - Explicit ownership confirmation (user_confirmed)

Key rules:
  - Discovery produces *observations*, not ownership claims
  - 1Password evidence remains requires_review, never known
  - Provider name alone cannot establish ownership
  - OmniRoute connection existence cannot establish ownership
  - Same input must always produce the same result (deterministic)
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from typing import Any

from .state import load_state, save_state, now_iso
from .catalog import load_catalog, get_all_providers, get_provider
from .graph import ProviderGraph
from .policy import (
    get_policy,
    can_automate_registration,
    can_create_multiple_accounts,
    policy_risk_score,
    get_opportunity_policy_status,
)

try:
    from adapters.omniroute import is_running, get_connected_providers
    from adapters.onepassword import list_vaults, search_items, ensure_signed_in
except ImportError:
    from ..adapters.omniroute import is_running, get_connected_providers
    from ..adapters.onepassword import list_vaults, search_items, ensure_signed_in

try:
    from .utils import now_iso as _now_iso, uuid_id
except ImportError:
    from ..engine.utils import now_iso as _now_iso, uuid_id


# ── Ownership statuses ─────────────────────────────────────────────────

OWNERSHIP_UNKNOWN = "unknown"
OWNERSHIP_MATCHED = "known"
OWNERSHIP_INFERRED = "inferred"
OWNERSHIP_REQUIRES_REVIEW = "requires_review"


# ── Identity sources ───────────────────────────────────────────────────

IDENTITY_SOURCE_USER_PROVIDED = "user_provided"
IDENTITY_SOURCE_LOCAL_STATE = "local_state"
IDENTITY_SOURCE_OMNIROUTE = "omniroute_metadata"
IDENTITY_SOURCE_1PASSWORD = "onepassword_metadata"
IDENTITY_SOURCE_AGY = "agy"


# ── Identity Discovery ───────────────────────────────────────────────────

def discover_identities(state: dict | None = None) -> list[dict]:
    """
    Discover identities from safe sources.

    Sources (in order of reliability):
      0. User-provided identity leads (explicitly declared by user — highest priority)
      1. Local state (provider_state.json) — explicitly user-declared identities
      2. 1Password login items (metadata only — username/email fields)
      3. OmniRoute safe metadata (display_name, email fields — metadata only)

    Does NOT retrieve:
      - Passwords
      - API keys
      - OAuth tokens
      - TOTP secrets

    Returns a list of identity observation dicts. These are OBSERVATIONS,
    not claims of ownership.
    """
    if state is None:
        state = load_state()

    observed_identities = []
    seen_values = set()

    # 0. User-provided identity leads (highest priority)
    # These are email addresses the user has explicitly stated they own.
    # They establish source=user_provided observations but do NOT
    # automatically prove ownership of any provider account.
    for user_email in _USER_PROVIDED_EMAILS:
        if user_email and user_email.lower() not in [v.lower() for v in seen_values]:
            identity_id = f"identity_email_{_normalize_email(user_email)}"
            observed_identities.append({
                "id": identity_id,
                "type": "email",
                "value": user_email,
                "source": IDENTITY_SOURCE_USER_PROVIDED,
                "confidence": "high",
                "verified": False,
                "evidence_type": "user_provided_identity",
                "note": "Identity explicitly provided by user in Phase 6.4",
            })
            seen_values.add(user_email.lower())

    # 1. Local state identities
    for identity in state.get("identities", []):
        value = identity.get("value", "")
        if value and value not in seen_values:
            observed_identities.append({
                "id": identity["id"],
                "type": identity["type"],
                "value": value,
                "source": identity.get("source", "local_state"),
                "confidence": "high",
                "verified": identity.get("verification", {}).get(
                    "email_verified" if identity["type"] in ("email", "google") else
                    "phone_verified", False
                ),
                "evidence_type": "local_identity",
            })
            seen_values.add(value)

    # 2. 1Password metadata (metadata only — no secrets)
    if ensure_signed_in():
        op_items = _discover_onepassword_identities()
        for item in op_items:
            value = item.get("username")
            if not value or value in seen_values:
                continue
            observed_identities.append({
                "type": item.get("identity_type", "email"),
                "value": value,
                "source": "1password_metadata",
                "confidence": "low",
                "verified": False,
                "evidence_type": "1password_login_item",
                "item_id": item.get("item_id"),
                "vault": item.get("vault"),
                "title": item.get("title"),
            })
            seen_values.add(value)

    # 3. OmniRoute safe metadata (metadata only)
    omni_identities = _discover_omniroute_identities()
    for item in omni_identities:
        value = item.get("value")
        if not value or value in seen_values:
            continue
        observed_identities.append({
            "type": item.get("type", "email"),
            "value": value,
            "source": "omniroute_metadata",
            "confidence": "low",
            "verified": False,
            "evidence_type": "omniroute_connection_metadata",
            "connection_id": item.get("connection_id"),
            "provider_id": item.get("provider_id"),
        })
        seen_values.add(value)

    return observed_identities


def reconcile_identities(state: dict | None = None, catalog: dict | None = None) -> dict:
    """
    Reconcile identities, OmniRoute connections, and ownership status.

    This is a READ-ONLY operation (except it may update local state with
    observation metadata — never credentials).

    Returns a reconciliation report:
    {
        "identities": [...],          # discovered identity observations
        "ownership": {
            "known": [...],
            "inferred": [...],
            "requires_review": [...],
            "unknown": [...],
        },
        "review_queue": [...],         # items requiring user confirmation
        "duplicate_check": {           # CASE analysis for OmniRoute connections
            "case_a": [...],          # confirmed duplicates (known ownership)
            "case_b": [...],          # requires_review (unknown ownership)
            "case_c": [...],          # different identity (hard block)
            "case_d": [...],          # no existing connection (pass)
        },
        "state_hash_before": str,
        "state_hash_after": str,
    }

    Does NOT:
    - Register any accounts
    - Modify OmniRoute
    - Write to 1Password
    - Store credentials
    """
    if state is None:
        state = load_state()
    if catalog is None:
        catalog = load_catalog()

    # Hash state before reconciliation
    state_before = hashlib.sha256(
        json.dumps(state, sort_keys=True).encode()
    ).hexdigest()

    # Discover identities (read-only — observations only)
    identities = discover_identities(state)

    # Get OmniRoute connections (GET only)
    omni_providers = []
    if is_running():
        try:
            omni_providers = get_connected_providers()
        except Exception:
            omni_providers = []

    # Match ownership for all connections
    op_evidence = _discover_onepassword_evidence_items()
    ownership_results = match_all_ownerships(
        omni_providers,
        state.get("provider_accounts", []),
        state=state,
        catalog=catalog,
    )

    # Build review queue
    review_queue = build_review_queue(ownership_results, omni_providers, state, catalog)

    # Duplicate check (read-only analysis)
    duplicate_check = {
        "case_a": [],  # known ownership + existing connection = hard block
        "case_b": [],  # unknown ownership + existing connection = requires_review
        "case_c": [],  # known ownership to another identity = hard block
        "case_d": [],  # no existing connection = pass
    }

    local_pa_by_provider = {}
    for pa in state.get("provider_accounts", []):
        local_pa_by_provider[pa.get("provider_id")] = pa

    for omni_pa in omni_providers:
        pid = omni_pa.get("provider_id", "")
        conn_id = omni_pa.get("connection_id", "")

        result = match_ownership(
            omni_pa, state.get("provider_accounts", []), op_evidence, catalog
        )
        status = result["ownership_status"]

        if status == OWNERSHIP_MATCHED:
            # CASE A or C
            dup_entry = {
                "provider_id": pid,
                "connection_id": conn_id,
                "ownership_status": status,
                "identity_id": result.get("identity_id"),
                "case": "A" if not result.get("identity_id") or \
                    local_pa_by_provider.get(pid, {}).get("identity_id") == result.get("identity_id")
                    else "C",
            }
            duplicate_check["case_a" if dup_entry["case"] == "A" else "case_c"].append(dup_entry)
        elif status == OWNERSHIP_REQUIRES_REVIEW:
            duplicate_check["case_b"].append({
                "provider_id": pid,
                "connection_id": conn_id,
                "ownership_status": status,
            })

    # Determine CASE D: ALLOW providers with no existing OmniRoute connection
    for p in get_all_providers(catalog):
        if p.get("policy") == "allow" and p["id"] not in {
            c.get("provider_id") for c in omni_providers
        }:
            duplicate_check["case_d"].append({
                "provider_id": p["id"],
                "connection_id": None,
                "ownership_status": "pass",
            })

    state_after = hashlib.sha256(
        json.dumps(state, sort_keys=True).encode()
    ).hexdigest()

    return {
        "identities": identities,
        "ownership": ownership_results,
        "review_queue": review_queue,
        "duplicate_check": duplicate_check,
        "state_hash_before": state_before,
        "state_hash_after": state_after,
    }


def _discover_onepassword_identities() -> list[dict]:
    """Extract identity-like observations from 1Password login items (metadata only)."""
    identities = []
    search_terms = ["login", "account", "api", "key"]
    seen_ids = set()

    for term in search_terms:
        try:
            items = search_items(term)
        except Exception:
            continue

        for item in items:
            item_id = item.get("id")
            if item_id in seen_ids:
                continue
            seen_ids.add(item_id)

            # Extract safe metadata only — NO passwords, tokens, or secrets
            vault = item.get("vault", {})
            if isinstance(vault, dict):
                vault_name = vault.get("name", vault.get("id", "?"))
            else:
                vault_name = vault or "?"

            username = (
                item.get("additional", {}).get("username") or
                item.get("additional", {}).get("email") or
                item.get("username") or
                item.get("email")
            )

            if not username:
                continue

            # Infer identity type from item title
            title_lower = (item.get("title") or "").lower()
            identity_type = _infer_identity_type(title_lower)

            identities.append({
                "item_id": item_id,
                "title": item.get("title", ""),
                "vault": vault_name,
                "username": username,
                "identity_type": identity_type,
                "category": item.get("category", ""),
            })

    return identities


def _infer_identity_type(title_lower: str) -> str:
    """Infer identity type from a 1Password item title (best-effort, low confidence)."""
    if any(t in title_lower for t in ["google", "gmail", "gcp", "google.com"]):
        return "google"
    if any(t in title_lower for t in ["github", "git"]):
        return "github"
    if any(t in title_lower for t in ["microsoft", "azure", "ms account", "outlook", "hotmail"]):
        return "microsoft"
    if any(t in title_lower for t in ["apple"]):
        return "apple"
    return "email"


def _discover_omniroute_identities() -> list[dict]:
    """
    Extract identity-like observations from OmniRoute safe metadata only.

    Does NOT retrieve secrets. Only reads display_name and email fields
    that OmniRoute exposes in its GET /api/providers response.
    """
    if not is_running():
        return []

    ids = []
    try:
        providers = get_connected_providers()
    except Exception:
        return []

    for p in providers:
        # Only extract safe metadata — NEVER secrets
        email = p.get("email") or p.get("metadata", {}).get("email")
        display_name = p.get("display_name") or p.get("name")

        if email and "@" in email:
            ids.append({
                "value": email,
                "type": "email",
                "connection_id": p.get("connection_id"),
                "provider_id": p.get("provider_id"),
            })
        elif display_name and "@" in display_name:
            ids.append({
                "value": display_name,
                "type": "email",
                "connection_id": p.get("connection_id"),
                "provider_id": p.get("provider_id"),
            })

    return ids


# ── Ownership Matching ──────────────────────────────────────────────────

# User-provided identity leads — these are email addresses the user has
# explicitly stated they own. They establish source=user_provided
# observations but do NOT automatically prove ownership of provider
# accounts. Email match = moderate evidence → inferred (requires_review
# if combined with conflicting evidence, known if user explicitly confirms).
_USER_PROVIDED_EMAILS = [
    "angeloandrea.isola@gmail.com",
    "lazymause@gmail.com",
    "islandgametrale@gmail.com",
    "andrea.isola@me.com",
]


def _match_email_identity(omni_provider: dict) -> dict | None:
    """
    Check if an OmniRoute connection's email matches a user-provided identity.

    This is MODERATE evidence (→ inferred), not strong evidence (→ known).
    The email must exactly match one of the user's declared email identities.

    Searches both the 'email' field and the 'display_name'/'name' fields
    (since some OmniRoute connections embed the email in the display name,
    e.g., "GitHub andrea.isola@me.com" for agentrouter).

    Returns the match dict or None if no match.
    """
    import re

    # Collect all fields that might contain an email address
    candidate_fields = []
    email = omni_provider.get("email") or omni_provider.get("metadata", {}).get("email")
    if email:
        candidate_fields.append(email)

    display_name = omni_provider.get("display_name") or omni_provider.get("name")
    if display_name:
        candidate_fields.append(display_name)

    for field_val in candidate_fields:
        if not field_val:
            continue

        # Extract all email-like substrings from the field value
        found_emails = re.findall(r'[\w.+-]+@[\w.-]+\.\w+', field_val)
        for found_email in found_emails:
            email_lower = found_email.lower().strip()
            for user_email in _USER_PROVIDED_EMAILS:
                if email_lower == user_email.lower():
                    return {
                        "identity_id": f"identity_email_{_normalize_email(user_email)}",
                        "evidence": {
                            "source": "user_provided",
                            "evidence_type": "email_match",
                            "strength": "moderate",
                            "email": user_email,
                            "connection_id": omni_provider.get("connection_id"),
                            "provider_id": omni_provider.get("provider_id", ""),
                            "note": "Exact email match between OmniRoute connection metadata and user-provided identity. Requires user confirmation to upgrade to 'known'.",
                        },
                    }
    return None


def _normalize_email(email: str) -> str:
    """Normalize an email address for deterministic ID generation."""
    import re
    return re.sub(r"[^a-zA-Z0-9]", "_", email.lower())[:40]


def match_ownership(
    omni_provider: dict,
    local_pas: list[dict],
    op_evidence: list[dict],
    catalog: dict | None = None,
) -> dict:
    """
    Deterministically match an OmniRoute connection to a local identity/external account.

    Matching priority:
      1. Existing explicit local provider-account relationship (omniroute_account_id)
      2. Existing explicit external-account relationship
      3. Provider ID match with local state
      4. Strong account identifier match
      5. Safe 1Password metadata as supporting evidence

    Returns:
    {
      "ownership_status": "known" | "inferred" | "requires_review" | "unknown",
      "match_method": "connection_id" | "provider_id" | "external_account" |
                      "1password_username" | "manual" | None,
      "match_confidence": "high" | "medium" | "low" | "none",
      "identity_id": str | None,
      "external_account_id": str | None,
      "evidence": [...],
    }

    NEVER fabricates ownership from provider name alone.
    NEVER equates OmniRoute connection existence with user ownership.
    """
    conn_id = omni_provider.get("connection_id")
    provider_id = omni_provider.get("provider_id", "")

    # ── 0. Email-based identity match (MODERATE evidence → inferred) ──────
    # If the OmniRoute connection exposes an email that exactly matches
    # a user-provided identity, this is moderate evidence of ownership.
    # It does NOT automatically upgrade to "known" — that requires
    # explicit user confirmation via confirm_ownership().
    email_match = _match_email_identity(omni_provider)
    if email_match:
        return {
            "ownership_status": OWNERSHIP_INFERRED,
            "match_method": "email_identity_match",
            "match_confidence": "medium",
            "identity_id": email_match["identity_id"],
            "external_account_id": None,
            "evidence": [email_match["evidence"]],
        }

    # ── 1. Match by OmniRoute connection UUID ──────────────────────────
    for pa in local_pas:
        if conn_id and pa.get("omniroute_account_id") == conn_id:
            return _build_match_result(
                pa, "connection_id", "high",
                evidence=[{
                    "source": "local_state",
                    "evidence_type": "connection_id_match",
                    "connection_id": conn_id,
                }],
            )
        # Also check metadata.connection_id
        if conn_id and pa.get("metadata", {}).get("connection_id") == conn_id:
            return _build_match_result(
                pa, "connection_id", "high",
                evidence=[{
                    "source": "local_state",
                    "evidence_type": "connection_id_match",
                    "connection_id": conn_id,
                }],
            )

    # ── 2. Match by provider_id in local state ─────────────────────────
    for pa in local_pas:
        if pa.get("provider_id") == provider_id:
            # We have a local record for this provider_id
            if pa.get("identity_id"):
                # Local state claims ownership — verify via match_method
                existing_method = pa.get("match_method", "")
                if existing_method in ("connection_id", "manual", "omniroute_uuid"):
                    return _build_match_result(
                        pa, existing_method or "provider_id", "high",
                        evidence=[{
                            "source": "local_state",
                            "evidence_type": "provider_id_match",
                            "provider_id": provider_id,
                            "existing_match_method": existing_method,
                        }],
                    )
                else:
                    # Provider ID match is a candidate, not proof
                    return _build_match_result(
                        pa, "provider_id", "medium",
                        evidence=[{
                            "source": "local_state",
                            "evidence_type": "provider_id_match",
                            "provider_id": provider_id,
                            "note": "candidate match — requires identity link",
                        }],
                    )

    # ── 3. 1Password evidence ──────────────────────────────────────────
    op_matches = _match_onepassword_evidence(conn_id, provider_id, op_evidence)
    if op_matches:
        # 1Password evidence → requires_review (NOT known)
        return {
            "ownership_status": OWNERSHIP_REQUIRES_REVIEW,
            "match_method": "1password_evidence",
            "match_confidence": "medium",
            "identity_id": None,
            "external_account_id": None,
            "evidence": op_matches,
        }

    # ── 4. No evidence ──────────────────────────────────────────────────
    return {
        "ownership_status": OWNERSHIP_UNKNOWN,
        "match_method": None,
        "match_confidence": "none",
        "identity_id": None,
        "external_account_id": None,
        "evidence": [],
    }


def _build_match_result(pa: dict, match_method: str, confidence: str, evidence: list) -> dict:
    """Build a match result from an existing local provider account."""
    # A UUID connection match is the strongest evidence — it confirms
    # the OmniRoute connection belongs to this local record.
    # The local record's ownership_status is preserved UNLESS it is
    # explicitly "requires_review" (which requires user review).
    local_status = pa.get("ownership_status", OWNERSHIP_UNKNOWN)
    if local_status == OWNERSHIP_REQUIRES_REVIEW:
        status = OWNERSHIP_REQUIRES_REVIEW
    elif local_status == OWNERSHIP_INFERRED:
        status = OWNERSHIP_INFERRED
    else:
        # UUID match or explicit method → known
        status = OWNERSHIP_MATCHED

    return {
        "ownership_status": status,
        "match_method": match_method,
        "match_confidence": confidence,
        "identity_id": pa.get("identity_id"),
        "external_account_id": pa.get("external_account_id"),
        "evidence": evidence,
        "local_account_id": pa.get("id"),
    }


def _match_onepassword_evidence(conn_id: str, provider_id: str, op_evidence: list[dict]) -> list[dict]:
    """Find 1Password evidence items matching this OmniRoute connection."""
    matches = []
    for item in op_evidence:
        evidence_provider = item.get("provider_id", "").lower()
        item_title = (item.get("title") or "").lower()
        pid = provider_id.lower()

        if evidence_provider and evidence_provider in pid:
            matches.append(item)
        elif pid in item_title:
            matches.append(item)
    return matches


def match_all_ownerships(
    omni_providers: list[dict],
    local_pas: list[dict] | None = None,
    state: dict | None = None,
    catalog: dict | None = None,
) -> dict:
    """
    Match ownership for all OmniRoute connections.

    Returns:
    {
      "known": [...],
      "inferred": [...],
      "requires_review": [...],
      "unknown": [...],
    }

    Deterministic: same inputs produce same outputs.
    """
    if state is None:
        state = load_state()
    if local_pas is None:
        local_pas = state.get("provider_accounts", [])
    if catalog is None:
        catalog = load_catalog()

    # Discover 1Password evidence (metadata only)
    op_evidence = _discover_onepassword_evidence_items()

    known = []
    inferred = []
    requires_review = []
    unknown = []

    for omni_pa in omni_providers:
        result = match_ownership(omni_pa, local_pas, op_evidence, catalog)
        entry = {
            "provider_id": omni_pa.get("provider_id", ""),
            "connection_id": omni_pa.get("connection_id"),
            "auth_type": omni_pa.get("auth_type"),
            "display_name": omni_pa.get("display_name") or omni_pa.get("provider_id", ""),
            **result,
        }

        status = result["ownership_status"]
        if status == OWNERSHIP_MATCHED:
            known.append(entry)
        elif status == OWNERSHIP_INFERRED:
            inferred.append(entry)
        elif status == OWNERSHIP_REQUIRES_REVIEW:
            requires_review.append(entry)
        else:
            unknown.append(entry)

    return {
        "known": known,
        "inferred": inferred,
        "requires_review": requires_review,
        "unknown": unknown,
    }
def _discover_onepassword_evidence_items() -> list[dict]:
    """
    Discover 1Password items as evidence for OmniRoute connections.

    Returns metadata only — NEVER secret values.
    Each item is classified as evidence_type="1password_evidence".
    """
    if not ensure_signed_in():
        return []

    evidence = []
    search_terms = ["api", "login", "account", "key", "token"]
    seen_ids = set()

    for term in search_terms:
        try:
            items = search_items(term)
        except Exception:
            continue

        for item in items:
            item_id = item.get("id")
            if item_id in seen_ids:
                continue
            seen_ids.add(item_id)

            vault = item.get("vault", {})
            if isinstance(vault, dict):
                vault_name = vault.get("name", vault.get("id", "?"))
            else:
                vault_name = vault or "?"

            username = (
                item.get("additional", {}).get("username") or
                item.get("additional", {}).get("email") or
                item.get("username") or
                item.get("email")
            )

            title = item.get("title", "")
            provider_id = _match_provider_from_title(title)

            evidence.append({
                "item_id": item_id,
                "title": title,
                "vault": vault_name,
                "category": item.get("category", ""),
                "username": username,  # may be None — that's OK
                "provider_id": provider_id,
                "evidence_type": "1password_evidence",
                "confidence": "low",
            })

    return evidence


def _match_provider_from_title(title: str) -> str:
    """
    Match a 1Password item title to a catalog provider_id.

    This identifies the PROVIDER, not the OWNER. A match here is
    evidence that the user *may* have an account, but does NOT prove
    ownership of any specific OmniRoute connection.
    """
    if not title:
        return ""
    title_lower = title.lower()
    catalog = load_catalog()
    for p in get_all_providers(catalog):
        pid = p["id"].lower()
        pname = p.get("name", "").lower()
        if pid in title_lower or pname in title_lower:
            return p["id"]
    return ""


# ── Review Queue ────────────────────────────────────────────────────────

def build_review_queue(
    ownership_results: dict | None = None,
    omni_providers: list[dict] | None = None,
    state: dict | None = None,
    catalog: dict | None = None,
) -> list[dict]:
    """
    Build a queue of connections requiring user review.

    Items are added to the queue when:
      - 1Password evidence exists but no deterministic ownership match (requires_review)
      - Multiple possible ownership matches exist (ambiguous)
      - Provider has insufficient evidence (unknown) but user should be prompted

    Each queue item includes all evidence needed for the user to make
    an informed decision.
    """
    if ownership_results is None:
        if omni_providers is None:
            from adapters.omniroute import get_connected_providers
            omni_providers = get_connected_providers() if is_running() else []
        ownership_results = match_all_ownerships(omni_providers, state=state, catalog=catalog)

    queue = []

    # requires_review items always go in the queue
    for entry in ownership_results.get("requires_review", []):
        queue.append({
            "review_type": "provider_ownership",
            "provider_id": entry.get("provider_id"),
            "connection_id": entry.get("connection_id"),
            "auth_type": entry.get("auth_type"),
            "candidate_identities": [],
            "evidence": entry.get("evidence", []),
            "reason": "1Password evidence exists but no deterministic ownership match",
            "current_status": OWNERSHIP_REQUIRES_REVIEW,
        })

    # Unknown items with 1Password evidence go in the queue
    for entry in ownership_results.get("unknown", []):
        if entry.get("evidence"):
            queue.append({
                "review_type": "provider_ownership",
                "provider_id": entry.get("provider_id"),
                "connection_id": entry.get("connection_id"),
                "auth_type": entry.get("auth_type"),
                "candidate_identities": [],
                "evidence": entry.get("evidence", []),
                "reason": "Connection observed but ownership cannot be established",
                "current_status": OWNERSHIP_UNKNOWN,
            })

    return queue


# ── Explicit Ownership Confirmation ─────────────────────────────────────

def confirm_ownership(
    connection_id: str,
    external_account_id: str | None = None,
    identity_id: str | None = None,
    state: dict | None = None,
    catalog: dict | None = None,
) -> dict:
    """
    Explicitly confirm ownership of an OmniRoute connection.

    This is the ONLY way to upgrade:
      requires_review → known
      unknown → known

    Requirements:
      - Explicit user confirmation (this function is only called after user says "yes")
      - Records confirmation timestamp
      - Records match_method = "user_confirmed"
      - Records confidence = "high"
      - Preserves original observation metadata
      - Does not modify unrelated accounts

    NEVER retrieves credentials or secrets.

    Args:
        connection_id: The OmniRoute connection UUID
        external_account_id: Optional link to an ExternalAccount
        identity_id: Optional link to an Identity

    Returns:
        The updated provider account record.
    """
    if state is None:
        state = load_state()
    if catalog is None:
        catalog = load_catalog()

    # Find the provider account with matching connection_id
    updated = False
    for pa in state.get("provider_accounts", []):
        if pa.get("omniroute_account_id") == connection_id or \
           pa.get("metadata", {}).get("connection_id") == connection_id:
            # Preserve original observation metadata
            # Only update ownership fields
            pa["ownership_status"] = OWNERSHIP_MATCHED
            pa["match_method"] = "user_confirmed"
            pa["match_confidence"] = "high"
            pa["identity_id"] = identity_id
            pa["external_account_id"] = external_account_id
            pa["confirmed_at"] = now_iso()
            updated = True
            break

    if not updated:
        # No existing provider account — this shouldn't normally happen
        # during confirmation, but handle gracefully
        return {
            "status": "error",
            "message": f"No provider account found for connection_id: {connection_id}",
        }

    save_state(state)
    return {
        "status": "confirmed",
        "connection_id": connection_id,
        "ownership_status": OWNERSHIP_MATCHED,
        "match_method": "user_confirmed",
        "match_confidence": "high",
        "identity_id": identity_id,
        "external_account_id": external_account_id,
        "confirmed_at": pa["confirmed_at"],
    }


# ── Identity Bootstrap ──────────────────────────────────────────────────

def add_identity(
    identity_type: str,
    value: str,
    label: str | None = None,
    state: dict | None = None,
) -> dict:
    """
    Add a new user-declared identity to local state.

    This is for explicitly user-declared identities (e.g., "I got a new phone number +15551234567").

    The identity is added with source="user_declared" and confidence="high".

    Does NOT:
      - Register any accounts
      - Send verification
      - Create any external accounts
      - Retrieve any credentials
    """
    if state is None:
        state = load_state()

    # Check for duplicates
    existing = [i for i in state.get("identities", []) if i.get("value") == value]
    if existing:
        return {
            "status": "exists",
            "identity": existing[0],
            "message": "Identity already exists in local state",
        }

    identity_id = f"identity_{identity_type}_{value.replace('@', '_').replace('+', '').replace('-', '').replace('.', '_')[:20]}"
    new_identity = {
        "id": identity_id,
        "type": identity_type,
        "label": label or value,
        "value": value,
        "created_at": now_iso(),
        "status": "available",
        "verification": {},
        "constraints": [],
        "source": "user_declared",
        "verified": False,
        "metadata": {"consumed_for": []},
    }

    state.setdefault("identities", []).append(new_identity)
    save_state(state)

    return {
        "status": "created",
        "identity": new_identity,
    }


def plan_new_phone(phone_number: str, state: dict | None = None, catalog: dict | None = None) -> dict:
    """
    Plan for a new phone number — does NOT perform registration.

    Distinguishes three cases:
      1. NEW_PHONE_IDENTITY — phone is not in local state
      2. UPDATE_EXISTING_PHONE — phone exists but is consumed/retired
      3. PHONE_USED_BY_EXISTING_ACCOUNT — phone is already linked to an account

    No SMS or verification occurs during planning.
    The phone identity is added to a planning copy of state (not saved).
    """
    from .planner import plan_new_phone as _planner_plan_new_phone
    return _planner_plan_new_phone(phone_number, state, catalog)
