"""
policy.py — Provider policy classification and enforcement.

Critical design principle:

Hermes should NEVER infer permission from technical possibility.

Can create another account?
    ↓
    YES
    ↓
Does provider permit it?
    ↓
    UNKNOWN
    ↓
    DO NOT AUTOMATE

Instead it reports: "Technically possible, policy unknown — manual verification required."

Each provider in the catalog has a policy classification with values:
  allowed | disallowed | restricted | unknown

For each of these dimensions:
  - multiple_accounts
  - duplicate_account_policy
  - automation_allowed
  - third_party_proxy_allowed
  - phone_reuse_allowed
"""

from __future__ import annotations

from typing import Any

from .catalog import load_catalog, get_provider


# ── Policy resolution ──────────────────────────────────────────────────

def get_policy(catalog: dict | None = None, provider_id: str | None = None) -> dict:
    """
    Get the policy dict for a provider.

    Returns a dict with keys: multiple_accounts, duplicate_account_policy,
    automation_allowed, third_party_proxy_allowed, phone_reuse_allowed.
    Missing values default to 'unknown'.
    """
    if catalog is None:
        catalog = load_catalog()
    p = get_provider(catalog, provider_id)
    if p is None:
        return _default_policy()

    policy = p.get("policy", {})
    # Fill in defaults
    defaults = _default_policy()
    for key, default_val in defaults.items():
        if key not in policy or policy[key] not in ("allowed", "disallowed", "restricted", "unknown"):
            policy[key] = default_val

    return policy


def _default_policy() -> dict[str, str]:
    return {
        "multiple_accounts": "unknown",
        "duplicate_account_policy": "unknown",
        "automation_allowed": "unknown",
        "third_party_proxy_allowed": "unknown",
        "phone_reuse_allowed": "unknown",
    }


# ── Decision helpers ───────────────────────────────────────────────────

def can_automate_registration(catalog: dict | None = None, provider_id: str | None = None) -> tuple[bool, str]:
    """
    Determine whether Hermes can automatically register for this provider.

    Rules:
    1. If automation_allowed == 'disallowed' → NEVER automate
    2. If automation_allowed == 'restricted' → manual review required
    3. If automation_allowed == 'unknown' → DO NOT AUTOMATE (report unknown)
    4. If automation_allowed == 'allowed' → can automate (subject to other checks)

    Returns (can_automate, reason).
    """
    policy = get_policy(catalog, provider_id)

    auto = policy.get("automation_allowed", "unknown")

    if auto == "disallowed":
        return False, "Provider explicitly disallows automation"
    elif auto == "restricted":
        return False, "Provider automation is restricted — manual approval required"
    elif auto == "unknown":
        return False, "Technically possible, but provider automation policy is unknown — manual verification required"
    elif auto == "allowed":
        return True, "Automation allowed per catalog policy"

    return False, "Unknown automation policy"


def can_create_multiple_accounts(catalog: dict | None = None, provider_id: str | None = None) -> tuple[bool, str]:
    """
    Determine whether multiple accounts for this provider are permitted.

    Returns (can_create_multiple, reason).
    """
    policy = get_policy(catalog, provider_id)
    ma = policy.get("multiple_accounts", "unknown")

    if ma == "disallowed":
        return False, "Provider disallows multiple accounts"
    elif ma == "restricted":
        return False, "Provider restricts multiple accounts — manual review required"
    elif ma == "unknown":
        return False, "Multiple account policy is unknown — manual verification required"
    elif ma == "allowed":
        return True, "Multiple accounts allowed per catalog policy"

    return False, "Unknown multiple-accounts policy"


def can_use_third_party_proxy(catalog: dict | None = None, provider_id: str | None = None) -> tuple[bool, str]:
    """
    Determine whether a third-party proxy/harness is allowed for this provider.
    """
    policy = get_policy(catalog, provider_id)
    tp = policy.get("third_party_proxy_allowed", "unknown")

    if tp == "disallowed":
        return False, "Provider disallows third-party proxy/harness"
    elif tp == "restricted":
        return False, "Provider proxy usage is restricted — manual review required"
    elif tp == "unknown":
        return False, "Third-party proxy policy is unknown — manual verification required"
    elif tp == "allowed":
        return True, "Third-party proxy allowed per catalog policy"

    return False, "Unknown proxy policy"


def can_reuse_phone(catalog: dict | None = None, provider_id: str | None = None) -> tuple[bool, str]:
    """Determine whether a phone number can be reused for verification."""
    policy = get_policy(catalog, provider_id)
    phone = policy.get("phone_reuse_allowed", "unknown")

    if phone == "disallowed":
        return False, "Provider disallows phone number reuse"
    elif phone == "restricted":
        return False, "Provider phone reuse is restricted"
    elif phone == "unknown":
        return False, "Phone reuse policy is unknown"
    elif phone == "allowed":
        return True, "Phone reuse allowed"

    return False, "Unknown phone reuse policy"


# ── Policy status for opportunities ────────────────────────────────────

def get_opportunity_policy_status(catalog: dict | None = None, provider_id: str | None = None) -> str:
    """
    Return the overall policy status for an opportunity.

    'allowed' if all relevant policies are explicitly 'allowed'.
    'disallowed' if any relevant policy is 'disallowed'.
    'restricted' if any policy is 'restricted' (but none disallowed).
    'unknown' if any relevant policy is 'unknown' (and no disallowed/restricted).
    """
    policy = get_policy(catalog, provider_id)

    statuses = [
        policy.get("automation_allowed", "unknown"),
        policy.get("multiple_accounts", "unknown"),
        policy.get("third_party_proxy_allowed", "unknown"),
        policy.get("phone_reuse_allowed", "unknown"),
        policy.get("duplicate_account_policy", "unknown"),
    ]

    if any(s == "disallowed" for s in statuses):
        return "disallowed"
    if any(s == "restricted" for s in statuses):
        return "restricted"
    if any(s == "unknown" for s in statuses):
        return "unknown"
    if all(s == "allowed" for s in statuses):
        return "allowed"
    return "unknown"


def policy_summary(catalog: dict | None = None, provider_id: str | None = None) -> dict[str, str]:
    """Return a human-readable policy summary for a provider."""
    policy = get_policy(catalog, provider_id)
    p = get_provider(catalog, provider_id)
    name = p["name"] if p else provider_id

    return {
        "provider": name,
        "provider_id": provider_id,
        "multiple_accounts": policy.get("multiple_accounts", "unknown"),
        "free_tier": p.get("free_tier", {}).get("enabled", False) if p else False,
        "duplicate_account_policy": policy.get("duplicate_account_policy", "unknown"),
        "automation_allowed": policy.get("automation_allowed", "unknown"),
        "third_party_proxy_allowed": policy.get("third_party_proxy_allowed", "unknown"),
        "phone_reuse_allowed": policy.get("phone_reuse_allowed", "unknown"),
    }


# ── Policy-based risk scoring ──────────────────────────────────────────

def policy_risk_score(catalog: dict | None = None, provider_id: str | None = None) -> int:
    """
    Return a policy risk score (0-30). Higher = more risk.

    unknown → 25 (high risk — don't assume permission)
    restricted → 15 (medium risk)
    allowed → 0 (no penalty)
    disallowed → 30 (block entirely)
    """
    policy = get_policy(catalog, provider_id)

    risk = 0
    for key in ("automation_allowed", "multiple_accounts",
                "third_party_proxy_allowed", "phone_reuse_allowed",
                "duplicate_account_policy"):
        val = policy.get(key, "unknown")
        if val == "disallowed":
            risk += 30
        elif val == "restricted":
            risk += 15
        elif val == "unknown":
            risk += 25
        # 'allowed' adds 0

    # Cap at 50
    return min(risk, 50)
