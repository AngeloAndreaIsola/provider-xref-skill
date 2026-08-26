"""
catalog.py — Provider catalog loader and accessor.

The catalog is the knowledge base: what providers exist, their auth types,
free tiers, signup requirements, policy classifications, and OmniRoute
compatibility.  It is versioned and treated as reference data — not
modified by sync operations.
"""

from __future__ import annotations

from typing import Any

from .utils import CATALOG_FILE, load_json, now_iso, uuid_id


def default_catalog() -> dict:
    """Return a minimal valid catalog structure."""
    return {
        "catalog_version": 1,
        "last_verified": now_iso(),
        "sources": [],
        "scoring_weights": {
            "quota_value": 15,
            "usefulness": 15,
            "downstream_capabilities": 30,
            "compatibility": 15,
            "account_freshness": 5,
            "registration_cost": -10,
            "verification_cost": -5,
            "policy_risk": -10,
        },
        "providers": [],
    }


def load_catalog() -> dict:
    """Load provider_catalog.json. Falls back to default if missing."""
    data = load_json(CATALOG_FILE, default=None)
    if data is None:
        return default_catalog()
    if "scoring_weights" not in data:
        data["scoring_weights"] = default_catalog()["scoring_weights"]
    return data


def get_provider(catalog: dict | None = None, provider_id: str | None = None) -> dict | None:
    """Look up a single provider by ID."""
    if catalog is None:
        catalog = load_catalog()
    for p in catalog.get("providers", []):
        if p["id"] == provider_id:
            return p
    return None


def get_all_providers(catalog: dict | None = None) -> list[dict]:
    """Return all providers in the catalog."""
    if catalog is None:
        catalog = load_catalog()
    return catalog.get("providers", [])


def get_providers_by_category(catalog: dict | None = None, category: str | None = None) -> list[dict]:
    """Filter providers by category (e.g. 'llm', 'tool_platform', 'oauth_idp')."""
    if catalog is None:
        catalog = load_catalog()
    providers = get_all_providers(catalog)
    if category is None:
        return providers
    return [p for p in providers if p.get("category") == category]


def get_provider_by_name(catalog: dict | None = None, name: str | None = None) -> dict | None:
    """Look up a provider by name (case-insensitive)."""
    if catalog is None:
        catalog = load_catalog()
    for p in catalog.get("providers", []):
        if p["name"].lower() == name.lower():
            return p
    return None


def get_scoring_weights(catalog: dict | None = None) -> dict:
    """Return scoring weights, falling back to defaults."""
    if catalog is None:
        catalog = load_catalog()
    return catalog.get("scoring_weights", default_catalog()["scoring_weights"])


def is_identity_provider(provider: dict) -> bool:
    """True if this provider can act as an identity provider (e.g. Google, GitHub)."""
    return provider.get("category") == "oauth_idp" and provider.get("cascades_to", []) != []


def get_downstream_providers(catalog: dict | None = None, provider_id: str | None = None) -> list[str]:
    """Return the list of provider IDs that can be unlocked by *provider_id*."""
    if catalog is None:
        catalog = load_catalog()
    p = get_provider(catalog, provider_id)
    if p:
        return p.get("cascades_to", [])
    return []


def search_providers(query: str | None = None) -> list[dict]:
    """Search for providers by name or ID."""
    catalog = load_catalog()
    results = []
    for p in catalog.get("providers", []):
        if query:
            if query.lower() in p["id"].lower() or query.lower() in p["name"].lower():
                results.append(p)
        else:
            results.append(p)
    return results
