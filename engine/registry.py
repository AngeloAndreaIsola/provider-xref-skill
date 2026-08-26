"""
registry.py — Workflow and adapter registry.

Dynamically loads provider workflows based on auth type / provider ID.
Also provides the get_adapter() function that sync.py and other
modules use to access OmniRoute / 1Password / Browser adapters.
"""

from __future__ import annotations

from typing import Any
from pathlib import Path

from .catalog import load_catalog, get_provider
from .utils import SKILL_ROOT


# ── Workflow registry ───────────────────────────────────────────────────

# Map provider_id → workflow module name
# Falls back to auth_type-based selection if not found
_PROVIDER_WORKFLOW_MAP = {
    "google": "google",      # Google account creation cascade
    "github": "github",      # GitHub account creation cascade
    "azure": "api_key",      # Azure uses API key but needs Microsoft identity
}

_AUTH_TYPE_DEFAULTS = {
    "api_key": "api_key",
    "oauth": "oauth",
    "password": "api_key",   # Use api_key workflow for password-based (close enough)
    "pat": "api_key",
    "unknown": "oauth",      # Default to OAuth
}


def get_workflow(provider_id: str, catalog: dict | None = None) -> Any:
    """
    Get the appropriate workflow class for a provider.

    Priority:
    1. Provider-specific workflow (from _PROVIDER_WORKFLOW_MAP)
    2. Auth-type-based default workflow
    3. Generic api_key or oauth workflow
    """
    if catalog is None:
        catalog = load_catalog()

    provider = get_provider(catalog, provider_id)
    if not provider:
        return None

    auth_type = provider.get("auth_type", "unknown")

    # Check for provider-specific workflow
    wf_name = _PROVIDER_WORKFLOW_MAP.get(provider_id)
    if wf_name:
        try:
            import importlib
            mod = importlib.import_module(f"workflows.{wf_name}")
            return getattr(mod, "Workflow")()
        except (ImportError, AttributeError):
            pass

    # Fall back to auth-type-based workflow
    wf_name = _AUTH_TYPE_DEFAULTS.get(auth_type, "oauth")
    try:
        if wf_name == "api_key":
            try:
                from workflows.api_key import APIKeyWorkflow
            except ImportError:
                from ..workflows.api_key import APIKeyWorkflow
            return APIKeyWorkflow()
        elif wf_name == "oauth":
            try:
                from workflows.oauth import OAuthWorkflow
            except ImportError:
                from ..workflows.oauth import OAuthWorkflow
            return OAuthWorkflow()
    except ImportError:
        pass

    return None


def get_workflow_for_opportunity(opportunity: dict, catalog: dict | None = None) -> Any:
    """Get the workflow for an opportunity."""
    return get_workflow(opportunity["provider"], catalog)


# ── Adapter registry ────────────────────────────────────────────────────

class _AdapterRegistry:
    """Lazy-loading adapter registry."""

    _cache: dict = {}
    _adapters = {
        "omniroute": "_load_omniroute",
        "onepassword": "_load_onepassword",
        "browser": "_load_browser",
    }

    @classmethod
    def get(cls, name: str):
        """Get an adapter by name. Returns a wrapper or None."""
        if name not in cls._adapters:
            return None
        if name in cls._cache:
            return cls._cache[name]
        loader = getattr(cls, cls._adapters[name])
        adapter = loader()
        cls._cache[name] = adapter
        return adapter

    @staticmethod
    def _load_omniroute():
        try:
            from adapters.omniroute import Adapter
        except ImportError:
            from ..adapters.omniroute import Adapter
        return Adapter()

    @staticmethod
    def _load_onepassword():
        try:
            from adapters.onepassword import Adapter
        except ImportError:
            from ..adapters.onepassword import Adapter
        return Adapter()

    @staticmethod
    def _load_browser():
        try:
            from adapters.browser import Adapter
        except ImportError:
            from ..adapters.browser import Adapter
        return Adapter()

    @classmethod
    def clear_cache(cls):
        """Clear the adapter cache (useful for testing)."""
        cls._cache.clear()


def get_adapter(name: str):
    """Get an adapter by name."""
    return _AdapterRegistry.get(name)
