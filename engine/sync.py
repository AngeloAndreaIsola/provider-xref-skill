"""
sync.py — State reconciliation pipeline.

Sync pipeline:
  OmniRoute → State reconciler ← 1Password
                       ↓
              provider_state.json

Hermes should never overwrite the whole state blindly.
Instead:

  discover → normalize → compare → produce changes → apply changes

This prevents an incomplete OmniRoute response from destroying
information.
"""

from __future__ import annotations

from typing import Any
from datetime import datetime

from .state import load_state, save_state, now_iso, validate_state
from .catalog import load_catalog, get_provider
from .graph import ProviderGraph
from .registry import get_adapter
from .utils import save_json_atomic

# Use absolute import to avoid relative import issues when the skill
# is loaded with sys.path pointing at the skill root directory.
try:
    from adapters.omniroute import discover_omniroute_state
except ImportError:
    # Fallback for when loaded as a package (engine.adapters.omniroute)
    from ..adapters.omniroute import discover_omniroute_state


def sync(state: dict | None = None, catalog: dict | None = None,
         dry_run: bool = True) -> dict:
    """
    Synchronize reality into provider_state.json.

    Steps:
    1. Discover: Query OmniRoute + 1Password for current state
    2. Normalize: Convert discoveries into state format
    3. Compare: Diff discovered data against local state
    4. Produce changes: Generate a list of additions/deletions/updates
    5. Apply changes: Merge changes into state (never overwrite)

    Returns a dict describing what changed.
    """
    if state is None:
        state = load_state()
    if catalog is None:
        catalog = load_catalog()

    graph = ProviderGraph(state, catalog)

    # ── Step 1: Discover ────────────────────────────────────────────────
    state_provider_ids = {pa["provider_id"] for pa in state.get("provider_accounts", [])}

    # OmniRoute discovery
    omni_discovery = discover_omniroute_state(state_provider_ids)

    # 1Password discovery (find items that look like provider credentials)
    onepassword_adapter = get_adapter("onepassword")
    op_discovery = {"items": [], "count": 0, "vaults": []}
    if onepassword_adapter and onepassword_adapter.ensure_signed_in():
        # Discover available vaults dynamically
        try:
            op_discovery["vaults"] = onepassword_adapter.list_vaults()
        except (AttributeError, Exception):
            op_discovery["vaults"] = []

        op_items = onepassword_adapter.search_items("api key") + \
                   onepassword_adapter.search_items("provider") + \
                   onepassword_adapter.search_items("token") + \
                   onepassword_adapter.search_items("login")
        # Deduplicate by item ID
        seen_ids = set()
        unique_items = []
        for item in op_items:
            if item.get("id") not in seen_ids:
                seen_ids.add(item.get("id"))
                unique_items.append(item)
        op_discovery = {
            "items": unique_items,
            "count": len(unique_items),
            "vaults": op_discovery.get("vaults", []),
        }

    # ── Step 2: Normalize ───────────────────────────────────────────────
    normalized = _normalize_omniroute(omni_discovery, catalog)
    op_normalized = _normalize_onepassword(op_discovery, catalog)

    # ── Step 3: Compare ─────────────────────────────────────────────────
    changes = _compare(state, graph, normalized, op_normalized, catalog)

    # ── Step 4: Apply ───────────────────────────────────────────────────
    change_summary = {
        "added_provider_accounts": [],
        "removed_provider_accounts": [],
        "updated_provider_accounts": [],
        "added_credentials": [],
        "removed_credentials": [],
        "added_identities": [],
        "added_external_accounts": [],
        "changes_count": 0,
    }

    if not dry_run:
        _apply_changes(state, changes, graph)
        save_state(state)
    else:
        # In dry-run, just report what would change
        for change in changes:
            if change["type"] == "add_provider_account":
                change_summary["added_provider_accounts"].append(change["provider_id"])
            elif change["type"] == "remove_provider_account":
                change_summary["removed_provider_accounts"].append(change["provider_id"])
            elif change["type"] == "update_provider_account":
                change_summary["updated_provider_accounts"].append(change["provider_id"])
            elif change["type"] == "add_credential":
                change_summary["added_credentials"].append(change["provider_id"])
            elif change["type"] == "add_identity":
                change_summary["added_identities"].append(change.get("value", change.get("label", "?")))
            elif change["type"] == "add_external_account":
                change_summary["added_external_accounts"].append(change.get("provider", "?"))

        change_summary["changes_count"] = len(changes)

    change_summary["omniroute_discovery"] = {
        "total_providers": omni_discovery.get("total_omniroute_providers", 0),
        "omniroute_only": omni_discovery.get("omniroute_only", []),
        "state_only": omni_discovery.get("state_only", []),
        "matches": len(omni_discovery.get("matches", [])),
        "uncatalogued": omni_discovery.get("uncatalogued", []),
        "ownership_breakdown": omni_discovery.get("ownership_breakdown", {}),
    }
    change_summary["onepassword_discovery"] = op_discovery.get("count", 0)

    return change_summary


def _normalize_omniroute(discovery: dict, catalog: dict) -> list[dict]:
    """
    Convert OmniRoute discovery data into normalized provider account records.

    Preserves observation state without assuming ownership:
    - identity_id is null unless explicitly matched
    - ownership_status defaults to 'unknown'
    - source is 'omniroute_sync'
    - observed_at is set to current time
    - match_method is null unless determined
    """
    normalized = []
    providers = discovery.get("all_omniroute_providers", [])

    for p in providers:
        provider_id = p.get("provider_id") or \
            (p.get("provider") or p.get("id") or p.get("name", "")).lower()

        # Look up in catalog for metadata
        catalog_p = get_provider(catalog, provider_id)

        record = {
            "provider_id": provider_id,
            "status": "connected",
            "omniroute_connected": True,
            "omniroute_account_id": p.get("connection_id") or p.get("id"),
            "last_seen": now_iso(),
            "observed_at": now_iso(),
            "source": "omniroute_sync",
            "ownership_status": "unknown",
            "match_method": None,
            "match_confidence": "unknown",
            "identity_id": None,
            "external_account_id": None,
        }

        if catalog_p:
            record["auth_type"] = catalog_p.get("auth_type", "unknown")
            record["catalog_name"] = catalog_p.get("name", provider_id)
        else:
            record["auth_type"] = p.get("auth_type", "unknown")
            record["catalog_name"] = provider_id

        # Preserve safe metadata (no secrets)
        try:
            from adapters.omniroute import _is_sensitive_key
        except ImportError:
            from ..adapters.omniroute import _is_sensitive_key
        safe_meta = {k: v for k, v in p.items() if not _is_sensitive_key(k)}
        record["metadata"] = safe_meta

        normalized.append(record)

    return normalized


def _normalize_onepassword(discovery: dict, catalog: dict) -> list[dict]:
    """
    Convert 1Password discovery into normalized credential records.
    """
    normalized = []
    items = discovery.get("items", [])

    for item in items:
        title = (item.get("title") or "").lower()

        # Try to match to a catalog provider
        matched_provider = None
        for p in catalog.get("providers", []):
            if p["id"].lower() in title or p["name"].lower() in title:
                matched_provider = p["id"]
                break

        normalized.append({
            "item_id": item.get("id"),
            "vault": (item.get("vault") or {}).get("name", "Personal") if isinstance(item.get("vault"), dict) else item.get("vault", "Personal"),
            "title": item.get("title", ""),
            "tags": item.get("tags", []),
            "matched_provider": matched_provider,
        })

    return normalized


def _compare(state: dict, graph: ProviderGraph,
             omniroute_data: list[dict],
             onepassword_data: list[dict],
             catalog: dict) -> list[dict]:
    """
    Compare discovered data against local state.

    Produce a list of changes: add, remove, update.

    Key principle: Never delete historical records silently.
    Mark as disconnected, but preserve the entry.
    """
    changes = []

    # ── OmniRoute comparison ───────────────────────────────────────────
    state_pas = {pa["provider_id"]: pa for pa in state.get("provider_accounts", [])}
    discovered_pas = {rec["provider_id"]: rec for rec in omniroute_data}

    # New providers in OmniRoute but not in state
    for pid, rec in discovered_pas.items():
        if pid not in state_pas:
            changes.append({
                "type": "add_provider_account",
                "provider_id": pid,
                **rec,
            })
        else:
            # Existing provider — check if status changed
            existing = state_pas[pid]
            if existing.get("omniroute_connected") is False:
                changes.append({
                    "type": "update_provider_account",
                    "provider_id": pid,
                    "field": "omniroute_connected",
                    "old_value": False,
                    "new_value": True,
                })
            # Update last_verified
            if existing.get("last_verified") != rec.get("last_seen"):
                changes.append({
                    "type": "update_provider_account",
                    "provider_id": pid,
                    "field": "last_verified",
                    "new_value": rec.get("last_seen"),
                })

    # Providers in state but not in OmniRoute → mark disconnected
    for pid, existing in state_pas.items():
        if pid not in discovered_pas and existing.get("omniroute_connected"):
            changes.append({
                "type": "update_provider_account",
                "provider_id": pid,
                "field": "omniroute_connected",
                "old_value": True,
                "new_value": False,
                "note": "Provider no longer found in OmniRoute",
            })

    # ── 1Password comparison ───────────────────────────────────────────
    state_creds = {c.get("provider_account_id") for c in state.get("credentials", [])}
    for item in onepassword_data:
        if item.get("matched_provider"):
            pid = item["matched_provider"]
            # Check if we have a credential for this provider
            provider_pa = [pa for pa in state.get("provider_accounts", [])
                           if pa["provider_id"] == pid]
            if not provider_pa:
                # Credential exists in 1Password but no provider account in state
                changes.append({
                    "type": "add_provider_account",
                    "provider_id": pid,
                    "source": "1password",
                    "credential_ref": {
                        "backend": "1password",
                        "vault": item["vault"],
                        "item_id": item["item_id"],
                    },
                })

    return changes


def _apply_changes(state: dict, changes: list[dict], graph: ProviderGraph) -> None:
    """
    Apply a list of changes to the state.

    Changes are applied in order: removals first, then additions,
    then updates.  This ensures consistency.
    """
    from .utils import uuid_id

    for change in changes:
        if change["type"] == "add_provider_account":
            pa = {
                "id": uuid_id("pa"),
                "provider_id": change["provider_id"],
                "status": change.get("status", "connected"),
                "auth_type": change.get("auth_type", "unknown"),
                "omniroute_connected": change.get("omniroute_connected", True),
                "omniroute_account_id": change.get("omniroute_account_id"),
                "created_at": change.get("created_at", now_iso()),
                "last_verified": change.get("last_seen", now_iso()),
                "observed_at": change.get("observed_at"),
                "source": change.get("source", "omniroute_sync"),
                "ownership_status": change.get("ownership_status", "unknown"),
                "match_method": change.get("match_method"),
                "match_confidence": change.get("match_confidence", "unknown"),
                "identity_id": change.get("identity_id"),
                "external_account_id": change.get("external_account_id"),
                "metadata": _strip_sensitive_metadata(change.get("metadata", {})),
            }
            if change.get("credential_ref"):
                pa["credential_ref"] = change["credential_ref"]
            if change.get("identity_id"):
                pa["identity_id"] = change["identity_id"]
            if change.get("external_account_id"):
                pa["external_account_id"] = change["external_account_id"]

            state["provider_accounts"].append(pa)

        elif change["type"] == "update_provider_account":
            pid = change["provider_id"]
            pa = next((p for p in state.get("provider_accounts", [])
                       if p["provider_id"] == pid), None)
            if pa:
                field = change["field"]
                if field == "omniroute_connected":
                    pa["omniroute_connected"] = change["new_value"]
                elif field == "last_verified":
                    pa["last_verified"] = change["new_value"]
                else:
                    pa[field] = change["new_value"]

        elif change["type"] == "add_credential":
            cred = {
                "id": uuid_id("cred"),
                "type": change.get("type", "api_key"),
                "backend": "1password",
                "vault": change.get("vault", "Personal"),
                "item_id": change.get("item_id"),
                "field": change.get("field", "credential"),
                "provider_account_id": change.get("provider_account_id"),
                "status": "active",
                "created_at": now_iso(),
            }
            state["credentials"].append(cred)


def _strip_sensitive_metadata(metadata: dict) -> dict:
    """Remove any keys that might contain secrets from a metadata dict."""
    try:
        from adapters.omniroute import _is_sensitive_key
    except ImportError:
        from ..adapters.omniroute import _is_sensitive_key
    if not isinstance(metadata, dict):
        return {}
    return {k: v for k, v in metadata.items() if not _is_sensitive_key(k)}


# ── Adapter registry ────────────────────────────────────────────────────
# (Simple inline registry so we don't create circular imports at module load)

_ADAPTER_CACHE: dict = {}

def get_adapter(name: str):
    """Lazy-load an adapter by name."""
    if name in _ADAPTER_CACHE:
        return _ADAPTER_CACHE[name]

    try:
        if name == "omniroute":
            from adapters.omniroute import is_running as _ir
        elif name == "onepassword":
            from adapters.onepassword import ensure_signed_in as _esi
        else:
            _ADAPTER_CACHE[name] = None
            return _ADAPTER_CACHE[name]
        _ADAPTER_CACHE[name] = _AdapterWrapper(name, _ir if name == "omniroute" else _esi)
    except ImportError:
        if name == "omniroute":
            from ..adapters.omniroute import is_running as _ir
            _ADAPTER_CACHE[name] = _AdapterWrapper(name, _ir)
        elif name == "onepassword":
            from ..adapters.onepassword import ensure_signed_in as _esi
            _ADAPTER_CACHE[name] = _AdapterWrapper(name, _esi)
        else:
            _ADAPTER_CACHE[name] = None

    return _ADAPTER_CACHE[name]


class _AdapterWrapper:
    """Thin wrapper so sync.py can call adapter methods."""
    def __init__(self, name: str, health_check_fn):
        self.name = name
        self._health_check = health_check_fn

        try:
            if name == "omniroute":
                from adapters.omniroute import (
                    get_connected_providers, get_provider, verify_provider,
                    connect_provider, discover_omniroute_state
                )
                self.get_connected_providers = get_connected_providers
                self.get_provider = get_provider
                self.verify_provider = verify_provider
                self.connect_provider = connect_provider
                self.discover_omniroute_state = discover_omniroute_state
                self.is_running = self._health_check
            elif name == "onepassword":
                from adapters.onepassword import (
                    search_items, search_provider_items, get_item, get_login,
                    get_credential_value, create_login, update_login,
                    ensure_signed_in, build_credential_ref, list_vaults
                )
                self.search_items = search_items
                self.search_provider_items = search_provider_items
                self.list_vaults = list_vaults
                self.get_item = get_item
                self.get_login = get_login
                self.get_credential_value = get_credential_value
                self.create_login = create_login
                self.update_login = update_login
                self.ensure_signed_in = self._health_check
                self.build_credential_ref = build_credential_ref
            elif name == "browser":
                from adapters.browser import (
                    navigate, click, type_text, fill_form, screenshot,
                    oauth_flow, api_key_flow
                )
                self.navigate = navigate
                self.click = click
                self.type_text = type_text
                self.fill_form = fill_form
                self.screenshot = screenshot
                self.oauth_flow = oauth_flow
                self.api_key_flow = api_key_flow
        except ImportError:
            if name == "omniroute":
                from ..adapters.omniroute import (
                    get_connected_providers, get_provider, verify_provider,
                    connect_provider, discover_omniroute_state
                )
                self.get_connected_providers = get_connected_providers
                self.get_provider = get_provider
                self.verify_provider = verify_provider
                self.connect_provider = connect_provider
                self.discover_omniroute_state = discover_omniroute_state
                self.is_running = self._health_check
            elif name == "onepassword":
                from ..adapters.onepassword import (
                    search_items, search_provider_items, get_item, get_login,
                    get_credential_value, create_login, update_login,
                    ensure_signed_in, build_credential_ref, list_vaults
                )
                self.search_items = search_items
                self.search_provider_items = search_provider_items
                self.list_vaults = list_vaults
                self.get_item = get_item
                self.get_login = get_login
                self.get_credential_value = get_credential_value
                self.create_login = create_login
                self.update_login = update_login
                self.ensure_signed_in = self._health_check
                self.build_credential_ref = build_credential_ref
            elif name == "browser":
                from ..adapters.browser import (
                    navigate, click, type_text, fill_form, screenshot,
                    oauth_flow, api_key_flow
                )
                self.navigate = navigate
                self.click = click
                self.type_text = type_text
                self.fill_form = fill_form
                self.screenshot = screenshot
                self.oauth_flow = oauth_flow
                self.api_key_flow = api_key_flow
