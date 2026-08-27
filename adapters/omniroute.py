"""
omniroute.py — OmniRoute adapter.

Interacts with the local OmniRoute instance at localhost:20128.

Supports:
- get_connected_providers(): list providers connected in OmniRoute
- get_provider(provider_id): get details for a specific provider
- connect_provider(...): connect a new provider account
- verify_provider(provider_id): test a provider connection
- generate_import_record(...): produce an OmniRoute import record (JSON/CSV)

The adapter reads the OmniRoute API token from:
1. Environment variable OMNIR_TOKEN
2. ~/.omniroute/config.json (contexts.local-auth.accessToken)
3. ~/.hermes/.env file
4. Fallback to ~/.hermes/config.yaml model.api_key field
"""

from __future__ import annotations

import json
import os
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any

OMNIROUTE_BASE = "http://localhost:20128"
TOKEN_ENV = "OMNIR_TOKEN"
ENV_FILE = Path.home() / ".hermes" / ".env"
OMNIROUTE_CONFIG = Path.home() / ".omniroute" / "config.json"


# ── Security helpers ─────────────────────────────────────────────────────
# Patterns that indicate a field might contain a raw secret value.
# "auth" is intentionally excluded — authType/auth_type are safe field names.
_SENSITIVE_PATTERNS = ("key", "token", "secret", "password", "pass", "credential", "cookie")

def _is_sensitive_key(key: str) -> bool:
    """Check if a key name might contain sensitive data."""
    kl = key.lower()
    return any(p in kl for p in _SENSITIVE_PATTERNS)


# ── API ──────────────────────────────────────────────────────────────────

def _get_token() -> str | None:
    """Get OmniRoute API token from (in priority order):

    1. Environment variable OMNIR_TOKEN
    2. ~/.omniroute/config.json (contexts.local-auth.accessToken or .default.accessToken)
    3. ~/.hermes/.env file
    4. ~/.hermes/config.yaml model.api_key field
    """
    token = os.environ.get(TOKEN_ENV)
    if token:
        return token

    # Try ~/.omniroute/config.json (the OmniRoute CLI's own config)
    if OMNIROUTE_CONFIG.exists():
        try:
            import json as _json
            cfg = _json.loads(OMNIROUTE_CONFIG.read_text())
            contexts = cfg.get("contexts", {})
            current = cfg.get("currentContext")
            # Try current context first, then local-auth, then default
            for ctx_name in [current, "local-auth", "default-local", "default"]:
                ctx = contexts.get(ctx_name, {})
                token = ctx.get("accessToken") or ctx.get("apiKey")
                if token:
                    return token
        except Exception:
            pass

    # Try .env file
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            line = line.strip()
            if line.startswith(f"{TOKEN_ENV}="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")

    # Try config.yaml
    import yaml
    config_path = Path.home() / ".hermes" / "config.yaml"
    if config_path.exists():
        try:
            with open(config_path) as f:
                config = yaml.safe_load(f)
            token = config.get("model", {}).get("api_key", "")
            if token:
                return token
        except Exception:
            pass

    return None


def _api_request(method: str, path: str, data: dict | None = None) -> dict | None:
    """Make an API request to OmniRoute."""
    token = _get_token()
    url = f"{OMNIROUTE_BASE}{path}"

    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    body = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=body, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            if resp.status in (200, 201, 204):
                content = resp.read().decode("utf-8")
                if content:
                    return json.loads(content)
                return {"status": "ok"}
            else:
                return {"error": f"HTTP {resp.status}", "status_code": resp.status}
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}", "status_code": e.code,
                "detail": e.read().decode("utf-8")[:500]}
    except urllib.error.URLError as e:
        return {"error": f"Connection failed: {e.reason}", "status": "connection_error"}
    except Exception as e:
        return {"error": str(e), "status": "unknown_error"}


def is_running() -> bool:
    """Check if OmniRoute is running and reachable."""
    result = _api_request("GET", "/api/providers")
    if result is None:
        return False
    if isinstance(result, dict) and ("error" in result or "status_code" in result):
        return False
    return True


def get_connected_providers() -> list[dict]:
    """
    Get all providers connected in OmniRoute.

    Returns a list of provider dicts. Each dict preserves the raw OmniRoute
    response fields plus a normalized 'provider_id' for consistent matching.

    Normalized fields:
    - provider_id: lowercased provider identifier (from 'provider' or 'id')
    - auth_type: mapped from 'authType' (oauth, apikey → api_key)
    - connection_id: the OmniRoute UUID (preserved for matching)

    Raw fields from the API are preserved in 'raw' for metadata that is safe
    to persist (display names, test status, priority, etc.).
    """
    result = _api_request("GET", "/api/providers")
    if result is None or isinstance(result, dict) and "error" in result:
        return []

    if isinstance(result, list):
        connections = result
    elif isinstance(result, dict):
        # OmniRoute returns {"connections": [...], "total": N}
        connections = result.get("connections") or result.get("providers", []) or result.get("data", [])
    else:
        return []

    # Normalize each connection
    normalized = []
    for p in connections:
        pid = (p.get("provider") or p.get("id") or p.get("name", "")).lower()
        auth_type_raw = p.get("authType") or p.get("auth_type") or "unknown"
        # Map OmniRoute authType to our schema: apikey → api_key
        auth_type = "api_key" if auth_type_raw == "apikey" else auth_type_raw

        entry = {
            "provider_id": pid,
            "provider": p.get("provider", pid),
            "auth_type": auth_type,
            "auth_type_raw": auth_type_raw,
            "connection_id": p.get("id"),
            "display_name": p.get("name"),
            "priority": p.get("priority"),
            "is_active": p.get("isActive", p.get("active")),
            "test_status": p.get("testStatus"),
        }
        # Preserve any other safe metadata
        for k, v in p.items():
            if k not in entry and not _is_sensitive_key(k):
                entry[k] = v
        normalized.append(entry)

    return normalized


def get_provider(account_id: str | None = None, provider_id: str | None = None) -> dict | None:
    """
    Get details for a specific provider in OmniRoute.

    Can be looked up by OmniRoute account_id or by provider identifier.
    """
    if account_id:
        result = _api_request("GET", f"/api/providers/{account_id}")
        return result if result else None
    elif provider_id:
        result = _api_request("GET", f"/api/providers/alias/{provider_id}")
        return result if result else None
    return None


def verify_provider(provider_id: str) -> bool:
    """Test if a provider connection is working."""
    result = _api_request("POST", f"/api/providers/{provider_id}/test")
    if result and result.get("success") is True:
        return True
    if result and result.get("status") == "ok":
        return True
    return False


def connect_provider(provider_id: str, credential: dict, name: str | None = None) -> dict:
    """
    Connect a provider to OmniRoute.

    Args:
        provider_id: The OmniRoute provider identifier (e.g. 'openai', 'anthropic')
        credential: Dict with auth info (api_key, base_url, etc.)
        name: Optional alias for the connection

    Returns: dict with success status and connection details.
    """
    payload = {
        "auth": credential,
        "name": name or provider_id,
    }
    result = _api_request("POST", f"/api/providers/{provider_id}", data=payload)
    return result or {}


def find_existing_connection(provider_id: str, account_identifier: str | None = None) -> dict | None:
    """
    Find an existing OmniRoute connection for a provider.

    Uses provider_id matching and optionally account_identifier
    (the provider's account ID) to find a matching connection.

    Returns the connection dict or None.
    """
    connections = get_connected_providers()
    for conn in connections:
        conn_pid = (conn.get("provider_id") or "").lower()
        if conn_pid == provider_id.lower():
            # If account_identifier is provided, check further
            if account_identifier:
                # Check if the connection name matches the account identifier
                display_name = conn.get("display_name", "")
                if account_identifier in display_name:
                    return conn
                # Also check raw connection data
                raw = conn.get("raw", {})
                raw_name = raw.get("name", "") if isinstance(raw, dict) else ""
                if account_identifier in raw_name:
                    return conn
            else:
                return conn
    return None


def rename_provider(connection_id: str, new_name: str) -> dict:
    """
    Rename an existing OmniRoute provider connection.

    Phase 8 discovered:
    - PATCH /api/providers/{id} returns 405 (Method Not Allowed)
    - PUT /api/providers/{id} works for updates

    This function uses PUT (not PATCH) to update the connection name.

    Args:
        connection_id: The OmniRoute connection UUID
        new_name: The new display name for the connection

    Returns: dict with success status.
    """
    payload = {
        "name": new_name,
        # OmniRoute's PUT endpoint for provider updates
    }
    result = _api_request("PUT", f"/api/providers/{connection_id}", data=payload)
    if result is None:
        return {"error": "No response from OmniRoute"}
    if isinstance(result, dict) and "error" in result:
        return result
    return {"success": True, "connection_id": connection_id, "name": new_name}


def update_provider(connection_id: str, updates: dict) -> dict:
    """
    Update an existing OmniRoute provider connection with arbitrary fields.

    Uses PUT (not PATCH — PATCH returns 405 as discovered in Phase 8).

    Args:
        connection_id: The OmniRoute connection UUID
        updates: Dict of fields to update (e.g. {"name": "...", "priority": 1})

    Returns: dict with success status.
    """
    payload = dict(updates)
    result = _api_request("PUT", f"/api/providers/{connection_id}", data=payload)
    if result is None:
        return {"error": "No response from OmniRoute"}
    if isinstance(result, dict) and "error" in result:
        return result
    return {"success": True, "connection_id": connection_id, "updated_fields": list(updates.keys())}


def generate_import_record(provider_id: str, provider_name: str | None = None,
                           auth_type: str = "api_key",
                           credential: dict | None = None,
                           base_url: str | None = None,
                           api_mode: str = "chat_completions") -> dict:
    """
    Generate an OmniRoute import record for a provider.

    For API key providers:
    {
      "provider": "example",
      "name": "My Example",
      "auth": {"type": "apiKey", "apiKey": "..."},
      "base_url": "https://...",
      "api_mode": "chat_completions"
    }

    For OAuth providers:
    {
      "provider": "google",
      "name": "My Google",
      "auth": {"type": "oauth", "oauth": {...}}
    }
    """
    record = {
        "provider": provider_id,
        "name": provider_name or provider_id,
    }

    if auth_type == "api_key":
        record["auth"] = {
            "type": "apiKey",
            "apiKey": "PLACEHOLDER_RETRIEVED_FROM_1PASSWORD",
        }
        if base_url:
            record["base_url"] = base_url
        if api_mode:
            record["api_mode"] = api_mode
    elif auth_type == "oauth":
        record["auth"] = {
            "type": "oauth",
        }
    elif auth_type == "custom":
        record["auth"] = {
            "type": "apiKey",
            "apiKey": "PLACEHOLDER_RETRIEVED_FROM_1PASSWORD",
            "baseURL": base_url,
        }

    return record


def generate_import_file(providers: list[dict], filename: str | None = None) -> str:
    """
    Generate a JSON import file for OmniRoute's batch importer.

    Returns the path to the generated file.
    """
    import tempfile

    if filename is None:
        fd, filename = tempfile.mkstemp(suffix=".json", prefix="omniroute_import_")
        os.close(fd)

    with open(filename, "w") as f:
        json.dump(providers, f, indent=2)

    return filename


def get_model_catalog() -> list[dict]:
    """Get the available model catalog from OmniRoute."""
    result = _api_request("GET", "/v1/models")
    if result and "data" in result:
        return result["data"]
    return []


def test_connection() -> dict:
    """Test the connection to OmniRoute."""
    token = _get_token()
    if not token:
        return {"status": "no_token", "message": "No OmniRoute API token found"}

    result = _api_request("GET", "/api/providers")
    if result is None:
        return {"status": "no_response", "message": "No response from OmniRoute"}

    if "error" in result:
        if "AUTH_001" in str(result.get("error", "")):
            return {"status": "auth_error", "message": "Authentication failed — check OMNIR_TOKEN"}
        return {"status": "error", "message": str(result.get("error"))}

    if isinstance(result, list):
        return {"status": "ok", "connected_providers": len(result)}
    if isinstance(result, dict):
        providers = result.get("connections") or result.get("providers", []) or result.get("data", [])
        return {"status": "ok", "connected_providers": len(providers)}

    return {"status": "ok"}


def discover_omniroute_state(state_provider_ids: set[str] | None = None) -> dict:
    """
    Discover what OmniRoute knows about, compared to local state.

    Returns a dict with:
    - omniroute_only: provider IDs in OmniRoute but not in local state
    - state_only: provider IDs in local state but not in OmniRoute
    - matches: providers in both (with metadata + connection_id comparison)
    - all_omniroute_providers: full normalized list from OmniRoute
    - total_omniroute_providers: count
    - uncatalogued: provider IDs in OmniRoute but not in catalog
    - ownership_breakdown: {known, unknown, requires_review, inferred}
    """
    if state_provider_ids is None:
        # Lazy import to avoid circular dependency
        try:
            from engine.state import load_state  # when loaded as a package
        except ImportError:
            from ..engine.state import load_state  # when loaded as sibling
        state = load_state()
        state_provider_ids = {pa["provider_id"] for pa in state.get("provider_accounts", [])}

    omniroute_providers = get_connected_providers()

    # Extract identifiers from OmniRoute (using normalized provider_id)
    omniroute_ids = set()
    for p in omniroute_providers:
        pid = p.get("provider_id") or p.get("provider") or p.get("id") or p.get("name", "")
        if pid:
            omniroute_ids.add(pid.lower())

    # Load catalog to check which providers are known
    try:
        from engine.catalog import load_catalog
        catalog = load_catalog()
    except ImportError:
        catalog = {"providers": []}

    omniroute_only = omniroute_ids - state_provider_ids
    state_only = state_provider_ids - omniroute_ids

    # Build match metadata
    matches = []
    for p in omniroute_providers:
        pid = p.get("provider_id", "").lower()
        if pid in state_provider_ids:
            matches.append({
                "omniroute": p,
                "provider_id": pid,
                "connection_id": p.get("connection_id"),
            })

    # Identify uncatalogued providers
    catalog_ids = {p["id"] for p in catalog.get("providers", [])} if catalog else set()
    uncatalogued = [pid for pid in omniroute_ids if pid not in catalog_ids]

    # Ownership breakdown
    ownership = {"known": 0, "unknown": 0, "requires_review": 0, "inferred": 0}
    for p in omniroute_providers:
        pid = p.get("provider_id", "").lower()
        conn_id = p.get("connection_id")
        found_ownership = False
        for m in matches:
            if m.get("connection_id") == conn_id:
                found_ownership = True
                break
        if not found_ownership:
            ownership["unknown"] += 1

    return {
        "omniroute_only": sorted(omniroute_only),
        "state_only": sorted(state_only),
        "matches": matches,
        "all_omniroute_providers": omniroute_providers,
        "total_omniroute_providers": len(omniroute_providers),
        "uncatalogued": sorted(uncatalogued),
        "ownership_breakdown": ownership,
    }


# ── Adapter wrapper class ──────────────────────────────────────────────

class Adapter:
    """OmniRoute adapter wrapper — delegates to module-level functions."""

    def __init__(self):
        self.base_url = OMNIROUTE_BASE

    def is_running(self):
        return is_running()

    def get_connected_providers(self):
        return get_connected_providers()

    def get_provider(self, **kwargs):
        return get_provider(**kwargs)

    def verify_provider(self, provider_id):
        return verify_provider(provider_id)

    def connect_provider(self, **kwargs):
        return connect_provider(**kwargs)

    def find_existing_connection(self, **kwargs):
        return find_existing_connection(**kwargs)

    def rename_provider(self, **kwargs):
        return rename_provider(**kwargs)

    def update_provider(self, **kwargs):
        return update_provider(**kwargs)

    def discover_omniroute_state(self, **kwargs):
        return discover_omniroute_state(**kwargs)

    def generate_import_record(self, **kwargs):
        return generate_import_record(**kwargs)

    def generate_import_file(self, **kwargs):
        return generate_import_file(**kwargs)

    def get_model_catalog(self):
        return get_model_catalog()

    def test_connection(self):
        return test_connection()
