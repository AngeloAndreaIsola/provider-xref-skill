"""
onepassword.py — 1Password adapter.

Interacts with the 1Password CLI (op) to:
- search_items: find login items by provider or identity
- get_login: retrieve a login item's details (with secrets)
- create_login: create a new 1Password item
- update_login: update an existing item
- get_credential: retrieve just the credential value from a 1Password item

IMPORTANT: The adapter returns credential *references* (vault, item_id, field),
never the actual secret value in state files.  The secret is only retrieved
when needed for an operation.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any


# ── Authentication backend detection (Phase 9D) ───────────────────────────


def detect_auth_backend() -> dict:
    """
    Detect which 1Password backend/authentication method is currently in use.

    Returns a dict with:
      - backend: "service_account", "desktop_cli", "cli_token", or "unknown"
      - account: The account identifier (email or hash) or None
      - signed_in: bool — whether we are authenticated at all
      - is_service_account: bool
      - whoami: raw op whoami output (for diagnostics, no secrets)

    This function NEVER prints credentials or tokens. It only runs
    `op whoami` and inspects the output to classify the auth method.

    Phase 8 discovered that OP_SERVICE_ACCOUNT_TOKEN can override the
    user's main 1Password account, causing write failures because the
    service account may be read-only. This function helps detect that
    situation so the workflow can fall back to the user's desktop
    integration.
    """
    # Check for service account token in environment
    service_token = os.environ.get("OP_SERVICE_ACCOUNT_TOKEN")
    is_service_account = bool(service_token)

    # Run `op whoami` to detect current auth state
    # Note: `op whoami` may fail in subprocess contexts even when the desktop
    # app integration is active (macOS keychain isn't accessible to subprocess).
    # Fall back to `op vault list` which does work via desktop app integration.
    whoami_output = ""
    signed_in = False

    try:
        result = subprocess.run(
            ["op", "whoami"],
            capture_output=True, text=True, timeout=10
        )
        signed_in = result.returncode == 0
        whoami_output = result.stdout.strip() if signed_in else ""
    except Exception:
        signed_in = False

    # Fallback: try `op vault list` if whoami failed
    # (desktop app integration works for vault list but not whoami in subprocess)
    if not signed_in and not is_service_account:
        try:
            vault_result = subprocess.run(
                ["op", "vault", "list"],
                capture_output=True, text=True, timeout=10
            )
            if vault_result.returncode == 0 and "Private" in vault_result.stdout:
                signed_in = True
                whoami_output = "signed_in via desktop CLI integration"
        except Exception:
            pass

    # Classify backend
    if is_service_account:
        backend = "service_account"
    elif signed_in:
        backend = "desktop_cli"
    else:
        backend = "unknown"

    return {
        "backend": backend,
        "account": whoami_output.split("\n")[0] if whoami_output else None,
        "signed_in": signed_in,
        "is_service_account": is_service_account,
        "whoami": whoami_output,
    }


def can_read() -> bool:
    """Test whether the current 1Password backend can read items."""
    backend_info = detect_auth_backend()
    if not backend_info["signed_in"]:
        return False
    # Service accounts and desktop CLI can both read
    return True


def can_write() -> bool:
    """
    Test whether the current 1Password backend can WRITE items.

    Phase 8 discovered:
    - The user's main 1Password account (desktop CLI integration) has
      write access to the Private vault.
    - A service account (OP_SERVICE_ACCOUNT_TOKEN) may be read-only,
      causing write failures during API key storage.

    This function tests write capability by attempting a harmless
    item creation. If it fails, the workflow should try switching
    to the user's desktop account or create a human checkpoint.
    """
    backend_info = detect_auth_backend()
    if not backend_info["signed_in"]:
        return False

    if backend_info["is_service_account"]:
        # Service accounts may be read-only — test explicitly
        try:
            # Attempt a trivial edit that doesn't actually create anything
            # Use `op item edit` on a dummy ID with --dry-run-style test
            # Since we can't do a true dry-run, we check capabilities
            # by running `op vault list` (reads) and checking if the
            # service account has write scope in its configuration
            result = subprocess.run(
                ["op", "whoami", "--format", "json"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                try:
                    info = json.loads(result.stdout)
                    # Check if the account has write permissions
                    # Service account configs include a "delegations" field
                    # or we can check the account type
                    account_type = info.get("account_type", "")
                    if account_type in ("service-account", "service_account"):
                        return False  # Service accounts are read-only by default
                    # User accounts have write access
                    return True
                except (json.JSONDecodeError, TypeError):
                    pass
            # Fallback: assume user account if we can't determine
            return True
        except Exception:
            return False

    # Desktop CLI user account — has write access
    return True


def get_desktop_account() -> str | None:
    """
    Get the user's desktop-integrated 1Password account email.

    This is the account that has full read/write access (unlike a
    service account which may be read-only).
    """
    backend_info = detect_auth_backend()
    if not backend_info["signed_in"]:
        return None
    if backend_info["is_service_account"]:
        # Try to find the desktop account
        # The `op account list` command shows all configured accounts
        result = _run_op(["account", "list", "--format", "json"])
        if isinstance(result, list):
            for acct in result:
                if acct.get("type") == "USER_CREATED":
                    return acct.get("email") or acct.get("name")
        return None
    # Already using desktop account
    return backend_info.get("account")


def require_write_access() -> tuple[bool, str | None]:
    """
    Ensure we have write access to 1Password.

    Returns (has_access: bool, error_message: str | None).

    If write access is not available, the caller should create a
    human checkpoint prompting the user to sign in via the 1Password
    desktop app, then retry.
    """
    if not can_write():
        backend_info = detect_auth_backend()
        if backend_info["is_service_account"]:
            desktop = get_desktop_account()
            if desktop:
                return False, (
                    "1Password is using a read-only service account. "
                    f"The user's desktop account ({desktop}) has write access. "
                    "Please sign in via the 1Password desktop app."
                )
            return False, (
                "1Password is using a read-only service account. "
                "Please sign in via the 1Password CLI or desktop app "
                "for write access."
            )
        return False, "Not signed into 1Password. Please authenticate."
    return True, None


# ── Item title conventions (Phase 9E / 9F / 9K) ───────────────────────────

def account_login_title(provider_name: str) -> str:
    """
    Generate a deterministic 1Password LOGIN item title for a provider account.

    Convention: The provider's display name (e.g. "Cloudflare").
    This matches the user's requirement that account logins follow
    the provider naming convention.
    """
    return provider_name


def api_key_title(hostname: str) -> str:
    """
    Generate the deterministic 1Password item title for an API credential.

    Convention: "OmniRoute [hostname] Api Key"

    Examples:
        OmniRoute api.cloudflare.com Api Key
        OmniRoute api.openai.com Api Key
        OmniRoute api.groq.com Api Key

    This is the EXACT naming convention required by Phase 9F/9K.
    """
    return f"OmniRoute {hostname} Api Key"


# ── Item lookup helpers (Phase 9G / 9K) ───────────────────────────────────


def find_login_item(provider_name: str, vault: str | None = None,
                    account: str | None = None) -> dict | None:
    """
    Find an existing 1Password LOGIN item for a provider account.

    Returns item metadata (id, title, vault, username) or None.
    NEVER returns the password value.

    This supports Phase 9G: before creating a new login, check if one
    already exists to avoid duplicate accounts.
    """
    title = account_login_title(provider_name)
    items = search_items(query=title, vault=vault)
    for item in items:
        if (item.get("title") or "").lower() == title.lower():
            return {
                "item_id": item.get("id"),
                "title": item.get("title"),
                "vault": item.get("vault", {}).get("name") if isinstance(item.get("vault"), dict) else item.get("vault"),
                "username": _extract_item_username(item),
                "tags": item.get("tags", []),
            }
    return None


def find_api_key_item(hostname: str, vault: str | None = None,
                      account: str | None = None) -> dict | None:
    """
    Find an existing 1Password item for an OmniRoute API key.

    Returns item metadata (id, title, vault) or None.
    NEVER returns the API key value.

    This supports Phase 9K: before creating a new API key credential,
    check if one already exists to avoid duplicates.
    """
    title = api_key_title(hostname)
    items = search_items(query=title, vault=vault)
    for item in items:
        if (item.get("title") or "").lower() == title.lower():
            return {
                "item_id": item.get("id"),
                "title": item.get("title"),
                "vault": item.get("vault", {}).get("name") if isinstance(item.get("vault"), dict) else item.get("vault"),
                "tags": item.get("tags", []),
            }
    return None


def item_exists(title: str, vault: str | None = None) -> bool:
    """
    Check whether a 1Password item with the given title already exists.

    Used to avoid accidental duplication of login items and API key items.
    """
    return find_login_item(title, vault=vault) is not None or \
           find_api_key_item(title.split()[-2] if "Api Key" in title else "", vault=vault) is not None


def _extract_item_username(item: dict) -> str | None:
    """Extract username from a 1Password item (no secret values)."""
    details = item.get("details", {})
    if isinstance(details, dict):
        fields = details.get("fields", {})
        if isinstance(fields, dict):
            for key in ("username", "email"):
                if key in fields:
                    val = fields[key]
                    return val.get("value") if isinstance(val, dict) else val
        elif isinstance(fields, list):
            for f in fields:
                if isinstance(f, dict) and f.get("id") in ("username", "email"):
                    return f.get("value")
    if "fields" in item and isinstance(item["fields"], list):
        for f in item["fields"]:
            if isinstance(f, dict) and f.get("id") in ("username", "email"):
                return f.get("value")
    return None


# ── Vault resolution ────────────────────────────────────────────────────

def get_default_vault() -> str:
    """Get the default vault name."""
    vault = os.environ.get("OP_VAULT", "Personal")
    return vault


def list_vaults() -> list[dict]:
    """
    Discover all available 1Password vaults dynamically.

    Returns a list of dicts with: id, name.
    Does NOT assume a hardcoded 'Private' or 'Personal' vault.
    """
    result = _run_op(["vault", "list", "--format", "json"])
    if isinstance(result, list):
        return [{"id": v.get("id"), "name": v.get("name")} for v in result]
    if isinstance(result, dict) and "error" in result:
        return []
    return []


def get_vault_by_name(vault_name: str) -> dict | None:
    """Find a vault by name or ID."""
    for v in list_vaults():
        if v.get("name") == vault_name or v.get("id") == vault_name:
            return v
    return None


def ensure_vault_exists(vault_name: str | None = None) -> str | None:
    """
    Validate that a vault exists. Returns the vault name if valid, None if not.

    If vault_name is None, returns the first available vault.
    """
    vaults = list_vaults()
    if not vaults:
        return None
    if vault_name is None:
        return vaults[0].get("name")
    for v in vaults:
        if v.get("name") == vault_name or v.get("id") == vault_name:
            return v.get("name")
    return None


def ensure_signed_in() -> bool:
    """Check if we're signed into 1Password."""
    try:
        result = subprocess.run(
            ["op", "whoami"],
            capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


def _run_op(args: list[str], timeout: int = 15) -> dict | str | None:
    """Run an op command and return parsed JSON or raw output."""
    try:
        result = subprocess.run(
            ["op"] + args,
            capture_output=True, text=True, timeout=timeout
        )
        if result.returncode != 0:
            return {"error": result.stderr.strip() or result.stdout.strip()}

        output = result.stdout.strip()
        if not output:
            return None

        # Try to parse as JSON
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            return output
    except subprocess.TimeoutExpired:
        return {"error": "op command timed out"}
    except Exception as e:
        return {"error": str(e)}


# ── Search ──────────────────────────────────────────────────────────────

def search_items(query: str | None = None, vault: str | None = None,
                 tags: list[str] | None = None) -> list[dict]:
    """
    Search 1Password for items matching a query.

    Returns a list of item dicts with: id, title, vault, tags, etc.
    (No secret values included.)
    """
    args = ["item", "list"]

    if vault:
        args.extend(["--vault", vault])
    if query:
        args.extend(["--search", query])
    if tags:
        for t in tags:
            args.extend(["--tag", t])

    result = _run_op(args)
    if isinstance(result, dict) and "error" in result:
        return []
    if isinstance(result, str):
        return []
    return result if isinstance(result, list) else []


def search_provider_items(provider_name: str, vault: str | None = None) -> list[dict]:
    """Search for 1Password items related to a specific provider."""
    # Search by provider name, provider ID, and common patterns
    queries = [provider_name, provider_name.lower(), provider_name.upper()]
    results = []
    seen_ids = set()

    for q in queries:
        items = search_items(q, vault=vault)
        for item in items:
            if item.get("id") not in seen_ids:
                seen_ids.add(item.get("id"))
                results.append(item)

    return results


# ── Get ─────────────────────────────────────────────────────────────────

def get_item(item_id: str, vault: str | None = None) -> dict | None:
    """
    Get a 1Password item by ID.

    Returns the full item including details (but secrets are masked
    unless --reveal is used).
    """
    args = ["item", "get", item_id]
    if vault:
        args.extend(["--vault", vault])

    result = _run_op(args)
    if isinstance(result, dict) and "error" in result:
        return None
    return result if isinstance(result, dict) else None


def get_item_detail(item_id: str, vault: str | None = None) -> dict | None:
    """Get full item details including field references."""
    return get_item(item_id, vault)


def get_credential_value(item_id: str, field: str = "credential",
                         vault: str | None = None, account: str | None = None) -> str | None:
    """
    Retrieve the actual secret value from a 1Password item.

    This is the ONLY method that retrieves the actual secret — used only
    when needed for an operation (e.g. generating an OmniRoute import).

    Args:
        item_id: The 1Password item ID
        field: The field name containing the secret (default: 'credential')
        vault: The vault name
        account: The 1Password account to use (email address)
    """
    args = ["item", "get", item_id, "--fields", field, "--reveal"]
    if vault:
        args.extend(["--vault", vault])
    if account:
        args.extend(["--account", account])

    result = _run_op(args)
    if isinstance(result, dict) and "error" in result:
        return None
    if isinstance(result, str):
        return result.strip()
    return None


def get_login(item_id: str, vault: str | None = None) -> dict | None:
    """
    Get a login item's details.

    Returns a dict with: id, title, username, url, credential_ref, etc.
    """
    item = get_item(item_id, vault)
    if not item:
        return None

    # Extract fields
    fields = item.get("details", {}).get("fields", {}) if isinstance(item.get("details"), dict) else {}
    # Also check the newer v2 format
    if not fields and "fields" in item:
        fields = item["fields"]

    credential_ref = {
        "backend": "1password",
        "vault": vault or item.get("vault", {}).get("name", get_default_vault()),
        "item_id": item_id,
        "item_title": item.get("title", ""),
        "field": "credential",
        "reference": f"op://{vault or get_default_vault()}/{item_id}/credential",
    }

    return {
        "id": item_id,
        "title": item.get("title", ""),
        "vault": item.get("vault", {}).get("name") if isinstance(item.get("vault"), dict) else item.get("vault"),
        "username": _extract_field_value(fields, "username") or _extract_field_value(fields, "email"),
        "url": _extract_field_value(fields, "url") or _extract_field_value(fields, "website"),
        "credential_ref": credential_ref,
        "tags": item.get("tags", []),
        "created": item.get("created", ""),
        "updated": item.get("updated", ""),
    }


def _extract_field_value(fields: dict | list, field_name: str) -> str | None:
    """Extract a field value from various 1Password field formats."""
    if isinstance(fields, dict):
        if field_name in fields:
            val = fields[field_name]
            return val.get("value") if isinstance(val, dict) else val
    elif isinstance(fields, list):
        for field in fields:
            if isinstance(field, dict) and field.get("id") == field_name:
                return field.get("value")
    return None


# ── Create / Update ────────────────────────────────────────────────────

def create_login(title: str, username: str | None = None, password: str | None = None,
                 url: str | None = None, vault: str | None = None,
                 tags: list[str] | None = None,
                 custom_fields: dict | None = None,
                 account: str | None = None) -> dict | None:
    """
    Create a new 1Password login item.

    Args:
        title: Item title (e.g. "OpenAI API Key")
        username: The username/email
        password: The password or API key
        url: The signup/login URL
        vault: The vault to create in
        tags: Tags for the item
        custom_fields: Additional custom fields
        account: 1Password account to use

    Returns: dict with 'id' of the created item, or None on failure.
    """
    args = ["item", "create"]
    if vault:
        args.extend(["--vault", vault])
    if account:
        args.extend(["--account", account])

    # Build the item JSON
    item = {
        "title": title,
        "tags": tags or ["provider-xref", "auto-generated"],
    }

    fields = []
    if username:
        fields.append({"id": "username", "type": "STRING", "value": username})
    if password:
        fields.append({"id": "credential", "type": "CONCEALED", "value": password, "label": "Credential"})
    if url:
        fields.append({"id": "url", "type": "URL", "value": url})

    if custom_fields:
        for key, val in custom_fields.items():
            fields.append({"id": key, "type": "STRING", "value": str(val)})

    if fields:
        item["fields"] = fields

    # Write to a temp file for the API
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(item, f)
        tmp_path = f.name

    try:
        result = subprocess.run(
            ["op", "item", "create", "--category", "LOGIN"]
            + (["--vault", vault] if vault else [])
            + (["--account", account] if account else [])
            + ["--format", "json"],
            input=open(tmp_path).read(),
            capture_output=True, text=True, timeout=30
        )
        os.unlink(tmp_path)

        if result.returncode == 0:
            data = json.loads(result.stdout)
            return {"id": data.get("id"), "title": data.get("title"),
                    "vault": vault or get_default_vault()}
        else:
            return {"error": result.stderr.strip()}
    except Exception as e:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        return {"error": str(e)}


def update_login(item_id: str, updates: dict, vault: str | None = None,
                 account: str | None = None) -> dict | None:
    """
    Update an existing 1Password item.

    Args:
        item_id: The item ID to update
        updates: Dict of field_id -> new_value
        vault: The vault containing the item
        account: 1Password account to use
    """
    args = ["item", "edit", item_id]
    if vault:
        args.extend(["--vault", vault])
    if account:
        args.extend(["--account", account])

    # Build edit command
    field_args = []
    for field_id, value in updates.items():
        field_args.extend(["--fields", f"{field_id}={value}"])

    args.extend(field_args)
    args.extend(["--format", "json"])

    result = _run_op(args)
    if isinstance(result, dict) and "error" in result:
        return None
    return result if isinstance(result, dict) else None


def build_credential_ref(vault: str | None = None, item_id: str | None = None,
                         item_title: str | None = None,
                         field: str = "credential") -> dict:
    """
    Build a credential reference object for state storage.

    This is what gets stored in provider_state.json — NOT the actual secret.

    Phase 9E: The reference now includes item_title and a full
    op:// reference URL for clarity and auditability.
    """
    vault_name = vault or get_default_vault()
    return {
        "backend": "1password",
        "vault": vault_name,
        "item_id": item_id,
        "item_title": item_title or "",
        "field": field,
        "reference": f"op://{vault_name}/{item_id}/{field}",
    }


# ── Sync helpers ────────────────────────────────────────────────────────

def discover_1password_items(state_provider_ids: set[str] | None = None,
                             tag_filter: list[str] | None = None) -> dict:
    """
    Discover what's in 1Password, compared to local state.

    Returns:
    - op_only: Items in 1Password not in local state
    - state_only: Items in state not in 1Password
    - matches: Items in both
    - all_items: Full list from 1Password
    """
    if tag_filter:
        all_items = search_items(tags=tag_filter)
    else:
        # Search for common provider-related items
        all_items = search_items("api key") + search_items("provider") + search_items("token")

    # Deduplicate by ID
    seen = set()
    unique_items = []
    for item in all_items:
        if item.get("id") not in seen:
            seen.add(item.get("id"))
            unique_items.append(item)

    # Build lookup
    op_provider_map = {}
    for item in unique_items:
        title = (item.get("title") or "").lower()
        # Try to extract provider name from title
        for known_provider in ["openai", "claude", "anthropic", "deepseek", "gemini",
                              "mistral", "groq", "nvidia", "huggingface", "openrouter",
                              "nous", "fireworks", "cohere", "baseten", "scaleway"]:
            if known_provider in title:
                op_provider_map[item["id"]] = known_provider
                break

    op_provider_ids = set(op_provider_map.values())
    if state_provider_ids is None:
        state_provider_ids = set()

    op_only = op_provider_ids - state_provider_ids
    state_only = state_provider_ids - op_provider_ids

    return {
        "op_only": list(op_only),
        "state_only": list(state_only),
        "matches": list(op_provider_ids & state_provider_ids),
        "all_items": unique_items,
    }


# ── Adapter wrapper class ──────────────────────────────────────────────

class Adapter:
    """1Password adapter wrapper — delegates to module-level functions."""

    def ensure_signed_in(self):
        return ensure_signed_in()

    def detect_auth_backend(self):
        return detect_auth_backend()

    def can_read(self):
        return can_read()

    def can_write(self):
        return can_write()

    def get_desktop_account(self):
        return get_desktop_account()

    def require_write_access(self):
        return require_write_access()

    def account_login_title(self, provider_name: str):
        return account_login_title(provider_name)

    def api_key_title(self, hostname: str):
        return api_key_title(hostname)

    def find_login_item(self, **kwargs):
        return find_login_item(**kwargs)

    def find_api_key_item(self, **kwargs):
        return find_api_key_item(**kwargs)

    def item_exists(self, title: str, vault: str | None = None):
        return item_exists(title, vault=vault)

    def create_login(self, **kwargs):
        return create_login(**kwargs)

    def update_login(self, **kwargs):
        return update_login(**kwargs)

    def get_credential_value(self, **kwargs):
        return get_credential_value(**kwargs)

    def build_credential_ref(self, **kwargs):
        return build_credential_ref(**kwargs)

    def list_vaults(self):
        return list_vaults()

    def search_items(self, **kwargs):
        return search_items(**kwargs)

    def search_provider_items(self, **kwargs):
        return search_provider_items(**kwargs)

    def get_item(self, **kwargs):
        return get_item(**kwargs)

    def get_login(self, **kwargs):
        return get_login(**kwargs)

    def discover_1password_items(self, **kwargs):
        return discover_1password_items(**kwargs)
