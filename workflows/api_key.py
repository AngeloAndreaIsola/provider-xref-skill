"""
api_key.py — Generic API-key provider registration workflow.

Flow:
  select identity → open signup page → register → email verify →
  login → create API key → store in 1Password → connect to OmniRoute →
  test request → update state

The API key should NEVER appear in:
- Hermes chat output
- logs
- JSON state
- registration history

It only lives in 1Password.  State stores a credential_ref.
"""

from __future__ import annotations

from typing import Any

# Use absolute imports for top-level package modules
try:
    from engine.state import load_state, save_state, now_iso, add_provider_account, add_credential
    from engine.catalog import load_catalog, get_provider
    from engine.registration import record_attempt, record_success, record_failure, record_partial
    from engine.utils import uuid_id
    from adapters.onepassword import (
        create_login, get_credential_value, build_credential_ref,
        account_login_title, api_key_title, find_login_item, find_api_key_item,
    )
    from adapters.omniroute import connect_provider, verify_provider, generate_import_record
    from adapters.browser import api_key_flow
except ImportError:
    from ..engine.state import load_state, save_state, now_iso, add_provider_account, add_credential
    from ..engine.catalog import load_catalog, get_provider
    from ..engine.registration import record_attempt, record_success, record_failure, record_partial
    from ..engine.utils import uuid_id
    from ..adapters.onepassword import (
        create_login, get_credential_value, build_credential_ref,
        account_login_title, api_key_title, find_login_item, find_api_key_item,
    )
    from ..adapters.omniroute import connect_provider, verify_provider, generate_import_record
    from ..adapters.browser import api_key_flow

from urllib.parse import urlparse


class APIKeyWorkflow:
    """
    Registration workflow for API-key-based providers.

    Implements the ProviderWorkflow interface:
      can_register, prepare, register, verify, acquire_credentials,
      connect_omniroute, finalize

    The ``requires_browser`` attribute signals to the executor that this
    workflow needs a live browser session before execution can begin.
    When ``requires_browser`` is False (e.g. for mocked test workflows),
    the executor skips the browser-session verification.
    """

    requires_browser = True

    def can_register(self, opportunity: dict) -> tuple[bool, str]:
        """Check if we can register for this provider."""
        provider_id = opportunity["provider"]
        catalog = load_catalog()
        provider = get_provider(catalog, provider_id)

        if not provider:
            return False, f"Provider '{provider_id}' not in catalog"

        if provider["auth_type"] != "api_key":
            return False, f"Provider '{provider_id}' is not an API-key provider (auth_type={provider['auth_type']})"

        if opportunity["policy_status"] == "disallowed":
            return False, "Provider policy disallows this action"

        if opportunity["policy_status"] == "unknown":
            return False, "Provider policy unknown — manual approval required"

        if opportunity.get("identity_blocker"):
            return False, f"Missing required identities: {opportunity.get('missing_identities')}"

        return True, "Ready to register"

    def prepare(self, opportunity: dict, state: dict | None = None) -> dict:
        """Prepare for registration: select identity, prepare credentials."""
        if state is None:
            state = load_state()

        provider_id = opportunity["provider"]
        identity_id = opportunity.get("identity")

        # Select the identity to use
        identities = state.get("identities", [])
        identity = next((i for i in identities if i["id"] == identity_id), None)

        if not identity and opportunity.get("requirements"):
            # Find a compatible identity
            for req in opportunity["requirements"]:
                identity = next((i for i in identities if i["type"] == req
                                and i.get("status") in ("available", "active")), None)
                if identity:
                    break

        if not identity:
            # Use any available email
            identity = next((i for i in identities
                            if i["type"] in ("email", "google")
                            and i.get("status") in ("available", "active")), None)

        # Generate a password for the signup
        import secrets, string
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        password = "".join(secrets.choice(alphabet) for _ in range(24))

        return {
            "provider_id": provider_id,
            "identity": identity,
            "password": password,
            "credential_1password_item": None,  # Will be set after creation
            "omniroute_account_id": None,
        }

    def register(self, opportunity: dict, prep: dict, mode: str = "interactive") -> dict:
        """
        Execute the registration.

        modes:
          - 'dry_run': produce the browser action plan but don't execute
          - 'browser_dry_run': navigate but don't submit forms
          - 'interactive': execute, pause at human checkpoints
          - 'automatic': execute fully (only for explicitly safe workflows)
        """
        provider_id = opportunity["provider"]
        provider = get_provider(load_catalog(), provider_id)

        # In dry_run mode, do NOT mutate the registration history ledger.
        # Only record the attempt when actually executing (interactive/automatic).
        reg_id = None
        if mode != "dry_run":
            reg_id = record_attempt(
                provider_id=provider_id,
                method="api_key",
                trigger_event="manual",
                identity_id=(prep.get("identity") or {}).get("id"),
                provider_catalog_provider=provider,
            )

        catalog = load_catalog()
        provider = get_provider(catalog, provider_id)
        identity = prep.get("identity")

        if mode == "dry_run":
            actions = api_key_flow(provider_id, provider, identity)
            return {
                "registration_id": None,
                "mode": "dry_run",
                "provider": provider["name"],
                "actions": actions["actions"],
                "next_step": "Review the action plan, then run in 'interactive' mode",
            }

        # In interactive/automatic mode, the actual browser execution
        # is handled by the Hermes runtime (browser MCP tools).
        # This method returns the plan; the runtime executes it.

        actions = api_key_flow(provider_id, provider, identity)

        # Record the plan steps
        steps = {}
        for action in actions["actions"]:
            steps[action["step"]] = "pending"

        # In the actual execution, browser MCP tools would be called
        # to navigate, fill forms, extract API keys, etc.
        # For now, we return the action plan.

        # Build structured checkpoint data for resumability (Phase 9H)
        checkpoint_info = {
            "provider": provider_id,
            "identity": identity["value"] if identity else None,
            "identity_id": identity["id"] if identity else None,
            "workflow": "APIKeyWorkflow",
            "step": "awaiting_human_interaction",
            "checkpoint_type": "email_verification",
        }

        return {
            "registration_id": reg_id,
            "mode": mode,
            "provider": provider["name"],
            "provider_id": provider_id,
            "identity_used": identity["value"] if identity else None,
            # Password is transient — managed by the browser MCP runtime and
            # stored directly to 1Password. Never persisted in Hermes state.
            "actions": actions["actions"],
            "steps_status": steps,
            "next_step": "open_provider",
            "human_checkpoint_required": True,  # Email verification, CAPTCHA
            "checkpoint_info": checkpoint_info,
        }

    def verify(self, opportunity: dict, prep: dict) -> dict:
        """Verify the registration was successful."""
        provider_id = opportunity["provider"]
        # The runtime would navigate to the provider and test the API key
        return {
            "provider_id": provider_id,
            "status": "verified",
            "next_action": "acquire_credentials",
        }

    def acquire_credentials(self, opportunity: dict, prep: dict,
                          api_key: str | None = None,
                          password: str | None = None) -> dict:
        """
        Store account login AND API key in 1Password.

        This is the core Fix #3: the account login must be persisted
        alongside the API credential.

        For API-key providers, two items are created:
          1. Account login item (title: provider display name)
             Contains: username/email, password
          2. API key item (title: "OmniRoute [hostname] Api Key")
             Contains: the API key as the credential field

        Uses find_login_item / find_api_key_item to avoid duplicates.
        Only references (credential_ref) are stored in Hermes state;
        actual secrets go directly to 1Password.
        """
        provider_id = opportunity["provider"]
        provider = get_provider(load_catalog(), provider_id)
        identity = prep.get("identity")

        login_url = provider.get("login_url") or provider.get("signup_url") or ""
        hostname = urlparse(login_url).netloc if login_url else provider_id
        provider_name = provider.get("name", provider_id)

        # Phase 9G: Security boundary — NO secrets in return value beyond
        # credential_ref (op:// URI). The actual password and api_key go
        # directly to 1Password via the op CLI.
        # We return metadata only: item IDs, vault names, credential_ref paths.

        vault = "Personal"
        tags = ["provider-xref", "api-key", provider_id]

        results = {}

        # ── Step 1: Account login item ──────────────────────────────────
        # Naming: account_login_title(provider_name) → e.g. "Groq"
        login_ref = self._get_or_create_login(
            provider_name=provider_name,
            username=identity["value"] if identity else None,
            password=password,
            url=provider.get("login_url"),
            vault=vault,
            tags=tags + ["account-login"],
        )
        if "error" in login_ref:
            return {"status": "failed", "error": login_ref["error"]}
        results["login_ref"] = login_ref

        # ── Step 2: API key item ────────────────────────────────────────
        # Naming: api_key_title(hostname) → e.g. "OmniRoute api.groq.com Api Key"
        apikey_ref = self._get_or_create_api_key(
            hostname=hostname,
            api_key=api_key,
            username=identity["value"] if identity else None,
            url=provider.get("dashboard_url") or provider.get("login_url"),
            vault=vault,
            tags=tags,
        )
        if "error" in apikey_ref:
            return {"status": "failed", "error": apikey_ref["error"]}
        results["apikey_ref"] = apikey_ref

        # The primary credential_ref is the API key (used for OmniRoute)
        results["credential_ref"] = apikey_ref["credential_ref"]
        results["onepassword_item_id"] = apikey_ref["item_id"]
        results["login_item_id"] = login_ref["item_id"]
        results["vault"] = vault
        results["status"] = "success"
        return results

    def _get_or_create_login(self, provider_name: str, username: str | None,
                            password: str | None, url: str | None,
                            vault: str, tags: list) -> dict:
        """Get existing login item or create a new one. Never returns the password."""
        existing = find_login_item(provider_name, vault=vault)
        if existing:
            return {
                "item_id": existing["item_id"],
                "vault": existing["vault"],
                "title": existing["title"],
                "username": existing["username"],
                "credential_ref": build_credential_ref(
                    vault=existing["vault"],
                    item_id=existing["item_id"],
                    field="credential",
                ),
                "reused": True,
            }
        if not password:
            return {"error": "No password available and no existing login item to reuse"}
        result = create_login(
            title=account_login_title(provider_name),
            username=username,
            password=password,
            url=url,
            vault=vault,
            tags=tags,
        )
        if isinstance(result, dict) and "error" in result:
            return {"error": result["error"]}
        item_id = result.get("id")
        item_vault = result.get("vault", vault)
        return {
            "item_id": item_id,
            "vault": item_vault,
            "title": account_login_title(provider_name),
            "username": username,
            "credential_ref": build_credential_ref(
                vault=item_vault, item_id=item_id, field="credential",
            ),
            "reused": False,
        }

    def _get_or_create_api_key(self, hostname: str, api_key: str | None,
                              username: str | None, url: str | None,
                              vault: str, tags: list) -> dict:
        """Get existing API key item or create a new one. Never returns the API key."""
        existing = find_api_key_item(hostname, vault=vault)
        if existing:
            return {
                "item_id": existing["item_id"],
                "vault": existing["vault"],
                "title": existing["title"],
                "credential_ref": build_credential_ref(
                    vault=existing["vault"],
                    item_id=existing["item_id"],
                    field="credential",
                ),
                "reused": True,
            }
        if not api_key:
            return {"error": "No API key available and no existing API key item to reuse"}
        result = create_login(
            title=api_key_title(hostname),
            username=username,
            password=api_key,
            url=url,
            vault=vault,
            tags=tags,
        )
        if isinstance(result, dict) and "error" in result:
            return {"error": result["error"]}
        item_id = result.get("id")
        item_vault = result.get("vault", vault)
        return {
            "item_id": item_id,
            "vault": item_vault,
            "title": api_key_title(hostname),
            "credential_ref": build_credential_ref(
                vault=item_vault, item_id=item_id, field="credential",
            ),
            "reused": False,
        }

    def connect_omniroute(self, opportunity: dict, prep: dict,
                          cred_ref: dict) -> dict:
        """Connect the provider to OmniRoute using the credential reference."""
        provider_id = opportunity["provider"]
        provider = get_provider(load_catalog(), provider_id)

        # Retrieve the actual API key from 1Password
        api_key = get_credential_value(
            item_id=cred_ref["item_id"],
            field=cred_ref.get("field", "credential"),
            vault=cred_ref.get("vault", "Personal"),
        )

        if not api_key:
            return {
                "status": "failed",
                "error": "Could not retrieve API key from 1Password",
            }

        # Generate OmniRoute import record
        import_record = generate_import_record(
            provider_id=provider_id,
            provider_name=provider["name"],
            auth_type="api_key",
            base_url=provider.get("login_url"),  # Some providers use OpenAI-compatible endpoints
            api_mode="chat_completions",
        )

        # Connect via OmniRoute API
        catalog = load_catalog()
        provider = get_provider(catalog, provider_id)
        connect_result = connect_provider(
            provider_id=provider.get("omniroute_support", {}).get("omniroute_id", provider_id),
            credential={"api_key": api_key} if provider_id != "azure" else
                      {"api_key": api_key, "base_url": provider.get("login_url")},
            name=f"{provider['name']} ({prep.get('identity', {}).get('value', 'default')})",
        )

        # Verify connection
        verified = verify_provider(provider_id)

        return {
            "status": "connected" if verified else "failed",
            "omniroute_account_id": connect_result.get("id") or provider_id,
            "verified": verified,
        }

    def finalize(self, opportunity: dict, prep: dict, cred_ref: dict,
                 omniroute_result: dict) -> dict:
        """Finalize: update state with the new provider account + credential."""
        provider_id = opportunity["provider"]
        identity = prep.get("identity")

        state = load_state()

        # Update provider account
        existing_pa = next((pa for pa in state.get("provider_accounts", [])
                           if pa["provider_id"] == provider_id), None)

        if existing_pa:
            existing_pa["status"] = "connected"
            existing_pa["omniroute_connected"] = omniroute_result.get("verified", False)
            existing_pa["omniroute_account_id"] = omniroute_result.get("omniroute_account_id")
            existing_pa["credential_ref"] = cred_ref
            existing_pa["last_verified"] = now_iso()
            if identity:
                existing_pa["identity_id"] = identity["id"]
        else:
            new_pa = {
                "id": uuid_id("pa"),
                "provider_id": provider_id,
                "identity_id": identity["id"] if identity else None,
                "status": "connected",
                "auth_type": "api_key",
                "credential_ref": cred_ref,
                "omniroute_connected": omniroute_result.get("verified", False),
                "omniroute_account_id": omniroute_result.get("omniroute_account_id"),
                "created_at": now_iso(),
                "last_verified": now_iso(),
            }
            state["provider_accounts"].append(new_pa)

        # Add credential reference
        cred_exists = any(c.get("provider_account_id") == (existing_pa["id"] if existing_pa else new_pa["id"])
                         for c in state.get("credentials", []))
        if not cred_exists:
            state["credentials"].append({
                "id": uuid_id("cred"),
                "type": "api_key",
                "backend": "1password",
                "vault": cred_ref.get("vault", "Personal"),
                "item_id": cred_ref["item_id"],
                "field": cred_ref.get("field", "credential"),
                "provider_account_id": (existing_pa["id"] if existing_pa else new_pa["id"]),
                "status": "active",
                "created_at": now_iso(),
            })

        save_state(state)

        return {
            "status": "completed",
            "provider_id": provider_id,
            "credential": "stored",
            "omniroute": "connected" if omniroute_result.get("verified") else "failed",
            "onepassword": "stored",
            "verified": omniroute_result.get("verified", False),
        }
