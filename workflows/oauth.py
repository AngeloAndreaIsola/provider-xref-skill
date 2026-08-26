"""
oauth.py — Generic OAuth provider registration workflow.

OAuth is fundamentally different from API-key registration.

Hermes uses the browser/MCP layer rather than attempting to manipulate
OAuth tokens directly.

Architecture:
  Hermes → Registration workflow → Browser MCP → provider website
                                        → Google/GitHub login
                                        → consent
                                        → callback
                              → OmniRoute
                              → verify
"""

from __future__ import annotations

from typing import Any

# Use try/except for import compatibility (standalone vs package mode)
try:
    from engine.state import load_state, save_state, now_iso
    from engine.catalog import load_catalog, get_provider
    from engine.registration import record_attempt, record_success, record_failure, record_partial
    from engine.utils import uuid_id
    from adapters.onepassword import build_credential_ref, get_credential_value
    from adapters.omniroute import connect_provider, verify_provider, generate_import_record
    from adapters.browser import navigate, click, type_text, fill_form, oauth_flow, api_key_flow
except ImportError:
    from ..engine.state import load_state, save_state, now_iso
    from ..engine.catalog import load_catalog, get_provider
    from ..engine.registration import record_attempt, record_success, record_failure, record_partial
    from ..engine.utils import uuid_id
    from ..adapters.onepassword import build_credential_ref, get_credential_value
    from ..adapters.omniroute import connect_provider, verify_provider, generate_import_record
    from ..adapters.browser import navigate, click, type_text, fill_form, oauth_flow, api_key_flow


class OAuthWorkflow:
    """
    Registration workflow for OAuth-based providers.

    The browser performs the actual OAuth dance.  Hermes orchestrates
    the steps and pauses at human checkpoints (consent screen, CAPTCHA,
    phone verification, ToS).
    """

    def can_register(self, opportunity: dict) -> tuple[bool, str]:
        """Check if we can register for this provider via OAuth."""
        provider_id = opportunity["provider"]
        catalog = load_catalog()
        provider = get_provider(catalog, provider_id)

        if not provider:
            return False, f"Provider '{provider_id}' not in catalog"

        if provider["auth_type"] != "oauth":
            return False, f"Provider '{provider_id}' is not an OAuth provider"

        if opportunity["policy_status"] == "disallowed":
            return False, "Provider policy disallows this action"

        if opportunity["policy_status"] == "unknown":
            return False, "Provider policy unknown — manual approval required"

        if opportunity.get("identity_blocker"):
            return False, f"Missing required identities: {opportunity.get('missing_identities')}"

        return True, "Ready to register"

    def prepare(self, opportunity: dict, state: dict | None = None) -> dict:
        """Prepare for OAuth registration: select identity."""
        if state is None:
            state = load_state()

        provider_id = opportunity["provider"]
        identity_id = opportunity.get("identity")

        identities = state.get("identities", [])
        identity = next((i for i in identities if i["id"] == identity_id), None)

        if not identity:
            # Find a compatible identity
            reqs = set(opportunity.get("requirements", []))
            for req_type in reqs:
                identity = next((i for i in identities if i["type"] == req_type
                                and i.get("status") in ("available", "active")), None)
                if identity:
                    break

        if not identity:
            identity = next((i for i in identities
                            if i["type"] in ("email", "google", "github")
                            and i.get("status") in ("available", "active")), None)

        return {
            "provider_id": provider_id,
            "identity": identity,
            "credential_1password_item": None,
        }

    def register(self, opportunity: dict, prep: dict, mode: str = "interactive") -> dict:
        """
        Execute the OAuth flow.

        The browser MCP tools navigate to the provider's OAuth page,
        sign in with the selected identity, grant consent, and follow
        the callback back to OmniRoute.

        Hermes does NOT extract OAuth tokens or cookies — the normal
        OAuth flow is used.
        """
        provider_id = opportunity["provider"]
        catalog = load_catalog()
        provider = get_provider(catalog, provider_id)
        identity = prep.get("identity")

        reg_id = record_attempt(
            provider_id=provider_id,
            method="oauth",
            trigger_event="manual",
            identity_id=identity["id"] if identity else None,
            provider_catalog_provider=provider,
        )

        if mode == "dry_run":
            actions = oauth_flow(provider_id, provider, identity)
            return {
                "registration_id": reg_id,
                "mode": "dry_run",
                "provider": provider["name"],
                "actions": actions["actions"],
                "next_step": "Review the OAuth flow plan",
            }

        # In the actual execution, browser MCP tools would be called.
        # Hermes orchestrates but pauses at consent screens.
        actions = oauth_flow(provider_id, provider, identity)

        steps = {}
        for action in actions["actions"]:
            steps[action["step"]] = "pending"

        return {
            "registration_id": reg_id,
            "mode": mode,
            "provider": provider["name"],
            "provider_id": provider_id,
            "identity_used": identity["value"] if identity else None,
            "actions": actions["actions"],
            "steps_status": steps,
            "next_step": "open_provider",
            "human_checkpoint_required": True,  # Consent screen, CAPTCHA, phone verification
        }

    def verify(self, opportunity: dict, prep: dict) -> dict:
        """Verify the OAuth connection was successful."""
        provider_id = opportunity["provider"]
        catalog = load_catalog()
        provider = get_provider(catalog, provider_id)

        # Check if the provider is connected in OmniRoute
        omniroute_id = provider.get("omniroute_support", {}).get("omniroute_id", provider_id)
        verified = verify_provider(omniroute_id)

        return {
            "provider_id": provider_id,
            "status": "verified" if verified else "not_verified",
            "verified": verified,
            "next_action": "complete" if verified else "retry",
        }

    def acquire_credentials(self, opportunity: dict, prep: dict) -> dict:
        """
        For OAuth providers, credentials are managed by OmniRoute.
        No explicit credential storage in 1Password is needed —
        OmniRoute handles the OAuth token lifecycle.

        However, we may want to store metadata about the OAuth connection.
        """
        provider_id = opportunity["provider"]
        provider = get_provider(load_catalog(), provider_id)
        identity = prep.get("identity")

        # Store an info item in 1Password for audit purposes
        credential_ref = build_credential_ref(
            vault="Personal",
            item_id=None,  # Will be set later
            field="note",
        )

        return {
            "status": "success",
            "credential_ref": credential_ref,
            "note": "OAuth token managed by OmniRoute — no manual credential storage needed",
        }

    def connect_omniroute(self, opportunity: dict, prep: dict) -> dict:
        """
        For OAuth, OmniRoute handles the connection during the OAuth flow.
        This method verifies the connection.
        """
        provider_id = opportunity["provider"]
        catalog = load_catalog()
        provider = get_provider(catalog, provider_id)
        omniroute_id = provider.get("omniroute_support", {}).get("omniroute_id", provider_id)

        verified = verify_provider(omniroute_id)

        return {
            "status": "connected" if verified else "failed",
            "omniroute_account_id": omniroute_id,
            "verified": verified,
        }

    def finalize(self, opportunity: dict, prep: dict,
                 omniroute_result: dict) -> dict:
        """Finalize: update state with the OAuth provider account."""
        provider_id = opportunity["provider"]
        identity = prep.get("identity")

        state = load_state()

        existing_pa = next((pa for pa in state.get("provider_accounts", [])
                           if pa["provider_id"] == provider_id), None)

        if existing_pa:
            existing_pa["status"] = "connected"
            existing_pa["omniroute_connected"] = omniroute_result.get("verified", False)
            existing_pa["omniroute_account_id"] = omniroute_result.get("omniroute_account_id")
            existing_pa["last_verified"] = now_iso()
            if identity:
                existing_pa["identity_id"] = identity["id"]
                existing_pa["external_account_id"] = identity.get("external_account_id")
        else:
            new_pa = {
                "id": uuid_id("pa"),
                "provider_id": provider_id,
                "identity_id": identity["id"] if identity else None,
                "status": "connected",
                "auth_type": "oauth",
                "omniroute_connected": omniroute_result.get("verified", False),
                "omniroute_account_id": omniroute_result.get("omniroute_account_id"),
                "created_at": now_iso(),
                "last_verified": now_iso(),
            }
            state["provider_accounts"].append(new_pa)

        save_state(state)

        return {
            "status": "completed",
            "provider_id": provider_id,
            "credential": "oauth_managed_by_omniroute" if omniroute_result.get("verified") else "failed",
            "omniroute": "connected" if omniroute_result.get("verified") else "failed",
            "onepassword": "not_needed",
            "verified": omniroute_result.get("verified", False),
        }
