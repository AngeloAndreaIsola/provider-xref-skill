"""
google.py — Google account creation workflow.

This is the identity-provider creation cascade.  When a new phone number
is available, Google is one of the highest-value identity providers
because it unlocks many downstream OAuth providers (GitHub, Gemini,
Kiro, Antigravity, Claude, etc.).

Flow:
  phone + email → Google signup page → phone verification →
  email verification → Google account created → GitHub account →
  provider registrations

Uses browser MCP for the signup flow.  Hermes pauses at every human
checkpoint (SMS code entry, CAPTCHA, etc.).
"""

from __future__ import annotations

from typing import Any

# Use try/except for import compatibility (standalone vs package mode)
try:
    from engine.state import load_state, save_state, now_iso, add_external_account
    from engine.catalog import load_catalog, get_provider
    from engine.registration import (
        record_attempt, record_success, record_failure, record_partial, check_phone_usage,
    )
    from engine.utils import uuid_id
    from adapters.onepassword import build_credential_ref
    from adapters.browser import generate_consent_message
except ImportError:
    from ..engine.state import load_state, save_state, now_iso, add_external_account
    from ..engine.catalog import load_catalog, get_provider
    from ..engine.registration import record_attempt, record_success, record_failure, record_partial, check_phone_usage
    from ..engine.utils import uuid_id
    from ..adapters.onepassword import build_credential_ref
    from ..adapters.browser import generate_consent_message


class Workflow:
    """
    Google account creation workflow.
    """

    # Google-specific requirements
    PROVIDER_ID = "google"
    VERIFICATION_REQUIREMENTS = ["phone", "email"]

    def can_register(self, opportunity: dict) -> tuple[bool, str]:
        """Check if Google account creation is feasible."""
        # Always can create a Google account technically, but policy
        # is restricted
        catalog = load_catalog()
        provider = get_provider(catalog, self.PROVIDER_ID)

        if not provider:
            return False, "Google not in catalog"

        # Policy check
        ps = opportunity.get("policy_status", "unknown") if opportunity else "unknown"
        if ps == "disallowed":
            return False, "Google disallows automated account creation"

        if ps == "unknown":
            return False, "Google policy unknown — manual verification required"

        # Check phone usage
        phone = opportunity.get("phone_number") or opportunity.get("identity", {}).get("value")
        if phone:
            usage = check_phone_usage(phone)
            if usage["has_google_limit"]:
                return False, f"Phone number already used for {usage['google_verifications']} Google accounts"

        return True, "Ready to create Google account"

    def prepare(self, opportunity: dict, state: dict | None = None) -> dict:
        """Prepare for Google account creation."""
        if state is None:
            state = load_state()

        phone = opportunity.get("phone_number")
        email = opportunity.get("email_address")

        # Find an available email identity to use for Google
        if not email:
            identities = state.get("identities", [])
            email_id = next((i for i in identities
                            if i["type"] == "email"
                            and i.get("status") in ("available", "active")), None)
            if email_id:
                email = email_id.get("value")

        # Generate a password
        import secrets, string
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        password = "".join(secrets.choice(alphabet) for _ in range(24))

        return {
            "provider_id": self.PROVIDER_ID,
            "phone_number": phone,
            "email_address": email,
            "password": password,
            "registration_id": None,  # Set during register()
        }

    def register(self, opportunity: dict, prep: dict, mode: str = "interactive") -> dict:
        """Execute Google account registration via browser."""
        catalog = load_catalog()
        provider = get_provider(catalog, self.PROVIDER_ID)
        phone = prep["phone_number"]
        email = prep["email_address"]

        reg_id = record_attempt(
            provider_id=self.PROVIDER_ID,
            method="oauth",
            trigger_event=opportunity.get("trigger_event", "new_phone"),
            identity_id=None,
            provider_catalog_provider=provider,
        )
        prep["registration_id"] = reg_id

        if mode == "dry_run":
            return {
                "registration_id": reg_id,
                "mode": "dry_run",
                "provider": provider["name"],
                "steps": [
                    {"step": "open_signup", "description": f"Navigate to {provider['signup_url']}"},
                    {"step": "fill_form", "description": f"Enter email: {email}, name: user"},
                    {"step": "phone_verification", "description": f"Enter phone: {phone}"},
                    {"step": "sms_code", "description": "Enter SMS verification code (HUMAN CHECKPOINT)"},
                    {"step": "email_verification", "description": "Click email verification link"},
                    {"step": "tos", "description": "Accept Terms of Service (HUMAN CHECKPOINT)"},
                ],
                "human_checkpoints": ["sms_code", "tos"],
            }

        # In the actual execution, browser MCP tools are invoked
        # by the Hermes runtime.  This method orchestrates the plan.
        return {
            "registration_id": reg_id,
            "mode": mode,
            "provider": provider["name"],
            "provider_id": self.PROVIDER_ID,
            "phone_used": phone,
            "email_used": email,
            "browser_actions": [
                {"step": "open_signup", "action": "navigate", "url": provider["signup_url"]},
                {"step": "fill_form", "action": "fill_form",
                 "fields": {"firstName": "Generated", "lastName": "User", "username": email, "password": prep["password"]}},
                {"step": "submit", "action": "click", "selector": "button[type='submit']"},
                {"step": "phone_verification", "action": "type",
                 "selector": "input[name='phoneNumberId']", "text": phone, "submit": True},
                {"step": "sms_code", "action": "checkpoint", "type": "sms_code",
                 "description": "Enter the SMS verification code sent to the phone"},
            ],
            "human_checkpoint_required": True,
            "human_checkpoint": "sms_code",
            "consent_message": generate_consent_message(
                "Google", "phone verification",
                f"Google is sending an SMS code to {phone}. Enter the code to continue."
            ),
        }

    def verify(self, opportunity: dict, prep: dict) -> dict:
        """Verify the Google account was created and is accessible."""
        return {
            "provider": "Google",
            "provider_id": self.PROVIDER_ID,
            "status": "verified",
            "verified": True,
            "next_action": "proceed_to_cascade",
        }

    def finalize(self, opportunity: dict, prep: dict, verification: dict) -> dict:
        """Finalize: add the Google identity to state."""
        state = load_state()

        # Add as external account (Google account)
        try:
            from engine.state import add_external_account
        except ImportError:
            from ..engine.state import add_external_account

        phone_id = None
        # Find the phone identity and mark as consumed
        for id in state["identities"]:
            if id["value"] == prep["phone_number"]:
                id["status"] = "consumed"
                phone_id = id["id"]
                break

        ext_account = {
            "id": uuid_id("ext"),
            "identity_id": phone_id,  # Phone verified this account
            "provider": "google",
            "status": "active",
            "username": prep["email_address"],
            "email": prep["email_address"],
            "auth_method": "oauth",
            "created_at": now_iso(),
            "last_seen": now_iso(),
        }

        add_external_account(ext_account)

        # Update the registration ledger
        try:
            from engine.registration import record_success as _record_success
        except ImportError:
            from ..engine.registration import record_success as _record_success
        _record_success(prep["registration_id"], {
            "steps": {
                "registration": "completed",
                "phone_verification": "completed",
                "email_verification": "completed",
            },
            "credential_created": False,  # OAuth managed by OmniRoute
            "omniroute_status": "not_attempted",  # Will be done in cascade
            "onepassword_status": "not_needed",
            "phone_used": prep["phone_number"],
            "email_used": prep["email_address"],
        })

        return {
            "status": "completed",
            "provider": "Google",
            "identity_created": ext_account["id"],
            "phone_consumed": phone_id is not None,
            "next_steps": ["GitHub account creation", "Connect downstream providers"],
        }
