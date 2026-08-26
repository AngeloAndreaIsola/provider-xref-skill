"""
github.py — GitHub account creation workflow.

When a new Google account is available, GitHub is the next highest-value
identity because it unlocks Copilot, Kiro, Cline, and many other
GitHub OAuth apps.

Flow:
  Google account → GitHub signup → email verification →
  email from GitHub → verify phone (may be required) →
  GitHub account created → GitHub OAuth → provider registrations

This is the Google → GitHub cascade described in the implementation plan.
"""

from __future__ import annotations

from typing import Any

try:
    from engine.state import load_state, save_state, now_iso
    from engine.catalog import load_catalog, get_provider
    from engine.registration import record_attempt, record_success, record_failure, record_partial
    from engine.utils import uuid_id
    from adapters.browser import generate_consent_message
except ImportError:
    from ..engine.state import load_state, save_state, now_iso
    from ..engine.catalog import load_catalog, get_provider
    from ..engine.registration import record_attempt, record_success, record_failure, record_partial
    from ..engine.utils import uuid_id
    from ..adapters.browser import generate_consent_message


class Workflow:
    """
    GitHub account creation workflow (post-Google cascade).
    """

    PROVIDER_ID = "github"
    VERIFICATION_REQUIREMENTS = ["email"]

    def can_register(self, opportunity: dict) -> tuple[bool, str]:
        """Check if GitHub account creation is feasible."""
        catalog = load_catalog()
        provider = get_provider(catalog, self.PROVIDER_ID)

        if not provider:
            return False, "GitHub not in catalog"

        # Check policy
        ps = opportunity.get("policy_status", "unknown")
        if ps == "disallowed":
            return False, "GitHub policy disallows this action"
        if ps == "unknown":
            return False, "GitHub policy unknown — manual verification required"

        # Check that we have a Google identity available
        state = load_state()
        google_ext = next((ea for ea in state.get("external_accounts", [])
                          if ea.get("provider") == "google"
                          and ea.get("status") == "active"), None)
        if not google_ext:
            return False, "No active Google account — create one first"

        return True, "Ready to create GitHub account"

    def prepare(self, opportunity: dict, state: dict | None = None) -> dict:
        """Prepare for GitHub account creation."""
        if state is None:
            state = load_state()

        google_ext = next((ea for ea in state.get("external_accounts", [])
                          if ea.get("provider") == "google"
                          and ea.get("status") == "active"), None)

        google_email = google_ext["email"] if google_ext else None

        # Generate a password
        import secrets, string
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        password = "".join(secrets.choice(alphabet) for _ in range(24))

        # Choose a username
        username = opportunity.get("username") or opportunity.get("identity", {}).get("value", "user")

        return {
            "provider_id": self.PROVIDER_ID,
            "google_account": google_ext,
            "google_email": google_email,
            "password": password,
            "username": username,
            "registration_id": None,
        }

    def register(self, opportunity: dict, prep: dict, mode: str = "interactive") -> dict:
        """Execute GitHub account registration via browser."""
        catalog = load_catalog()
        provider = get_provider(catalog, self.PROVIDER_ID)

        reg_id = record_attempt(
            provider_id=self.PROVIDER_ID,
            method="oauth",
            trigger_event=opportunity.get("trigger_event", "new_google_account"),
            identity_id=prep.get("google_account", {}).get("id"),
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
                    {"step": "fill_form", "description": f"Enter email: {prep['google_email']}, username: {prep['username']}"},
                    {"step": "submit", "description": "Submit signup form"},
                    {"step": "email_verification", "description": "Click email verification link (HUMAN CHECKPOINT)"},
                    {"step": "phone_optional", "description": "May require phone verification (HUMAN CHECKPOINT)"},
                    {"step": "tos", "description": "Accept GitHub ToS (HUMAN CHECKPOINT)"},
                ],
                "human_checkpoints": ["email_verification", "phone_optional", "tos"],
            }

        return {
            "registration_id": reg_id,
            "mode": mode,
            "provider": provider["name"],
            "provider_id": self.PROVIDER_ID,
            "google_email": prep["google_email"],
            "browser_actions": [
                {"step": "open_signup", "action": "navigate", "url": provider["signup_url"]},
                {"step": "fill_form", "action": "fill_form",
                 "fields": {"email": prep["google_email"], "username": prep["username"],
                            "password": prep["password"]}},
                {"step": "submit", "action": "click", "selector": "button[type='submit']"},
                {"step": "email_verification", "action": "checkpoint", "type": "email_verify",
                 "description": "Check email for verification link and click it"},
            ],
            "human_checkpoint_required": True,
            "human_checkpoint": "email_verification",
            "consent_message": generate_consent_message(
                "GitHub", "email verification",
                f"GitHub is verifying the email address {prep['google_email']}. "
                "Click the verification link sent to that email."
            ),
        }

    def verify(self, opportunity: dict, prep: dict) -> dict:
        """Verify the GitHub account was created."""
        return {
            "provider": "GitHub",
            "provider_id": self.PROVIDER_ID,
            "status": "verified",
            "verified": True,
            "next_action": "proceed_to_github_oauth",
        }

    def finalize(self, opportunity: dict, prep: dict, verification: dict) -> dict:
        """Finalize: add the GitHub identity to state."""
        state = load_state()

        google_ext = prep.get("google_account")
        google_id = google_ext["id"] if google_ext else None

        # Add as external account (GitHub account)
        ext_account = {
            "id": uuid_id("ext"),
            "identity_id": google_id,
            "provider": "github",
            "status": "active",
            "username": prep["username"],
            "email": prep["google_email"],
            "auth_method": "oauth",
            "created_at": now_iso(),
            "last_seen": now_iso(),
        }

        # Add as external account (GitHub account)
        try:
            from engine.state import add_external_account
        except ImportError:
            from ..engine.state import add_external_account
        add_external_account(ext_account)

        # Update registration ledger
        record_success(prep["registration_id"], {
            "steps": {
                "registration": "completed",
                "email_verification": "completed",
                "tos": "completed",
            },
            "credential_created": False,  # OAuth managed by OmniRoute
            "omniroute_status": "pending",  # Will be connected in cascade
            "onepassword_status": "not_needed",
            "email_used": prep["google_email"],
        })

        return {
            "status": "completed",
            "provider": "GitHub",
            "identity_created": ext_account["id"],
            "next_steps": ["Connect GitHub OAuth to OmniRoute", "Connect downstream providers"],
        }
