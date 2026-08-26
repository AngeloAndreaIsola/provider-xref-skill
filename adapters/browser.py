"""
browser.py — Browser MCP adapter for OmniRoute browser automation.

Uses the Playwright MCP server (configured in config.yaml under mcp_servers)
to drive browser-based OAuth flows and manual signup steps.

This adapter provides low-level primitives.  Provider-specific workflows
(e.g. oauth.py, google.py) compose these primitives.
"""

from __future__ import annotations

from typing import Any


# ── Browser automation primitives ───────────────────────────────────────

def navigate(url: str) -> dict:
    """
    Navigate to a URL in the browser.

    Uses the browser_navigate tool (Playwright MCP).
    """
    # This is a thin wrapper around the MCP browser tools.
    # In the Hermes runtime, browser_navigate is available as a tool call.
    return {
        "action": "navigate",
        "url": url,
        "description": f"Navigate to {url}",
    }


def click(selector: str) -> dict:
    """Click an element identified by a CSS selector or XPath."""
    return {
        "action": "click",
        "selector": selector,
        "description": f"Click element: {selector}",
    }


def type_text(selector: str, text: str, submit: bool = False) -> dict:
    """Type text into an input field, optionally submitting."""
    action = {
        "action": "type",
        "selector": selector,
        "text": text,
        "description": f"Type into {selector}",
    }
    if submit:
        action["submit"] = True
        action["description"] = f"Type and submit into {selector}"
    return action


def fill_form(form_data: dict[str, str], form_selector: str = "form") -> dict:
    """Fill a form with multiple fields."""
    return {
        "action": "fill_form",
        "form_selector": form_selector,
        "fields": form_data,
        "description": f"Fill form at {form_selector} with {len(form_data)} fields",
    }


def screenshot() -> dict:
    """Take a screenshot of the current page."""
    return {"action": "screenshot", "description": "Capture current page"}


def get_text(selector: str) -> dict:
    """Extract text from an element."""
    return {"action": "get_text", "selector": selector}


def wait_for_text(text: str, timeout: int = 30) -> dict:
    """Wait for text to appear on the page."""
    return {"action": "wait_for_text", "text": text, "timeout": timeout}


def wait_for_element(selector: str, timeout: int = 30) -> dict:
    """Wait for an element to appear."""
    return {"action": "wait_for_element", "selector": selector, "timeout": timeout}


# ── OAuth Flow ──────────────────────────────────────────────────────────

def oauth_flow(provider_id: str, provider_config: dict, identity: dict | None = None,
               callback_url: str | None = None) -> dict:
    """
    Execute an OAuth flow for a provider using browser automation.

    Steps:
    1. Navigate to provider's OAuth consent page
    2. Select/sign in with the provided identity
    3. Grant consent
    4. Wait for callback to OmniRoute
    5. Verify connection

    Returns a sequence of browser actions.
    """
    signup_url = provider_config.get("signup_url", "")
    login_url = provider_config.get("login_url", signup_url)

    actions = []

    # Step 1: Navigate to login/consent page
    actions.append({
        "step": "open_provider",
        "description": f"Navigate to {provider_config.get('name', provider_id)} login",
        "action": "navigate",
        "url": login_url,
    })

    # Step 2: Sign in with identity
    if identity:
        email = identity.get("value", "")
        actions.append({
            "step": "sign_in",
            "description": f"Enter email: {email}",
            "action": "type",
            "selector": "input[type='email'], input[name='email'], input[name='identifier']",
            "text": email,
            "submit": True,
        })

        actions.append({
            "step": "password",
            "description": "Enter password from 1Password",
            "action": "type",
            "selector": "input[type='password']",
            "text": "<PASSWORD_RETRIEVED_FROM_1PASSWORD>",
            "submit": True,
        })

    # Step 3: OAuth consent
    actions.append({
        "step": "oauth_consent",
        "description": "Grant OAuth consent",
        "action": "click",
        "selector": "button[type='submit'], .consent-button, #approve, .oauth-allow",
    })

    # Step 4: Wait for redirect/callback
    if callback_url:
        actions.append({
            "step": "wait_for_callback",
            "description": f"Wait for redirect to {callback_url}",
            "action": "wait_for_url",
            "url_contains": callback_url,
            "timeout": 120,
        })
    else:
        actions.append({
            "step": "wait_for_callback",
            "description": "Wait for OAuth callback to complete",
            "action": "wait_for_text",
            "text": "success",
            "timeout": 120,
        })

    # Step 5: Human checkpoint — CAPTCHA, phone verification, etc.
    actions.append({
        "step": "checkpoint",
        "description": "Check for human verification (CAPTCHA, phone, ToS)",
        "action": "checkpoint",
        "type": "human_verify",
    })

    return {
        "provider_id": provider_id,
        "total_actions": len(actions),
        "actions": actions,
    }


# ── API Key Flow ───────────────────────────────────────────────────────

def api_key_flow(provider_id: str, provider_config: dict, identity: dict | None = None) -> dict:
    """
    Execute an API-key provider signup flow.

    Steps:
    1. Navigate to signup page
    2. Fill registration form (email, password)
    3. Verify email (click link / enter code)
    4. Log in to dashboard
    5. Create API key
    6. Store in 1Password
    7. Connect to OmniRoute
    8. Verify

    Returns a sequence of browser actions.
    """
    signup_url = provider_config.get("signup_url", "")
    login_url = provider_config.get("login_url", signup_url)

    actions = []

    # Step 1: Navigate to signup
    actions.append({
        "step": "open_signup",
        "description": f"Navigate to {provider_config.get('name', provider_id)} signup",
        "action": "navigate",
        "url": signup_url,
    })

    # Step 2: Fill registration form
    if identity:
        email = identity.get("value", "")
        actions.append({
            "step": "fill_registration",
            "description": "Fill registration form",
            "action": "fill_form",
            "form_selector": "form",
            "fields": {"email": email, "password": "<GENERATED_PASSWORD>"},
        })

        actions.append({
            "step": "submit_registration",
            "description": "Submit registration form",
            "action": "click",
            "selector": "button[type='submit'], input[type='submit']",
        })

    # Step 3: Email verification
    actions.append({
        "step": "email_verification",
        "description": "Check email for verification link",
        "action": "checkpoint",
        "type": "email_verify",
    })

    # Step 4: Login to dashboard
    actions.append({
        "step": "login_to_dashboard",
        "description": "Log in to get to the API key dashboard",
        "action": "navigate",
        "url": login_url,
    })

    actions.append({
        "step": "login_form",
        "description": "Fill login form",
        "action": "fill_form",
        "form_selector": "form",
        "fields": {"email": "<EMAIL>", "password": "<GENERATED_PASSWORD>"},
    })

    # Step 5: Navigate to API key creation
    dashboard_url = provider_config.get("dashboard_url", "")
    if dashboard_url:
        actions.append({
            "step": "open_dashboard",
            "description": "Navigate to API key dashboard",
            "action": "navigate",
            "url": dashboard_url,
        })

    actions.append({
        "step": "create_api_key",
        "description": "Create a new API key",
        "action": "click",
        "selector": "button.create-api-key, .create-key-button, [data-action='create-key']",
    })

    # Step 6: Extract API key
    actions.append({
        "step": "extract_api_key",
        "description": "Extract the newly created API key (copy to clipboard or read field)",
        "action": "checkpoint",
        "type": "api_key_extract",
    })

    # Step 7: Human checkpoint for CAPTCHA/ToS
    actions.append({
        "step": "checkpoint",
        "description": "Check for CAPTCHA or unexpected verification",
        "action": "checkpoint",
        "type": "human_verify",
    })

    return {
        "provider_id": provider_id,
        "total_actions": len(actions),
        "actions": actions,
    }


# ── Human checkpoint detection ─────────────────────────────────────────

def check_human_checkpoint(current_actions: list[dict]) -> dict | None:
    """
    Check if the current page state requires human intervention.

    Returns a checkpoint object if human action is needed, None otherwise.
    """
    # This would be called after each step to check page state
    # In the real implementation, this evaluates the browser snapshot
    return {
        "type": "check",
        "description": "Check for CAPTCHA, phone verification, ToS, or payment requirements",
        "selectors": [
            "iframe[title*='captcha']",        # CAPTCHA
            ".captcha-container",
            "input[name='phone_number']",       # Phone verification
            "input[name='sms_code']",           # SMS code
            ".recaptcha",                       # reCAPTCHA
            "[data-testid='tos']",             # Terms of service
            ".payment-form",                    # Payment
        ],
    }


# ── Consent page generation ─────────────────────────────────────────────

def generate_consent_message(provider_name: str, action: str, details: str) -> str:
    """Generate a human-readable consent message for interactive mode."""
    return f"""Registration paused.

Provider: {provider_name}
Action: {action}
Details: {details}

Everything before this step is complete.
Reply with the required action or type 'cancel' to abort.
"""


# ── Adapter wrapper class ──────────────────────────────────────────────

class Adapter:
    """Browser MCP adapter wrapper — delegates to module-level functions."""

    def navigate(self, url):
        return navigate(url)

    def click(self, selector):
        return click(selector)

    def type_text(self, selector, text, submit=False):
        return type_text(selector, text, submit)

    def fill_form(self, form_data, form_selector="form"):
        return fill_form(form_data, form_selector)

    def screenshot(self):
        return screenshot()

    def get_text(self, selector):
        return get_text(selector)

    def wait_for_text(self, text, timeout=30):
        return wait_for_text(text, timeout)

    def wait_for_element(self, selector, timeout=30):
        return wait_for_element(selector, timeout)

    def oauth_flow(self, provider_id, provider_config, identity=None, callback_url=None):
        return oauth_flow(provider_id, provider_config, identity, callback_url)

    def api_key_flow(self, provider_id, provider_config, identity=None):
        return api_key_flow(provider_id, provider_config, identity)

    def check_human_checkpoint(self, current_actions=None):
        return check_human_checkpoint(current_actions or [])

    def generate_consent_message(self, provider_name, action, details):
        return generate_consent_message(provider_name, action, details)
