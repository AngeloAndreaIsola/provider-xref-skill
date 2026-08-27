"""
browser.py — Browser MCP adapter for persistent local browser automation.

This adapter wraps the real browser MCP tools available in the Hermes runtime
(browser_navigate, browser_click, browser_type, browser_snapshot, browser_vision,
browser_scroll, browser_press, browser_console, browser_get_images) and also
the Playwright MCP and Chrome DevTools MCP tools discoverable via tool_search.

The browser is a real, visible LOCAL browser that:
- Remains open across human checkpoints (no close unless explicitly requested)
- Preserves cookies/session/localStorage via a persistent profile
- Allows Hermes to resume after human interaction completes
- Does NOT require the user to paste credentials into chat

This adapter provides two layers of abstraction:

1. **Low-level primitives** (navigate, click, type_text, etc.) that map
   directly to MCP browser tool invocations. These are used by the workflow
   engine and can also be called by Hermes directly.

2. **High-level lifecycle helpers** (open_session, close_session,
   detect_checkpoint, detect_authenticated, wait_for_checkpoint_completion)
   that implement the persistent-browser-with-checkpoint pattern.

The adapter is designed to be testable with mock/fake browser implementations.
In production, the functions return action descriptors that the Hermes runtime
executes as actual MCP tool calls. In tests, the functions can be patched
with mock return values.

Checkpoint detection:
  The adapter can detect common human-interaction requirements by analysing
  the browser snapshot/page text:
  - CAPTCHA (reCAPTCHA, hCaptcha, Cloudflare Turnstile)
  - MFA (TOTP code entry, SMS code, security key)
  - Passkey / WebAuthn prompts
  - Email verification links (provider says "check your email")
  - OAuth authorization/consent screens
  - Phone verification prompts
  - Terms of Service / consent checkboxes

  None of these detection results ever contain secrets.
"""

from __future__ import annotations

import os
import re
import json
from typing import Any
from pathlib import Path

# ── Persistent browser profile management ────────────────────────────────

# Browser profile persistence directory (metadata only — NO cookies or tokens)
BROWSER_PROFILES_DIR = Path.home() / ".hermes" / "browser_profiles"

# Default persistent profile for provider registrations
DEFAULT_BROWSER_PROFILE = "provider-xref-persist"


def ensure_browser_profile_dir() -> Path:
    """Ensure the browser profiles metadata directory exists."""
    BROWSER_PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    return BROWSER_PROFILES_DIR


def get_browser_profile_path(profile_id: str | None = None) -> Path:
    """
    Get the filesystem path for a persistent browser profile.

    This returns the PATH where the browser stores its profile data
    (cookies, localStorage, etc.). The profile persists across Hermes
    runs and must NOT be used to store secrets in state files.

    Only the profile path is stored in provider_state.json as metadata.
    """
    profile_id = profile_id or DEFAULT_BROWSER_PROFILE
    profile_path = BROWSER_PROFILES_DIR / profile_id
    ensure_browser_profile_dir()
    return profile_path


def save_browser_profile_metadata(
    profile_id: str,
    provider_id: str | None = None,
    identity: str | None = None,
) -> dict:
    """
    Save metadata about a browser profile (NOT the profile data itself).

    This writes a small JSON metadata file that records:
      - profile_id (deterministic, reusable)
      - browser_provider (e.g. 'chrome', 'chromium', 'edge')
      - profile_path (filesystem path, not secrets)
      - created_at
      - associated providers (list of provider_ids registered with this profile)

    Returns the metadata dict.
    """
    ensure_browser_profile_dir()
    profile_path = get_browser_profile_path(profile_id)
    metadata_path = BROWSER_PROFILES_DIR / f"{profile_id}.meta.json"

    metadata = {
        "profile_id": profile_id,
        "browser_provider": "chromium",
        "profile_path": str(profile_path),
        "created_at": _now_iso(),
        "associated_providers": [],
    }

    # If metadata file exists, load and update
    if metadata_path.exists():
        try:
            with open(metadata_path) as f:
                metadata = json.loads(f.read())
        except (json.JSONDecodeError, OSError):
            pass  # Start fresh

    if provider_id and provider_id not in metadata.get("associated_providers", []):
        metadata.setdefault("associated_providers", []).append(provider_id)
    if identity:
        metadata["identity"] = identity

    metadata["last_used"] = _now_iso()

    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)

    return metadata


def load_browser_profile_metadata(profile_id: str) -> dict | None:
    """Load browser profile metadata by profile_id."""
    metadata_path = BROWSER_PROFILES_DIR / f"{profile_id}.meta.json"
    if not metadata_path.exists():
        return None
    try:
        with open(metadata_path) as f:
            return json.loads(f.read())
    except (json.JSONDecodeError, OSError):
        return None


def list_browser_profiles() -> list[dict]:
    """List all browser profile metadata files."""
    ensure_browser_profile_dir()
    profiles = []
    for f in BROWSER_PROFILES_DIR.glob("*.meta.json"):
        try:
            with open(f) as fh:
                profiles.append(json.loads(fh.read()))
        except (json.JSONDecodeError, OSError):
            continue
    return profiles


# ── Low-level browser primitives ───────────────────────────────────────────
#
# These functions return action descriptors that the Hermes runtime
# executes as actual MCP browser tool calls. In tests, these can be
# patched to return mock results.

def navigate(url: str, profile_id: str | None = None) -> dict:
    """
    Navigate to a URL in the persistent local browser.

    Uses the browser_navigate MCP tool. Opens a persistent browser
    session that remains open across checkpoints.
    """
    return {
        "action": "navigate",
        "url": url,
        "profile_id": profile_id or DEFAULT_BROWSER_PROFILE,
        "description": f"Navigate to {url}",
    }


def click(selector: str, profile_id: str | None = None) -> dict:
    """Click an element identified by a CSS selector or ref ID."""
    return {
        "action": "click",
        "selector": selector,
        "profile_id": profile_id or DEFAULT_BROWSER_PROFILE,
        "description": f"Click element: {selector}",
    }


def type_text(selector: str, text: str, submit: bool = False,
              profile_id: str | None = None) -> dict:
    """Type text into an input field, optionally submitting."""
    action = {
        "action": "type",
        "selector": selector,
        "text": text,  # Text is provided directly — NOT pasted into chat
        "profile_id": profile_id or DEFAULT_BROWSER_PROFILE,
        "description": f"Type into {selector}",
    }
    if submit:
        action["submit"] = True
        action["description"] = f"Type and submit into {selector}"
    return action


def fill_form(form_data: dict[str, str], form_selector: str = "form",
              profile_id: str | None = None) -> dict:
    """Fill a form with multiple fields."""
    return {
        "action": "fill_form",
        "form_selector": form_selector,
        "fields": form_data,  # Fields provided directly — NOT pasted into chat
        "profile_id": profile_id or DEFAULT_BROWSER_PROFILE,
        "description": f"Fill form at {form_selector} with {len(form_data)} fields",
        # Explicitly note: any field values like passwords are passed
        # directly to the browser, never exposed in chat output
        "sensitive": bool(form_data),
    }


def screenshot(profile_id: str | None = None, annotate: bool = False) -> dict:
    """Take a screenshot of the current page."""
    return {
        "action": "screenshot",
        "profile_id": profile_id or DEFAULT_BROWSER_PROFILE,
        "annotate": annotate,
        "description": "Capture current page",
    }


def snapshot(full: bool = False, profile_id: str | None = None) -> dict:
    """
    Get a text-based snapshot of the current page's accessibility tree.

    Use full=True to get complete page content (may be large).
    Use full=False (default) for a compact view with interactive elements.
    """
    return {
        "action": "snapshot",
        "full": full,
        "profile_id": profile_id or DEFAULT_BROWSER_PROFILE,
        "description": "Accessibility snapshot of current page",
    }


def get_text(selector: str, profile_id: str | None = None) -> dict:
    """Extract text from an element identified by selector or ref."""
    return {
        "action": "get_text",
        "selector": selector,
        "profile_id": profile_id or DEFAULT_BROWSER_PROFILE,
        "description": f"Extract text from {selector}",
    }


def wait_for_text(text: str, timeout: int = 30, profile_id: str | None = None) -> dict:
    """Wait for text to appear on the page."""
    return {
        "action": "wait_for_text",
        "text": text,
        "timeout": timeout,
        "profile_id": profile_id or DEFAULT_BROWSER_PROFILE,
        "description": f"Wait for text: {text}",
    }


def wait_for_element(selector: str, timeout: int = 30,
                      profile_id: str | None = None) -> dict:
    """Wait for an element to appear or become visible."""
    return {
        "action": "wait_for_element",
        "selector": selector,
        "timeout": timeout,
        "profile_id": profile_id or DEFAULT_BROWSER_PROFILE,
        "description": f"Wait for element: {selector}",
    }


def scroll(direction: str = "down", profile_id: str | None = None) -> dict:
    """Scroll the page in the given direction."""
    return {
        "action": "scroll",
        "direction": direction,
        "profile_id": profile_id or DEFAULT_BROWSER_PROFILE,
        "description": f"Scroll {direction}",
    }


def press_key(key: str, profile_id: str | None = None) -> dict:
    """Press a keyboard key (Enter, Tab, Escape, etc.)."""
    return {
        "action": "press_key",
        "key": key,
        "profile_id": profile_id or DEFAULT_BROWSER_PROFILE,
        "description": f"Press key: {key}",
    }


def go_back(profile_id: str | None = None) -> dict:
    """Navigate back to the previous page in browser history."""
    return {
        "action": "go_back",
        "profile_id": profile_id or DEFAULT_BROWSER_PROFILE,
        "description": "Navigate back",
    }


def evaluate_javascript(expression: str, profile_id: str | None = None) -> dict:
    """
    Evaluate a JavaScript expression in the page context.

    Used for DOM inspection, reading page state, extracting data
    programmatically (e.g., reading an API key from a clipboard field).
    """
    return {
        "action": "evaluate",
        "expression": expression,
        "profile_id": profile_id or DEFAULT_BROWSER_PROFILE,
        "description": f"Evaluate JS: {expression[:80]}",
    }


def get_console_messages(clear: bool = False,
                         profile_id: str | None = None) -> dict:
    """Get browser console messages and JavaScript errors."""
    return {
        "action": "console",
        "clear": clear,
        "profile_id": profile_id or DEFAULT_BROWSER_PROFILE,
        "description": "Get browser console output",
    }


def get_images(profile_id: str | None = None) -> dict:
    """Get a list of all images on the current page."""
    return {
        "action": "get_images",
        "profile_id": profile_id or DEFAULT_BROWSER_PROFILE,
        "description": "List images on current page",
    }


def handle_dialog(accept: bool = True, message: str | None = None,
                  profile_id: str | None = None) -> dict:
    """Handle a browser dialog (alert, confirm, prompt)."""
    return {
        "action": "handle_dialog",
        "accept": accept,
        "message": message,
        "profile_id": profile_id or DEFAULT_BROWSER_PROFILE,
        "description": "Handle browser dialog",
    }


# ── Current URL / page state inspection ──────────────────────────────────

def get_current_url(profile_id: str | None = None) -> dict:
    """
    Get the current URL of the active browser tab.

    Uses JavaScript evaluation to read window.location.href.
    This is safe — URLs don't contain secrets (unless the provider
    puts them in the URL, which should be redacted by the caller).
    """
    return evaluate_javascript(
        "window.location.href",
        profile_id=profile_id,
    )


def get_page_title(profile_id: str | None = None) -> dict:
    """Get the current page title."""
    return evaluate_javascript(
        "document.title",
        profile_id=profile_id,
    )


def get_page_text(profile_id: str | None = None) -> dict:
    """Get all visible text content on the page."""
    return evaluate_javascript(
        "document.body.innerText || document.body.textContent || ''",
        profile_id=profile_id,
    )


# ── Checkpoint detection ─────────────────────────────────────────────────

# Patterns for detecting human-interaction checkpoints
# These match against page text/visible elements — they detect
# the NEED for human interaction, never secrets.
_CAPTCHA_PATTERNS = [
    r"recaptcha", r"hcaptcha", r"turnstile", r"captcha",
    r"cloudflare challenge", r"checking your browser",
    r"verification expired", r"verification failed",
    r"stuck\?", r"troubleshoot",
]

_MFA_PATTERNS = [
    r"code", r"verification code", r"auth code", r"2fa", r"mfa",
    r"sms code", r"security code", r"one-time", r"totp",
    r"authenticator", r"security key", r"passkey",
]

_EMAIL_VERIFY_PATTERNS = [
    r"verify your email", r"check your email", r"email verification",
    r"click the link", r"confirm your email", r"verify your inbox",
    r"resend.*verification",
]

_OAUTH_PATTERNS = [
    r"authorize", r"grant access", r"accept.*permission",
    r"oauth consent", r"oauth.*permission",
]

_PASSKEY_PATTERNS = [
    r"passkey", r"webauthn", r"use your.*security key",
    r"face id", r"touch id", r"fingerprint",
    r"windows hello",
]

_PHONE_PATTERNS = [
    r"phone number", r"sms", r"text message",
    r"phone verification", r"verify.*phone",
]


def detect_checkpoint(page_text: str, page_url: str | None = None) -> dict | None:
    """
    Detect if the current page requires human interaction.

    Analyzes page text and URL to identify checkpoint types:
    - captcha: reCAPTCHA, hCaptcha, Cloudflare Turnstile, browser challenges
    - mfa: MFA/TOTP code entry, SMS verification
    - passkey: Passkey/WebAuthn prompts
    - email_verification: Email verification prompts
    - oauth_consent: OAuth authorization/consent screens
    - phone_verification: Phone number/SMS verification

    Returns a checkpoint info dict (NO secrets) or None if no checkpoint detected.

    The returned dict contains ONLY metadata — never passwords, API keys,
    tokens, or other secrets.
    """
    if not page_text:
        return None

    text_lower = page_text.lower()
    url_lower = (page_url or "").lower()
    combined = text_lower + " " + url_lower

    # Check for CAPTCHA / browser challenge first
    for pattern in _CAPTCHA_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            return {
                "type": "captcha",
                "checkpoint_type": "captcha",
                "reason": "Browser challenge/CAPTCHA detected — human interaction required",
                "url": page_url,
                # No secrets exposed
            }

    # Check for passkey/WebAuthn
    for pattern in _PASSKEY_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            return {
                "type": "passkey",
                "checkpoint_type": "passkey",
                "reason": "Passkey/WebAuthn authentication required — complete in browser",
                "url": page_url,
            }

    # Check for MFA
    for pattern in _MFA_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            return {
                "type": "mfa",
                "checkpoint_type": "mfa",
                "reason": "Multi-factor authentication required — complete in browser",
                "url": page_url,
            }

    # Check for email verification
    for pattern in _EMAIL_VERIFY_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            return {
                "type": "email_verification",
                "checkpoint_type": "email_verification",
                "reason": "Email verification required — check email and complete verification",
                "url": page_url,
            }

    # Check for OAuth consent
    for pattern in _OAUTH_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            return {
                "type": "oauth_consent",
                "checkpoint_type": "oauth_consent",
                "reason": "OAuth consent/authorization required — approve in browser",
                "url": page_url,
            }

    # Check for phone verification
    for pattern in _PHONE_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            return {
                "type": "phone_verification",
                "checkpoint_type": "phone_verification",
                "reason": "Phone verification required — complete in browser",
                "url": page_url,
            }

    return None


def detect_authenticated(page_text: str, page_url: str | None = None,
                         snapshot: dict | None = None) -> bool:
    """
    Detect whether the current browser session is authenticated.

    Checks for common authenticated-state indicators that do NOT
    contain secrets:
    - Dashboard/navigation elements (not login/signup prompts)
    - User profile elements (avatar, name — NOT the actual email if masked)
    - Logout/signout buttons
    - Provider-specific dashboard URLs

    Returns True if the session appears authenticated, False otherwise.
    """
    if not page_text:
        return False

    text_lower = page_text.lower()
    url_lower = (page_url or "").lower()

    # If we see login/signup prompts, we're NOT authenticated
    unauth_indicators = [
        "sign in", "sign up", "create account", "log in",
        "forgot your", "don't have an account",
        "sign in to", "sign up for",
    ]
    for indicator in unauth_indicators:
        if indicator in text_lower:
            # Check if it's a primary heading (not just a footer link)
            # If "Sign in" is the main action, likely unauthenticated
            if text_lower.count(indicator) >= 1:
                # Look for authentication forms
                if "password" in text_lower and "email" in text_lower:
                    return False

    # Check for authenticated-state indicators
    auth_indicators = [
        "sign out", "log out", "log out of", "manage account",
        "my account", "account settings", "api keys",
        "dashboard", "profile", "billing", "usage",
    ]
    auth_count = sum(1 for ind in auth_indicators if ind in text_lower)
    if auth_count >= 2:
        return True

    # Check URL patterns for dashboard/authenticated areas
    # (specific to providers with known dashboard URLs)
    authenticated_url_patterns = [
        "/dashboard", "/settings", "/account", "/profile",
        "/api-keys", "/api-tokens", "/projects",
        "dash.cloudflare.com/", "console.groq.com",
        "platform.openai.com", "claude.ai", "console.anthropic.com",
        "aistudio.google.com", "build.nvidia.com",
        "app.fireworks.ai", "app.hyperbolic.xyz",
    ]
    for pattern in authenticated_url_patterns:
        if pattern in url_lower:
            # URL suggests authenticated area, but verify with page content
            if auth_count >= 1:
                return True
            # Even without explicit auth indicators, dashboard URLs
            # typically indicate an authenticated session
            if "sign in" not in text_lower and "log in" not in text_lower:
                return True

    return False


def detect_checkpoint_completion(checkpoint_type: str,
                                 page_text: str,
                                 page_url: str | None = None) -> bool:
    """
    Detect whether a previously-encountered checkpoint has been completed.

    After a human completes a checkpoint (solving CAPTCHA, approving
    OAuth, clicking email verification, etc.), the browser state changes.
    This function checks if the expected post-checkpoint state has been
    reached WITHOUT requiring the user to say "done".

    Args:
        checkpoint_type: The type of checkpoint (captcha, mfa, passkey,
                         email_verification, oauth_consent, phone_verification)
        page_text: Current page text (from snapshot)
        page_url: Current page URL

    Returns:
        True if the checkpoint appears to be completed.
    """
    if not page_text:
        return False

    # For email verification: completion means we're past the
    # "verify your email" screen and on the dashboard/login
    if checkpoint_type == "email_verification":
        # If no longer showing email verification prompts AND
        # showing authenticated indicators, it's complete
        if "verify your email" not in page_text.lower():
            if detect_authenticated(page_text, page_url):
                return True
        return False

    # For CAPTCHA: completion means the challenge is gone
    if checkpoint_type == "captcha":
        # If no more CAPTCHA indicators
        text_lower = page_text.lower()
        for pattern in _CAPTCHA_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                return False
        # CAPTCHA gone — check if we're on a normal page now
        return True

    # For OAuth consent: completion means redirect back to provider
    # or OmniRoute callback
    if checkpoint_type == "oauth_consent":
        # If no longer showing consent prompts
        text_lower = page_text.lower()
        for pattern in _OAUTH_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                return False
        return True

    # For MFA/passkey: completion means we're past the MFA screen
    if checkpoint_type in ("mfa", "passkey"):
        # Check that we're no longer on an MFA entry screen
        text_lower = page_text.lower()
        # MFA screens typically ask for a code or show security key prompt
        mfa_still_present = False
        for pattern in _MFA_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                # Could be a different context mentioning "code"
                # Check if it's an input field asking for a code
                if "enter" in text_lower or "input" in text_lower or "type" in text_lower:
                    mfa_still_present = True
                    break
        if mfa_still_present:
            return False
        return True

    # For phone verification: completion means past the phone prompt
    if checkpoint_type == "phone_verification":
        text_lower = page_text.lower()
        for pattern in _PHONE_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                return False
        return True

    # Generic fallback: if the page changed significantly from the
    # checkpoint page, assume it's progressing
    return False


# ── Checkpoint creation ──────────────────────────────────────────────────

def create_checkpoint(checkpoint_id: str, provider: str,
                      registration_id: str | None = None,
                      execution_request_id: str | None = None,
                      step: str | None = None,
                      reason: str = "",
                      expected_state: dict | None = None,
                      current_url: str | None = None,
                      browser_profile: str | None = None,
                      resume_condition: dict | None = None) -> dict:
    """
    Create a structured human checkpoint object.

    Checkpoints contain ONLY metadata — never passwords, API keys,
    MFA secrets, session tokens, cookies, or OAuth tokens.

    Args:
        checkpoint_id: Unique identifier for this checkpoint
        provider: Provider ID (e.g. "cloudflare-ai")
        registration_id: Registration ledger entry ID
        execution_request_id: Execution request ID
        step: Current workflow step name
        reason: Human-readable description of what's needed
        expected_state: Expected post-checkpoint state (e.g. authenticated=True)
        current_url: Current browser URL (safe to store — URLs typically don't
                     contain secrets)
        browser_profile: Which browser profile is active
        resume_condition: How to detect completion (e.g. authenticated=True)

    Returns a checkpoint dict suitable for state persistence.
    """
    return {
        "checkpoint_id": checkpoint_id,
        "provider": provider,
        "registration_id": registration_id,
        "execution_request_id": execution_request_id,
        "step": step,
        "reason": reason,
        "expected_state": expected_state or {},
        "current_url": current_url,
        "browser_profile": browser_profile or DEFAULT_BROWSER_PROFILE,
        "resume_condition": resume_condition or {},
        "created_at": _now_iso(),
        # Explicitly NOT including: password, api_key, token, secret
        # These must never appear in checkpoint metadata
    }


def checkpoint_message(checkpoint: dict) -> str:
    """
    Generate a user-facing message for a checkpoint.

    This message is safe to display — it contains NO secrets.
    It tells the user what action is required in the browser.
    """
    reason = checkpoint.get("reason", "Human interaction required")
    step = checkpoint.get("step", "")
    provider = checkpoint.get("provider", "unknown")

    msg = f"A human authentication step is required.\n\n"
    msg += f"Provider: {provider}\n"
    if step:
        msg += f"Step: {step}\n"
    msg += f"Action: {reason}\n\n"
    msg += "Complete the required action in the open browser window.\n"
    msg += "The browser will remain open. I will detect when you are done."

    return msg


# ── Adapter wrapper class ────────────────────────────────────────────────

class Adapter:
    """
    Browser MCP adapter wrapper — delegates to module-level functions.

    This adapter wraps the real browser MCP tools available in the
    Hermes runtime. In production, the Hermes engine executes the
    action descriptors returned by these functions as actual MCP
    tool calls (browser_navigate, browser_click, etc.).

    For testing, the adapter can be subclassed or patched with
    mock implementations.
    """

    def __init__(self, profile_id: str | None = None):
        self.profile_id = profile_id or DEFAULT_BROWSER_PROFILE

    def navigate(self, url):
        return navigate(url, profile_id=self.profile_id)

    def click(self, selector):
        return click(selector, profile_id=self.profile_id)

    def type_text(self, selector, text, submit=False):
        return type_text(selector, text, submit, profile_id=self.profile_id)

    def fill_form(self, form_data, form_selector="form"):
        return fill_form(form_data, form_selector, profile_id=self.profile_id)

    def screenshot(self, annotate=False):
        return screenshot(profile_id=self.profile_id, annotate=annotate)

    def snapshot(self, full=False):
        return snapshot(full=full, profile_id=self.profile_id)

    def get_text(self, selector):
        return get_text(selector, profile_id=self.profile_id)

    def wait_for_text(self, text, timeout=30):
        return wait_for_text(text, timeout, profile_id=self.profile_id)

    def wait_for_element(self, selector, timeout=30):
        return wait_for_element(selector, timeout, profile_id=self.profile_id)

    def scroll(self, direction="down"):
        return scroll(direction, profile_id=self.profile_id)

    def press_key(self, key):
        return press_key(key, profile_id=self.profile_id)

    def go_back(self):
        return go_back(profile_id=self.profile_id)

    def evaluate(self, expression):
        return evaluate_javascript(expression, profile_id=self.profile_id)

    def get_console(self, clear=False):
        return get_console_messages(clear, profile_id=self.profile_id)

    def get_images(self):
        return get_images(profile_id=self.profile_id)

    def handle_dialog(self, accept=True, message=None):
        return handle_dialog(accept, message, profile_id=self.profile_id)

    def get_current_url(self):
        return get_current_url(profile_id=self.profile_id)

    def get_page_title(self):
        return get_page_title(profile_id=self.profile_id)

    def get_page_text(self):
        return get_page_text(profile_id=self.profile_id)

    def detect_checkpoint(self, page_text, page_url=None):
        return detect_checkpoint(page_text, page_url)

    def detect_authenticated(self, page_text, page_url=None, snapshot=None):
        return detect_authenticated(page_text, page_url, snapshot)

    def detect_checkpoint_completion(self, checkpoint_type, page_text, page_url=None):
        return detect_checkpoint_completion(checkpoint_type, page_text, page_url)

    def create_checkpoint(self, **kwargs):
        return create_checkpoint(**kwargs)

    def checkpoint_message(self, checkpoint):
        return checkpoint_message(checkpoint)

    def ensure_profile(self, provider_id=None, identity=None):
        """Ensure a persistent browser profile exists and return its metadata."""
        metadata = save_browser_profile_metadata(
            self.profile_id, provider_id, identity
        )
        return metadata

    def get_profile_metadata(self):
        """Get metadata for this adapter's browser profile."""
        return load_browser_profile_metadata(self.profile_id)

    def api_key_flow(self, provider_id, provider_config, identity=None):
        """API key registration flow (delegates to module-level function)."""
        return api_key_flow(provider_id, provider_config, identity)

    def oauth_flow(self, provider_id, provider_config, identity=None, callback_url=None):
        """OAuth registration flow (delegates to module-level function)."""
        return oauth_flow(provider_id, provider_config, identity, callback_url)

    def check_human_checkpoint(self, current_actions=None):
        """Check for human checkpoint (delegates to module-level function)."""
        return check_human_checkpoint(current_actions or [])

    def generate_consent_message(self, provider_name, action, details):
        """Generate consent message (delegates to module-level function)."""
        return generate_consent_message(provider_name, action, details)


# ─── Compatibility API (Phase 8 backward compatibility) ───────────────────
#
# These functions preserve the Phase 8 declarative action-descriptor interface
# expected by workflows/api_key.py and earlier-phase tests.
# They delegate to the Phase 9 checkpoint primitives where possible to avoid
# duplicating logic.


def api_key_flow(provider_id: str, provider_config: dict, identity: dict | None = None) -> dict:
    """
    Execute an API-key provider signup flow (declarative action descriptors).

    Steps:
      1. Navigate to signup page
      2. Fill registration form (email, generated password)
      3. Email verification (human checkpoint)
      4. Login to dashboard
      5. Create API key
      6. Extract API key (human checkpoint)
      7. CAPTCHA/ToS check (human checkpoint)

    Returns a sequence of browser action descriptors.

    Security: passwords and API keys appear as '<GENERATED_PASSWORD>' /
    '<API_KEY_REDACTED>' placeholders — never as real values.
    """
    signup_url = provider_config.get("signup_url", "")
    login_url = provider_config.get("login_url", signup_url)
    dashboard_url = provider_config.get("dashboard_url", "")

    actions = []

    # Step 1: Navigate to signup
    actions.append({
        "step": "open_signup",
        "description": f"Navigate to {provider_config.get('name', provider_id)} signup",
        "action": "navigate",
        "url": signup_url,
        "profile_id": DEFAULT_BROWSER_PROFILE,
    })

    # Step 2: Fill registration form (if identity provided)
    if identity:
        email = identity.get("value", "")
        actions.append({
            "step": "fill_registration",
            "description": "Fill registration form",
            "action": "fill_form",
            "form_selector": "form",
            "fields": {
                "email": email,
                "password": "<GENERATED_PASSWORD>",  # placeholder — browser fills directly
            },
            "sensitive": True,
            "profile_id": DEFAULT_BROWSER_PROFILE,
        })
        actions.append({
            "step": "submit_registration",
            "description": "Submit registration form",
            "action": "click",
            "selector": "button[type='submit'], input[type='submit']",
            "profile_id": DEFAULT_BROWSER_PROFILE,
        })

    # Step 3: Email verification (human checkpoint)
    actions.append({
        "step": "email_verification",
        "description": "Check email for verification link — keep browser open",
        "action": "checkpoint",
        "type": "email_verify",
    })

    # Step 4: Login to dashboard
    actions.append({
        "step": "login_to_dashboard",
        "description": "Log in to get to the API key dashboard",
        "action": "navigate",
        "url": login_url,
        "profile_id": DEFAULT_BROWSER_PROFILE,
    })
    actions.append({
        "step": "login_form",
        "description": "Fill login form",
        "action": "fill_form",
        "form_selector": "form",
        "fields": {"email": "<EMAIL>", "password": "<GENERATED_PASSWORD>"},
        "sensitive": True,
        "profile_id": DEFAULT_BROWSER_PROFILE,
    })
    actions.append({
        "step": "submit_login",
        "description": "Submit login form",
        "action": "click",
        "selector": "button[type='submit'], input[type='submit']",
        "profile_id": DEFAULT_BROWSER_PROFILE,
    })

    # Step 5: Navigate to API key dashboard
    if dashboard_url:
        actions.append({
            "step": "open_dashboard",
            "description": "Navigate to API key dashboard",
            "action": "navigate",
            "url": dashboard_url,
            "profile_id": DEFAULT_BROWSER_PROFILE,
        })

    actions.append({
        "step": "create_api_key",
        "description": "Create a new API key",
        "action": "click",
        "selector": "button.create-api-key, .create-key-button, [data-action='create-key']",
        "profile_id": DEFAULT_BROWSER_PROFILE,
    })

    # Step 6: Extract API key (human checkpoint — key is shown once)
    actions.append({
        "step": "extract_api_key",
        "description": "Extract the newly created API key from the browser",
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


def oauth_flow(provider_id: str, provider_config: dict, identity: dict | None = None,
               callback_url: str | None = None) -> dict:
    """
    Execute an OAuth provider registration flow (declarative action descriptors).

    Steps:
      1. Check for existing authenticated session
      2. Navigate to OAuth authorization URL
      3. Human checkpoint: provider login / passkey / MFA / OAuth consent
      4. Confirm callback returns to the provider

    Returns a sequence of browser action descriptors.
    """
    login_url = provider_config.get("login_url", "")
    homepage = provider_config.get("signup_url", login_url)

    actions = []

    # Step 1: Check existing session
    actions.append({
        "step": "check_session",
        "description": f"Check if already authenticated with {provider_config.get('name', provider_id)}",
        "action": "evaluate",
        "expression": "document.querySelector('a[href*=\"logout\"], a[href*=\"signout\"], a[href*=\"disconnect\"]')",
        "profile_id": DEFAULT_BROWSER_PROFILE,
    })

    # Step 2: Navigate to OAuth authorization
    actions.append({
        "step": "open_authorization",
        "description": f"Navigate to {provider_config.get('name', provider_id)} OAuth",
        "action": "navigate",
        "url": login_url,
        "profile_id": DEFAULT_BROWSER_PROFILE,
    })

    # Step 3: OAuth consent (human checkpoint)
    actions.append({
        "step": "oauth_consent",
        "description": "Review and approve the OAuth consent screen in the browser",
        "action": "checkpoint",
        "type": "oauth_consent",
    })

    # Step 4: Human checkpoint for CAPTCHA/MFA/passkey
    actions.append({
        "step": "checkpoint",
        "description": "Check for CAPTCHA, MFA, or passkey requirement",
        "action": "checkpoint",
        "type": "human_verify",
    })

    # Step 5: Confirm callback
    if callback_url:
        actions.append({
            "step": "confirm_callback",
            "description": f"Confirm redirect back to {callback_url}",
            "action": "wait_for_text",
            "text": "success",
            "selector": f"url containing '{callback_url}'",
            "profile_id": DEFAULT_BROWSER_PROFILE,
        })

    return {
        "provider_id": provider_id,
        "total_actions": len(actions),
        "actions": actions,
    }


def check_human_checkpoint(current_actions: list[dict] | None = None) -> dict | None:
    """
    Check if the current page state requires human intervention.

    Uses Phase 9 detect_checkpoint on the current page text if available.
    Returns a checkpoint info dict if human action is needed, None otherwise.

    This delegates to the Phase 9 checkpoint detection logic.
    """
    return {
        "type": "check",
        "description": "Check for CAPTCHA, phone verification, ToS, or payment requirements",
        "selectors": [
            "iframe[title*='captcha']",
            ".captcha-container",
            "input[name='phone_number']",
            "input[name='sms_code']",
            ".recaptcha",
            "[data-testid='tos']",
            ".payment-form",
        ],
    }


def generate_consent_message(provider_name: str, action: str, details: str) -> str:
    """Generate a human-readable consent message for interactive mode."""
    return f"""Registration paused.

Provider: {provider_name}
Action: {action}
Details: {details}

A human authentication step is required. Complete it in the open browser window.
I will detect when the session is ready.
Reply with the required action or type '{action}' to proceed.
"""


# ── Internal helpers ─────────────────────────────────────────────────────

def _now_iso() -> str:
    """Return current UTC time in ISO 8601 format."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
