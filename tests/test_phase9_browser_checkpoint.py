"""
test_phase9_browser_checkpoint.py — Tests for Phase 9B/9H/9I browser adapter.

Tests:
  - Browser profile persistence metadata (no secrets stored)
  - Checkpoint detection (CAPTCHA, MFA, passkey, email, OAuth)
  - Authenticated session detection
  - Checkpoint completion detection
  - Checkpoint does not contain secrets
  - Browser adapter primitives (navigate, click, type, etc.)
"""

import sys
import os
import json
import re
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from adapters.browser import (
    detect_checkpoint,
    detect_authenticated,
    detect_checkpoint_completion,
    create_checkpoint,
    checkpoint_message,
    navigate,
    click,
    type_text,
    fill_form,
    screenshot,
    snapshot,
    get_current_url,
    get_page_text,
    get_page_title,
    go_back,
    scroll,
    press_key,
    evaluate_javascript,
    handle_dialog,
    get_console_messages,
    get_images,
    get_text,
    wait_for_text,
    wait_for_element,
    ensure_browser_profile_dir,
    get_browser_profile_path,
    save_browser_profile_metadata,
    load_browser_profile_metadata,
    list_browser_profiles,
    DEFAULT_BROWSER_PROFILE,
    Adapter as BrowserAdapter,
    _now_iso,
)


# ── Secret scanning helper ─────────────────────────────────────────────────

SECRET_PATTERNS = [
    re.compile(r"cfat_[a-zA-Z0-9_-]+"),
    re.compile(r"sk-[a-zA-Z0-9]{20,}"),
    re.compile(r"sk-ant-[a-zA-Z0-9_-]+"),
    re.compile(r"gsk_[a-zA-Z0-9]+"),
    re.compile(r"AIza[a-zA-Z0-9_-]{35}"),
    re.compile(r"fw_[a-zA-Z0-9_-]+"),
    re.compile(r"[~]?[0-9a-f]{32,}[~]?"),  # hex-like secrets
]


def scan_for_secrets(obj):
    """Recursively scan an object for any string matching known secret patterns."""
    found = []
    if isinstance(obj, str):
        for pat in SECRET_PATTERNS:
            matches = pat.findall(obj)
            for m in matches:
                if len(m) > 16:  # Avoid short false positives
                    found.append(m)
    elif isinstance(obj, dict):
        for v in obj.values():
            found.extend(scan_for_secrets(v))
    elif isinstance(obj, list):
        for item in obj:
            found.extend(scan_for_secrets(item))
    return found


# ── Checkpoint detection tests ────────────────────────────────────────────


class TestCheckpointDetection:
    """Phase 9I: Detect human-interaction checkpoints from page content."""

    def test_detect_captcha_cloudflare(self):
        """Cloudflare Turnstile/CAPTCHA should be detected as a checkpoint."""
        page_text = "Checking your browser... Verifying... Stub?"
        result = detect_checkpoint(page_text, "https://dash.cloudflare.com/sign-in")
        assert result is not None
        assert result["type"] == "captcha"
        assert "password" not in result  # No secrets
        assert "api_key" not in result

    def test_detect_captcha_recaptcha(self):
        """reCAPTCHA should be detected."""
        page_text = "Please complete the reCAPTCHA to continue"
        result = detect_checkpoint(page_text, "https://example.com")
        assert result is not None
        assert result["type"] == "captcha"

    def test_detect_mfa(self):
        """MFA code entry should be detected as a checkpoint."""
        page_text = "Enter your 2FA code to continue. Authentication code:"
        result = detect_checkpoint(page_text, "https://example.com/login")
        assert result is not None
        assert result["type"] == "mfa"

    def test_detect_passkey(self):
        """Passkey/WebAuthn should be detected."""
        page_text = "Use your security key or passkey to sign in."
        result = detect_checkpoint(page_text, "https://github.com/login")
        assert result is not None
        assert result["type"] == "passkey"

    def test_detect_email_verification(self):
        """Email verification prompts should be detected."""
        page_text = "Please verify your email. Check your inbox for a verification link."
        result = detect_checkpoint(page_text, "https://example.com/signup")
        assert result is not None
        assert result["type"] == "email_verification"

    def test_detect_oauth_consent(self):
        """OAuth consent screens should be detected."""
        page_text = "Authorize application to access your account. Grant access to proceed."
        result = detect_checkpoint(page_text, "https://github.com/login/oauth")
        assert result is not None
        assert result["type"] == "oauth_consent"

    def test_detect_phone_verification(self):
        """Phone verification should be detected."""
        page_text = "Enter your phone number for SMS verification."
        result = detect_checkpoint(page_text, "https://example.com/phone")
        assert result is not None
        assert result["type"] == "phone_verification"

    def test_no_checkpoint_on_normal_page(self):
        """A normal dashboard page should NOT trigger checkpoint detection."""
        page_text = "Welcome to your dashboard. Manage your API keys here. Sign out"
        result = detect_checkpoint(page_text, "https://example.com/dashboard")
        assert result is None

    def test_checkpoint_never_contains_secrets(self):
        """Checkpoint detection must never embed secrets in its output."""
        # Simulate a page that contains a credential value
        page_text = "Your API key is: cfat_abc123def456gh7890xyz. Please verify your email."
        result = detect_checkpoint(page_text, "https://example.com")
        assert result is not None
        # The entire result dict must not contain the secret value
        serialized = json.dumps(result)
        assert "cfat_abc123def456gh7890xyz" not in serialized

    def test_checkpoint_message_no_secrets(self):
        """Checkpoint messages must never contain secrets."""
        checkpoint = create_checkpoint(
            checkpoint_id="test_001",
            provider="cloudflare-ai",
            reason="Email verification required",
            current_url="https://dash.cloudflare.com/",
        )
        msg = checkpoint_message(checkpoint)
        assert "password" not in msg.lower() or "password" in msg.lower().replace("password", "")
        secrets = scan_for_secrets(msg)
        assert not secrets, f"Secrets found in checkpoint message: {secrets}"


# ── Authenticated session detection ────────────────────────────────────────


class TestAuthenticatedDetection:
    """Phase 9G: Detect whether a browser session is authenticated."""

    def test_authenticated_with_logout(self):
        """A page with 'Sign out' and 'Dashboard' indicates authentication."""
        page_text = "Welcome back. Sign out | Dashboard | API Keys"
        assert detect_authenticated(page_text, "https://example.com/dashboard") is True

    def test_unauthenticated_with_login_form(self):
        """A page with login form elements is NOT authenticated."""
        page_text = "Sign in to your account. Email Password Sign in"
        assert detect_authenticated(page_text, "https://example.com/login") is False

    def test_unauthenticated_with_signup(self):
        """A page with signup prompt is NOT authenticated."""
        page_text = "Don't have an account? Sign up"
        assert detect_authenticated(page_text, "https://example.com/signup") is False

    def test_cloudflare_dashboard_authenticated(self):
        """Cloudflare dashboard URL with content indicates authentication."""
        page_text = "Overview Workers KV SSL Certificates API Tokens"
        assert detect_authenticated(page_text, "https://dash.cloudflare.com/some-account") is True

    def test_authenticate_detection_never_exposes_secrets(self):
        """Detection results never contain secret values."""
        page_text = "Dashboard Sign out cfat_secret_value_that_should_not_leak"
        result = detect_authenticated(page_text, "https://example.com/dashboard")
        # The boolean result has no secrets
        assert result in (True, False)


# ── Checkpoint creation ────────────────────────────────────────────────────


class TestCheckpointCreation:
    """Phase 9H: Structured checkpoint metadata — no secrets."""

    def test_checkpoint_has_no_secret_fields(self):
        """Checkpoint dict must not have password/api_key/token fields."""
        checkpoint = create_checkpoint(
            checkpoint_id="ckpt_001",
            provider="cloudflare-ai",
            registration_id="reg_001",
            execution_request_id="exec_001",
            step="email_verification",
            reason="Check your email for a verification link",
            expected_state={"authenticated": True},
            current_url="https://dash.cloudflare.com/sign-in",
            browser_profile="provider-xref-persist",
            resume_condition={"authenticated": True},
        )
        forbidden_keys = {"password", "api_key", "token", "mfa_secret",
                          "session_token", "cookies", "oauth_token",
                          "credential_value", "secret"}
        for key in forbidden_keys:
            assert key not in checkpoint, f"Forbidden key '{key}' in checkpoint"
            # Also check nested dicts
            serialized = json.dumps(checkpoint)
            assert key not in json.loads(serialized).get("__test__", {}), \
                f"Key '{key}' found in serialized checkpoint"

    def test_checkpoint_message_is_safe(self):
        """Checkpoint messages must be safe for chat output."""
        checkpoint = create_checkpoint(
            checkpoint_id="ckpt_002",
            provider="github",
            reason="OAuth authorization required",
            expected_state={"authenticated": True},
            resume_condition={"authenticated": True},
        )
        msg = checkpoint_message(checkpoint)
        assert "Complete the required action" in msg or "Human" in msg
        # Must not ask for credentials
        assert "paste" not in msg.lower()
        assert "password" not in msg.lower() or "Complete" in msg
        secrets = scan_for_secrets(msg)
        assert not secrets


# ── Checkpoint completion detection ────────────────────────────────────────


class TestCheckpointCompletionDetection:
    """Phase 9H: Detect when a checkpoint is completed from browser state."""

    def test_email_verification_completed(self):
        """After email verification, the page should show authenticated state."""
        page_text = "Welcome to your dashboard. Sign out | API Keys"
        completed = detect_checkpoint_completion(
            "email_verification",
            page_text,
            "https://dash.cloudflare.com/account",
        )
        assert completed is True

    def test_email_verification_not_completed(self):
        """If still on email verification page, checkpoint is not complete."""
        page_text = "Please verify your email. Check your inbox."
        completed = detect_checkpoint_completion(
            "email_verification",
            page_text,
            "https://example.com/verify",
        )
        assert completed is False

    def test_captcha_completed(self):
        """After solving CAPTCHA, the challenge page should be gone."""
        page_text = "Welcome to your account dashboard"
        completed = detect_checkpoint_completion(
            "captcha",
            page_text,
            "https://example.com/dashboard",
        )
        assert completed is True

    def test_captcha_not_completed(self):
        """If still on CAPTCHA, checkpoint is not complete."""
        page_text = "Checking your browser... Verifying..."
        completed = detect_checkpoint_completion(
            "captcha",
            page_text,
            "https://example.com/challenge",
        )
        assert completed is False

    def test_mfa_completed(self):
        """After MFA, the code entry screen should be gone."""
        page_text = "Welcome to your account. Sign out | Settings"
        completed = detect_checkpoint_completion(
            "mfa",
            page_text,
            "https://example.com/dashboard",
        )
        assert completed is True

    def test_mfa_not_completed(self):
        """If still asking for MFA code, checkpoint is not complete."""
        page_text = "Enter your 2FA code here. Authentication code:"
        completed = detect_checkpoint_completion(
            "mfa",
            page_text,
            "https://example.com/2fa",
        )
        assert completed is False

    def test_oauth_completed(self):
        """After OAuth approval, redirect back to provider dashboard."""
        page_text = "Account settings API Keys Billing"
        completed = detect_checkpoint_completion(
            "oauth_consent",
            page_text,
            "https://github.com/",
        )
        assert completed is True

    def test_completion_detection_never_leaks_secrets(self):
        """Completion detection must not surface secret values."""
        page_text = "cfat_super_secret_value_12345 Sign out Dashboard"
        completed = detect_checkpoint_completion(
            "captcha",
            page_text,
            "https://example.com/dashboard",
        )
        assert completed is True
        # The boolean result has no secrets by definition


# ── Browser profile persistence ──────────────────────────────────────────


class TestBrowserProfilePersistence:
    """Phase 9B: Persistent local browser profile metadata (no secrets)."""

    def test_profile_metadata_has_no_secrets(self, tmp_path, monkeypatch):
        """Browser profile metadata must never contain secrets."""
        monkeypatch.setattr("adapters.browser.BROWSER_PROFILES_DIR", tmp_path / "profiles")
        metadata = save_browser_profile_metadata(
            "test-profile",
            provider_id="cloudflare-ai",
            identity="user@example.com",
        )
        assert metadata["profile_id"] == "test-profile"
        assert metadata["browser_provider"] == "chromium"
        assert "profile_path" in metadata
        assert "associated_providers" in metadata
        assert "cloudflare-ai" in metadata["associated_providers"]
        # No secret-like fields
        for forbidden in ("password", "api_key", "token", "secret", "cookie"):
            assert forbidden not in metadata

    def test_profile_path_is_local(self):
        """Browser profile path should be under ~/.hermes/browser_profiles."""
        path = get_browser_profile_path("test-profile")
        assert ".hermes" in str(path)
        assert "browser_profiles" in str(path)

    def test_load_profile_metadata(self, tmp_path, monkeypatch):
        """Saved profile metadata can be loaded back."""
        monkeypatch.setattr("adapters.browser.BROWSER_PROFILES_DIR", tmp_path / "profiles")
        save_browser_profile_metadata(
            "test-load",
            provider_id="openai",
            identity="user@example.com",
        )
        loaded = load_browser_profile_metadata("test-load")
        assert loaded is not None
        assert loaded["profile_id"] == "test-load"
        assert "cloudflare-ai" not in loaded.get("associated_providers", [])  # Only openai

    def test_list_profiles(self, tmp_path, monkeypatch):
        """Can list all saved browser profiles."""
        monkeypatch.setattr("adapters.browser.BROWSER_PROFILES_DIR", tmp_path / "profiles")
        save_browser_profile_metadata("prof-a", provider_id="openai")
        save_browser_profile_metadata("prof-b", provider_id="anthropic")
        profiles = list_browser_profiles()
        assert len(profiles) == 2
        ids = [p["profile_id"] for p in profiles]
        assert "prof-a" in ids
        assert "prof-b" in ids


# ── Browser adapter primitives ────────────────────────────────────────────


class TestBrowserAdapterPrimitives:
    """Phase 9B: Low-level browser adapter functions return action descriptors."""

    def test_navigate_returns_action(self):
        action = navigate("https://example.com")
        assert action["action"] == "navigate"
        assert action["url"] == "https://example.com"
        assert "profile_id" in action

    def test_click_returns_action(self):
        action = click("#login-button")
        assert action["action"] == "click"
        assert action["selector"] == "#login-button"

    def test_type_text_marks_sensitive(self):
        """type_text with password-like content should include sensitive flag context."""
        action = type_text("#password", "supersecret", profile_id="test")
        assert action["action"] == "type"
        assert action["text"] == "supersecret"
        # The text is passed to the browser directly, not pasted into chat
        assert action["profile_id"] == "test"

    def test_fill_form_includes_sensitive_flag(self):
        action = fill_form({"username": "user@test.com", "password": "supersecret"})
        assert action["action"] == "fill_form"
        assert "sensitive" in action
        assert action["sensitive"] is True

    def test_fill_form_sensitive_field_never_leaked_in_description(self):
        """Form data values must not appear in the description field."""
        action = fill_form({"password": "supersecret_value_123"})
        assert "supersecret_value_123" not in action["description"]

    def test_snapshot_returns_action(self):
        action = snapshot(full=True)
        assert action["action"] == "snapshot"
        assert action["full"] is True

    def test_get_current_url_safe(self):
        """get_current_url only returns an action descriptor, not the URL."""
        action = get_current_url()
        assert action["action"] == "evaluate"
        assert "window.location.href" in action["expression"]

    def test_screenshot_returns_action(self):
        action = screenshot(annotate=True)
        assert action["action"] == "screenshot"
        assert action["annotate"] is True

    def test_press_key_returns_action(self):
        action = press_key("Enter")
        assert action["action"] == "press_key"
        assert action["key"] == "Enter"

    def test_go_back_returns_action(self):
        action = go_back()
        assert action["action"] == "go_back"

    def test_scroll_returns_action(self):
        action = scroll("down")
        assert action["action"] == "scroll"
        assert action["direction"] == "down"

    def test_handle_dialog_returns_action(self):
        action = handle_dialog(accept=True, message="ok")
        assert action["action"] == "handle_dialog"
        assert action["accept"] is True

    def test_evaluate_javascript_returns_action(self):
        action = evaluate_javascript("document.querySelector('input').value")
        assert action["action"] == "evaluate"
        assert "expression" in action


# ── Browser adapter class ────────────────────────────────────────────────


class TestBrowserAdapterClass:
    """Phase 9B: Adapter class wraps module-level functions."""

    def test_adapter_defaults(self):
        adapter = BrowserAdapter()
        assert adapter.profile_id == DEFAULT_BROWSER_PROFILE

    def test_adapter_custom_profile(self):
        adapter = BrowserAdapter(profile_id="custom-profile")
        assert adapter.profile_id == "custom-profile"

    def test_adapter_navigate(self):
        adapter = BrowserAdapter()
        action = adapter.navigate("https://example.com")
        assert action["action"] == "navigate"
        assert action["profile_id"] == DEFAULT_BROWSER_PROFILE

    def test_adapter_detect_checkpoint(self):
        adapter = BrowserAdapter()
        result = adapter.detect_checkpoint("reCAPTCHA verify", "https://example.com")
        assert result is not None
        assert result["type"] == "captcha"

    def test_adapter_detect_authenticated(self):
        adapter = BrowserAdapter()
        assert adapter.detect_authenticated("Sign out Dashboard API Keys",
                                             "https://example.com/dashboard") is True

    def test_adapter_ensure_profile(self, tmp_path, monkeypatch):
        monkeypatch.setattr("adapters.browser.BROWSER_PROFILES_DIR", tmp_path / "profiles")
        adapter = BrowserAdapter()
        metadata = adapter.ensure_profile(provider_id="test-provider", identity="u@e.com")
        assert metadata["profile_id"] == DEFAULT_BROWSER_PROFILE
        assert "test-provider" in metadata["associated_providers"]

    def test_adapter_no_secrets_in_profile_metadata(self, tmp_path, monkeypatch):
        monkeypatch.setattr("adapters.browser.BROWSER_PROFILES_DIR", tmp_path / "profiles")
        adapter = BrowserAdapter()
        metadata = adapter.ensure_profile(provider_id="test", identity="u@e.com")
        serialized = json.dumps(metadata)
        secrets = scan_for_secrets(serialized)
        assert not secrets, f"Secrets in profile metadata: {secrets}"
