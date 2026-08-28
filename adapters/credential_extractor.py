"""
credential_extractor.py — Generic API credential extraction abstraction.

This module provides a generic framework for extracting API keys/tokens
from browser pages. Instead of scattering provider-specific regexes
throughout workflows, providers declare extraction rules as data.

Security requirements enforced by this module:
  - Extracted credentials are NEVER printed, logged, or returned in
    user-visible workflow results.
  - Credentials are passed directly to downstream functions (1Password
    storage, OmniRoute connection).
  - The extract_credential function returns a result that contains
    "[REDACTED]" in any debug/log output.
  - Page contents containing credentials are never persisted to disk.

The extraction process:
  1. A Snapshot object is provided (from the browser MCP).
  2. The provider's extraction_rules are consulted.
  3. The appropriate extraction strategy is applied.
  4. The credential value is returned ONLY to the caller (not logged).
"""

from __future__ import annotations

import re
import os
from typing import Any
from dataclasses import dataclass, field
from enum import Enum


class ExtractionStrategy(str, Enum):
    """How to extract the credential from the page."""
    REGEX = "regex"             # Apply a regex to page text
    SELECTOR = "selector"       # Read text from a DOM element by CSS selector
    CLIPBOARD = "clipboard"     # Read from clipboard (via browser JS)
    SNIPPET_BUTTON = "snippet_button"  # Click a "show" button, then read value
    TABLE_ROW = "table_row"     # Extract from a table row matching criteria


@dataclass
class ExtractionRule:
    """
    A rule for extracting a credential from a browser page.

    Attributes:
        credential_type: "api_key", "api_token", "secret_key"
        strategy: How to extract (REGEX, SELECTOR, CLIPBOARD, etc.)
        pattern: Regex pattern (for REGEX strategy) or CSS selector
                 (for SELECTOR strategy)
        prefix: Expected prefix of the credential (e.g. "cfat_", "sk-")
                Used for validation/verification
        page: Expected page URL or path (e.g. "/api-keys")
        description: Human-readable description (no secrets)
        case_sensitive: Whether regex matching is case-sensitive
        group: Which regex capture group to extract (default: 0 = whole match)
        min_length: Minimum length of extracted credential
        max_length: Maximum length of extracted credential
        mask_after: Number of chars to show before masking (for verification
                    without exposing the full value)
    """
    credential_type: str = "api_key"
    strategy: ExtractionStrategy = ExtractionStrategy.REGEX
    pattern: str = ""
    prefix: str | None = None
    page: str | None = None
    description: str = ""
    case_sensitive: bool = False
    group: int = 0
    min_length: int = 8
    max_length: int = 256
    mask_after: int = 8  # Show first 8 chars, mask rest


@dataclass
class ExtractionResult:
    """
    Result of a credential extraction.

    IMPORTANT: The `value` field contains the actual secret. This must
    NEVER be printed, logged, or included in user-visible output.
    The `masked_value` and `debug_info` are safe for logs/debug output.
    """
    value: str | None = None          # The actual credential (NEVER expose)
    masked_value: str = "[REDACTED]"  # Safe for logs/debug output
    found: bool = False
    credential_type: str = "api_key"
    source_description: str = ""      # Description of where it was found
    extraction_rule: str = ""         # Identifier of the rule used
    page: str = ""

    def to_debug_dict(self) -> dict:
        """Return a dict safe for logging/debugging (NO actual secret)."""
        return {
            "found": self.found,
            "credential_type": self.credential_type,
            "masked_value": self.masked_value,
            "source_description": self.source_description,
            "extraction_rule": self.extraction_rule,
            "page": self.page,
        }

    def to_result(self) -> dict:
        """Return a dict for workflow results (NO actual secret)."""
        return {
            "credential_extracted": self.found,
            "credential_type": self.credential_type,
            "credential_value": self.masked_value if self.found else None,
            "source_description": self.source_description,
            "extraction_rule": self.extraction_rule,
        }


# ── Provider extraction rule catalogs ────────────────────────────────────
#
# These are data-driven rules that describe how to extract credentials
# from specific provider pages. New providers can be added by extending
# this catalog without modifying the extraction logic.

PROVIDER_EXTRACTION_RULES: dict[str, list[ExtractionRule]] = {
    "cloudflare-ai": [
        ExtractionRule(
            credential_type="api_token",
            strategy=ExtractionStrategy.REGEX,
            pattern=r"cfat_[a-zA-Z0-9_-]+",
            prefix="cfat_",
            page="api-tokens",
            description="Cloudflare API token",
        ),
    ],
    "openai": [
        ExtractionRule(
            credential_type="api_key",
            strategy=ExtractionStrategy.REGEX,
            pattern=r"sk-[a-zA-Z0-9_-]{20,}",
            prefix="sk-",
            page="api-keys",
            description="OpenAI API key",
        ),
    ],
    "groq": [
        ExtractionRule(
            credential_type="api_key",
            strategy=ExtractionStrategy.REGEX,
            pattern=r"gsk_[a-zA-Z0-9]+",
            prefix="gsk_",
            page="api-keys",
            description="Groq API key",
        ),
    ],
    "anthropic": [
        ExtractionRule(
            credential_type="api_key",
            strategy=ExtractionStrategy.REGEX,
            pattern=r"sk-ant-[a-zA-Z0-9_-]+",
            prefix="sk-ant-",
            page="api-keys",
            description="Anthropic API key",
        ),
    ],
    "gemini": [
        ExtractionRule(
            credential_type="api_key",
            strategy=ExtractionStrategy.REGEX,
            pattern=r"(AIza[a-zA-Z0-9_-]{35})",
            prefix="AIza",
            page="api-keys",
            description="Google Gemini API key",
        ),
    ],
    "fireworks": [
        ExtractionRule(
            credential_type="api_key",
            strategy=ExtractionStrategy.REGEX,
            pattern=r"fw_[a-zA-Z0-9_-]+",
            prefix="fw_",
            page="api-keys",
            description="Fireworks API key",
        ),
    ],
    "deepseek": [
        ExtractionRule(
            credential_type="api_key",
            strategy=ExtractionStrategy.REGEX,
            pattern=r"sk-[a-zA-Z0-9_-]{48}",
            prefix="sk-",
            page="api-keys",
            description="DeepSeek API key",
        ),
    ],
    "deepinfra": [
        ExtractionRule(
            credential_type="api_key",
            strategy=ExtractionStrategy.REGEX,
            pattern=r"Bearer\s+(eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)",
            prefix="eyJ",
            page="api-keys",
            description="DeepInfra API key (JWT bearer token)",
            group=1,
        ),
    ],
    "siliconflow": [
        ExtractionRule(
            credential_type="api_key",
            strategy=ExtractionStrategy.REGEX,
            pattern=r"sk-[a-zA-Z0-9]{32,}",
            prefix="sk-",
            page="api-keys",
            description="SiliconFlow API key",
        ),
    ],
    "nebius": [
        ExtractionRule(
            credential_type="api_key",
            strategy=ExtractionStrategy.REGEX,
            pattern=r"xnd_[a-zA-Z0-9_-]{32,}",
            prefix="xnd_",
            page="api-keys",
            description="Nebius API key",
        ),
    ],
}


def get_extraction_rules(provider_id: str) -> list[ExtractionRule]:
    """
    Get extraction rules for a provider.

    Returns an empty list if no specific rules exist (caller should
    fall back to provider-specific logic or manual extraction).
    """
    return PROVIDER_EXTRACTION_RULES.get(provider_id, [])


def get_hostname_from_catalog(provider_id: str, catalog: dict) -> str | None:
    """
    Get the hostname for an API credential from the provider catalog.

    Returns None if not available.
    """
    from engine.catalog import get_provider
    provider = get_provider(catalog, provider_id)
    if provider:
        hostname = provider.get("hostname")
        if not hostname:
            # Try to extract from base_url
            base_url = provider.get("base_url", "")
            if base_url:
                from urllib.parse import urlparse
                parsed = urlparse(base_url if "://" in base_url else f"https://{base_url}")
                hostname = parsed.hostname
        return hostname
    return None


# ── Snapshot abstraction ─────────────────────────────────────────────────

@dataclass
class PageSnapshot:
    """
    A text-based snapshot of a browser page for credential extraction.

    This is populated from the browser MCP snapshot tool output.
    It does NOT contain the actual secret — the secret is only
    extracted by the extraction function and passed directly to
    downstream consumers.
    """
    text: str = ""           # Page text content
    url: str = ""            # Current URL
    html: str = ""           # Raw HTML (if available)
    elements: dict[str, Any] = field(default_factory=dict)  # Interactive elements with ref IDs


def extract_credential(
    snapshot: PageSnapshot,
    rules: list[ExtractionRule],
    provider_id: str = "",
) -> ExtractionResult:
    """
    Extract a credential from a page snapshot using the given rules.

    This function applies extraction rules to find credential values
    in page text, DOM elements, or clipboard content.

    Security:
      - The returned ExtractionResult.value field has a value attribute
        that contains the actual secret, but to_debug_dict() and
        to_result() NEVER include it.
      - This function never prints or logs the credential value.
      - The caller is responsible for passing the value directly to
        1Password or OmniRoute, then discarding it.

    Args:
        snapshot: Page snapshot (text, url, elements)
        rules: Extraction rules to try (in order)
        provider_id: Provider ID for context in the result

    Returns:
        ExtractionResult — check .value for the actual secret (NEVER log it).
    """
    for rule in rules:
        # Check page match if specified
        if rule.page and snapshot.url:
            if rule.page not in snapshot.url:
                continue

        result = _try_extract_rule(snapshot, rule, provider_id)
        if result.found:
            return result

    return ExtractionResult(
        found=False,
        credential_type="api_key",
        source_description="",
        page=snapshot.url,
    )


def _try_extract_rule(
    snapshot: PageSnapshot,
    rule: ExtractionRule,
    provider_id: str,
) -> ExtractionResult:
    """Try a single extraction rule against the snapshot."""
    flags = 0 if rule.case_sensitive else re.IGNORECASE

    if rule.strategy == ExtractionStrategy.REGEX:
        matches = re.findall(rule.pattern, snapshot.text, flags)
        if not matches:
            return ExtractionResult(found=False, page=snapshot.url)

        # findall returns strings when the pattern has no groups,
        # or tuples when it has groups. Handle both safely.
        for match in matches:
            if isinstance(match, str):
                cred = match
            elif isinstance(match, tuple):
                # Use the specified group, or group 0 (full match) if out of range
                try:
                    cred = match[rule.group] if rule.group < len(match) else match[0]
                except (IndexError, TypeError):
                    cred = match[0] if match else ""
            else:
                cred = str(match)
            if _validate_credential(cred, rule):
                return _build_result(cred, rule, snapshot, provider_id)

    elif rule.strategy == ExtractionStrategy.SELECTOR:
        # Look for element in snapshot elements
        element = snapshot.elements.get(rule.pattern, "")
        if element:
            cred = element.get("text", "") if isinstance(element, dict) else str(element)
            if _validate_credential(cred, rule):
                return _build_result(cred, rule, snapshot, provider_id)

    return ExtractionResult(found=False, page=snapshot.url)


def _validate_credential(value: str, rule: ExtractionRule) -> bool:
    """Validate an extracted credential against the rule's constraints."""
    if not value:
        return False
    if len(value) < rule.min_length:
        return False
    if len(value) > rule.max_length:
        return False
    if rule.prefix and not value.startswith(rule.prefix):
        return False
    return True


def _build_result(value: str, rule: ExtractionRule, snapshot: PageSnapshot,
                  provider_id: str) -> ExtractionResult:
    """
    Build an ExtractionResult from an extracted value.

    CRITICAL: The actual value is stored ONLY in .value.
    The .masked_value is safe for any output.
    """
    # Create a masked version safe for display
    show = min(rule.mask_after, len(value))
    masked = value[:show] + "*" * (len(value) - show) if len(value) > rule.mask_after else "*" * len(value)

    return ExtractionResult(
        value=value,  # Actual secret — handle with maximum care
        masked_value=masked,  # Safe for logs/debug
        found=True,
        credential_type=rule.credential_type,
        source_description=rule.description,
        extraction_rule=f"{provider_id}/{rule.strategy.value}",
        page=snapshot.url,
    )


# ── Credential lifecycle helpers ─────────────────────────────────────────
#
# Secret boundary architecture (MUST be enforced):
#
#   generated credential
#          │
#          ├──> browser input (form fill via browser_type)
#          │
#          └──> 1Password (via create_login / op CLI)
#                 │
#                 └──> credential_ref (op://vault/item_id/field)
#                          │
#                          └──> state / history / logs
#                               metadata ONLY — no raw secret
#
#   API key
#     │
#     ├──> transient browser extraction (browser_snapshot / get_text)
#     │
#     └──> 1Password (via create_login / op CLI)
#            │
#            └──> credential_ref
#
# The raw secret flows ONLY through the function parameter `value` on
# `credential_to_onepassword()`. After the 1Password `op` CLI call
# completes, the value is discarded — only the ref dict is returned.
#
# ExtractionResult.to_debug_dict() and to_result() NEVER include .value.
# The .value attribute is only consumed by credential_to_onepassword().
# retrieve_credential_value() returns the secret ONLY to the operational
# caller that actually needs it (e.g. OmniRoute connection bootstrap).
#
# ────────────────────────────────────────────────────────────────────────


def credential_to_onepassword(value: str, item_title: str, vault: str,
                               hostname: str | None = None) -> dict | None:
    """
    Store an extracted credential in 1Password.

    This is the ONLY place where the credential value should be
    passed to the 1Password adapter. After this call, the value
    should be discarded.

    Returns a credential_ref dict (metadata only, no secret) or None on failure.
    """
    from adapters.onepassword import create_login, build_credential_ref

    # Ensure write access before attempting
    from adapters.onepassword import require_write_access
    can_write, msg = require_write_access()
    if not can_write:
        raise PermissionError(f"Cannot write to 1Password: {msg}")

    # Determine field name: use 'credential' for API keys
    tag_parts = [f"provider:{hostname}" if hostname else "provider:unknown"]
    tags = ["provider-xref", "api-key"] + tag_parts

    result = create_login(
        title=item_title,
        password=value,
        vault=vault,
        tags=tags,
    )

    if result and "error" not in result and result.get("id"):
        ref = build_credential_ref(
            vault=vault,
            item_id=result["id"],
            item_title=item_title,
            field="credential",
        )
        # Discard the value — only ref is returned
        return ref

    return None


def retrieve_credential_value(credential_ref: dict) -> str | None:
    """
    Retrieve the actual credential value from 1Password using a ref.

    This is called ONLY when the credential is needed for
    an operation (e.g. connecting to OmniRoute). The value
    must be passed directly to the consumer and then discarded.

    This function should NEVER be called for logging/display purposes.
    """
    if not credential_ref or credential_ref.get("backend") != "1password":
        return None

    from adapters.onepassword import get_credential_value

    return get_credential_value(
        item_id=credential_ref["item_id"],
        field=credential_ref.get("field", "credential"),
        vault=credential_ref.get("vault"),
    )


def redact_credential(value: str, visible_chars: int = 4) -> str:
    """
    Return a redacted version of a credential for safe display.

    Shows the first `visible_chars` characters then masks the rest.
    For very short values, shows all as asterisks.
    """
    if not value:
        return "[REDACTED]"
    if len(value) <= visible_chars:
        return "*" * len(value)
    return value[:visible_chars] + "*" * (len(value) - visible_chars)
