"""
capability.py — Data-driven provider capability / catalog model (Phase 11).

Goal: make provider capabilities **data-driven** rather than engine-hardcoded.

The capability model answers questions such as:
  * Can this provider currently be registered?
  * Which authentication methods are supported?
  * Does registration require a browser?
  * Can human interaction / checkpoints be required?
  * What credential type is expected?
  * Can credentials be extracted automatically?
  * Is the provider ready for automated registration?
  * What is blocked by POLICY versus merely unsupported / not implemented?

These answers are derived PREDOMINANTLY FROM CATALOG DATA, reusing the
existing policy engine and extraction-rule catalog.  Where catalog data is
absent we fall back to safe defaults (conservative: "unknown" / "unsupported")
rather than assuming capability.

The data model keeps the following dimensions SEPARATE (per the Phase 11 spec):
  * policy_status
  * support_status
  * registration_readiness
  * registration_state
  * credential_state
  * authentication methods
  * browser requirement
  * human checkpoint requirement
  * credential type
  * extraction capability

Two new OPTIONAL, backward-compatible catalog blocks are consumed:
  * ``registration`` — registration metadata (methods, browser_required,
    human_checkpoint_possible, credential_type, ...)
  * ``extraction`` — credential extraction configuration (rules,
    automation_supported, checkpoint_types, ...)

Providers without these blocks still resolve to a complete, conservative
capability view (defaults are derived from existing fields: auth_type,
policy, omniroute_support, identity_requirements, verification_requirements).

Security:
  * This module is read-only over the catalog.
  * It never returns credential VALUES — only metadata / references / labels.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

from .catalog import load_catalog, get_provider
from .policy import (
    get_policy,
    can_automate_registration,
    get_opportunity_policy_status,
)
from adapters.credential_extractor import (
    PROVIDER_EXTRACTION_RULES,
    ExtractionStrategy,
)


# ── State vocabularies (explicit, distinct meanings) ────────────────────────
#
# These enums make the distinction the spec demands explicit — we must NOT
# conflate "we don't know", "we don't support it", "policy says no",
# "registration failed", and "registration hasn't been attempted".

# Policy: what the catalog says we are ALLOWED to do.
POLICY_ALLOWED = "allowed"
POLICY_DISALLOWED = "disallowed"
POLICY_RESTRICTED = "restricted"
POLICY_UNKNOWN = "unknown"

# Support: what the engine technically supports / knows how to do.
SUPPORT_SUPPORTED = "supported"
SUPPORT_PARTIAL = "partial"
SUPPORT_UNSUPPORTED = "unsupported"
SUPPORT_UNKNOWN = "unknown"

# Registration state: catalog classification of the provider's standing.
REG_STATE_CLASSIFIED = "classified"        # we understand the provider
REG_STATE_UNKNOWN = "unknown"              # we have no catalog data
REG_STATE_ELIGIBLE = "eligible"            # allowed + supported + ready
REG_STATE_BLOCKED = "blocked"              # policy disallows
REG_STATE_RESTRICTED = "restricted"        # policy restricted (manual review)
REG_STATE_SUPPORTED = "supported"         # supported but policy unknown
REG_STATE_REGISTRATION_READY = "registration_ready"  # ready to register
REG_STATE_REGISTERED = "registered"        # already registered (external signal)
REG_STATE_VERIFIED = "verified"           # registered + verified (external signal)

# Readiness: can the engine attempt registration right now?
READINESS_READY = "ready"
READINESS_BLOCKED_POLICY = "blocked_policy"
READINESS_UNSUPPORTED = "unsupported"
READINESS_NEEDS_REVIEW = "needs_review"
READINESS_UNKNOWN = "unknown"

# Credential state: what we know about credential handling.
CRED_STATE_EXTRACTABLE = "extractable"     # automated extraction configured
CRED_STATE_MANUAL = "manual"              # human must copy the key
CRED_STATE_NONE = "none"                  # no credential expected
CRED_STATE_UNKNOWN = "unknown"
CRED_STATE_UNSUPPORTED = "unsupported"

# Checkpoint / browser requirements are booleans in the model, surfaced as
# "required" / "possible" / "not_required" in helper accessors.


@dataclass
class ProviderCapability:
    """Normalized, data-driven capability view for a single provider.

    Every field is derived from catalog data + policy engine. No secrets.
    """
    provider_id: str
    name: str = ""

    # ── Policy dimension ───────────────────────────────────────────────
    policy_status: str = POLICY_UNKNOWN
    automation_allowed: str = POLICY_UNKNOWN
    multiple_accounts: str = POLICY_UNKNOWN
    duplicate_account_policy: str = POLICY_UNKNOWN

    # ── Support dimension ──────────────────────────────────────────────
    support_status: str = SUPPORT_UNKNOWN
    has_workflow: bool = False
    omniroute_supported: bool = False

    # ── Registration dimension ─────────────────────────────────────────
    registration_state: str = REG_STATE_UNKNOWN
    registration_readiness: str = READINESS_UNKNOWN
    can_register_now: bool = False

    # ── Authentication / credential dimension ──────────────────────────
    auth_type: str = "unknown"
    auth_methods: list[str] = field(default_factory=list)
    credential_type: str | None = None
    credential_state: str = CRED_STATE_UNKNOWN
    extraction_supported: bool = False
    browser_required: bool = False
    human_checkpoint_possible: bool = False
    checkpoint_types: list[str] = field(default_factory=list)

    # ── Derived signals (explanation, safe for serialization) ──────────
    reasons: list[str] = field(default_factory=list)
    source: str = "catalog"

    def to_dict(self) -> dict:
        return asdict(self)

    def is_ready_for_automation(self) -> bool:
        return self.can_register_now and self.policy_status == POLICY_ALLOWED


# ── Defaults ───────────────────────────────────────────────────────────────

def _default_capability(provider_id: str) -> ProviderCapability:
    return ProviderCapability(
        provider_id=provider_id,
        name=provider_id,
        policy_status=POLICY_UNKNOWN,
        automation_allowed=POLICY_UNKNOWN,
        support_status=SUPPORT_UNKNOWN,
        registration_state=REG_STATE_UNKNOWN,
        registration_readiness=READINESS_UNKNOWN,
        auth_type="unknown",
        credential_type=None,
        credential_state=CRED_STATE_UNKNOWN,
    )


# ── Catalog block parsers (backward compatible) ────────────────────────────

def _parse_registration_block(provider: dict) -> dict:
    """Parse the optional ``registration`` catalog block.

    Returns a normalized dict of registration metadata. Missing block ->
    empty dict (caller derives from other fields).
    """
    reg = provider.get("registration")
    if not isinstance(reg, dict):
        return {}
    return {
        "methods": list(reg.get("methods", [])),
        "browser_required": bool(reg.get("browser_required", False)),
        "human_checkpoint_possible": bool(reg.get("human_checkpoint_possible", False)),
        "credential_type": reg.get("credential_type"),
        "checkpoint_types": list(reg.get("checkpoint_types", [])),
        "automation_supported": reg.get("automation_supported"),  # tri-state: None=unspecified
    }


def _parse_extraction_block(provider: dict) -> dict:
    """Parse the optional ``extraction`` catalog block.

    Returns a normalized dict. Missing block -> empty dict.
    """
    ext = provider.get("extraction")
    if not isinstance(ext, dict):
        return {}
    return {
        "automation_supported": bool(ext.get("automation_supported", False)),
        "rules_ref": ext.get("rules_ref"),  # provider id key into PROVIDER_EXTRACTION_RULES
        "checkpoint_types": list(ext.get("checkpoint_types", [])),
        "notes": ext.get("notes", ""),
    }


# ── Main builder ───────────────────────────────────────────────────────────

def build_capability(provider_id: str, catalog: dict | None = None) -> ProviderCapability:
    """Build a normalized ProviderCapability from catalog data.

    Pure function over the catalog + policy engine. Safe (no secrets).
    """
    if catalog is None:
        catalog = load_catalog()

    provider = get_provider(catalog, provider_id)
    if provider is None:
        cap = _default_capability(provider_id)
        cap.reasons.append("provider not in catalog — status unknown")
        cap.source = "default"
        return cap

    cap = ProviderCapability(
        provider_id=provider_id,
        name=provider.get("name", provider_id),
    )
    reasons: list[str] = []

    # ── Policy dimension (reuse policy engine) ─────────────────────────
    policy = get_policy(catalog, provider_id)
    cap.automation_allowed = policy.get("automation_allowed", POLICY_UNKNOWN)
    cap.multiple_accounts = policy.get("multiple_accounts", POLICY_UNKNOWN)
    cap.duplicate_account_policy = policy.get("duplicate_account_policy", POLICY_UNKNOWN)
    cap.policy_status = get_opportunity_policy_status(catalog, provider_id)
    if cap.policy_status == POLICY_DISALLOWED:
        reasons.append("policy disallows automation")
    elif cap.policy_status == POLICY_RESTRICTED:
        reasons.append("policy restricted — manual review required")
    elif cap.policy_status == POLICY_UNKNOWN:
        reasons.append("policy unknown — manual verification required")

    # ── Support dimension ──────────────────────────────────────────────
    from .registry import get_workflow
    wf = get_workflow(provider_id, catalog)
    cap.has_workflow = wf is not None
    ors = provider.get("omniroute_support", {})
    cap.omniroute_supported = bool(ors.get("supported")) if isinstance(ors, dict) else False
    if cap.has_workflow:
        cap.support_status = SUPPORT_SUPPORTED
    elif cap.omniroute_supported:
        cap.support_status = SUPPORT_PARTIAL
        reasons.append("no dedicated workflow; OmniRoute support only")
    else:
        cap.support_status = SUPPORT_UNKNOWN
        reasons.append("no workflow and no OmniRoute support — support unknown")

    # ── Registration / auth / credential dimension ─────────────────────
    cap.auth_type = provider.get("auth_type", "unknown")
    reg_block = _parse_registration_block(provider)
    ext_block = _parse_extraction_block(provider)

    # Auth methods: prefer explicit registration.methods; else derive from auth_type
    if reg_block.get("methods"):
        cap.auth_methods = list(reg_block["methods"])
    else:
        cap.auth_methods = _derive_auth_methods(cap.auth_type, provider)

    # Browser requirement: explicit block > auth_type + identity-relationship heuristic
    if "browser_required" in reg_block:
        cap.browser_required = reg_block["browser_required"]
    else:
        # OAuth/password inherently needs a browser session; pure api_key with
        # only an email requirement does not (key can be pasted programmatically).
        needs_browser_auth = cap.auth_type in ("oauth", "password")
        oauth_identity_rel = any(
            rel in ("google", "github", "microsoft", "apple")
            for rel in provider.get("identity_relationships", [])
        )
        cap.browser_required = needs_browser_auth or oauth_identity_rel

    # Human checkpoint possibility
    if "human_checkpoint_possible" in reg_block:
        cap.human_checkpoint_possible = reg_block["human_checkpoint_possible"]
    else:
        cap.human_checkpoint_possible = cap.auth_type in ("oauth", "password") or bool(
            provider.get("verification_requirements")
        )

    # Checkpoint types: explicit block wins; else derive from verification reqs
    if reg_block.get("checkpoint_types"):
        cap.checkpoint_types = list(reg_block["checkpoint_types"])
    elif ext_block.get("checkpoint_types"):
        cap.checkpoint_types = list(ext_block["checkpoint_types"])
    else:
        cap.checkpoint_types = _derive_checkpoint_types(provider)

    # Credential type + extraction
    cap.credential_type = reg_block.get("credential_type") or _derive_credential_type(cap.auth_type)

    # Extraction support: explicit extraction.automation_supported > rule presence
    if ext_block and "automation_supported" in ext_block:
        cap.extraction_supported = ext_block["automation_supported"]
    else:
        rules_key = ext_block.get("rules_ref") or provider_id
        cap.extraction_supported = rules_key in PROVIDER_EXTRACTION_RULES

    if cap.extraction_supported:
        cap.credential_state = CRED_STATE_EXTRACTABLE
    elif cap.credential_type in (None, "none"):
        cap.credential_state = CRED_STATE_NONE
    else:
        cap.credential_state = CRED_STATE_MANUAL

    # ── Registration state (catalog classification) ────────────────────
    cap.registration_state = _classify_registration_state(cap, reasons)

    # ── Registration readiness (composite) ─────────────────────────────
    readiness, ready_reasons = _classify_readiness(cap)
    cap.registration_readiness = readiness
    cap.reasons = reasons + ready_reasons
    cap.can_register_now = (readiness == READINESS_READY)

    return cap


def build_capabilities(catalog: dict | None = None) -> dict[str, ProviderCapability]:
    """Build capabilities for every provider in the catalog."""
    if catalog is None:
        catalog = load_catalog()
    return {
        p["id"]: build_capability(p["id"], catalog)
        for p in get_all_providers_safe(catalog)
    }


def get_all_providers_safe(catalog: dict) -> list[dict]:
    return catalog.get("providers", [])


# ── Derivation helpers (defaults when catalog blocks are absent) ────────────

def _derive_auth_methods(auth_type: str, provider: dict) -> list[str]:
    """Derive plausible auth methods from auth_type + identity relationships."""
    methods = []
    if auth_type == "api_key":
        methods.append("api_key")
    elif auth_type == "oauth":
        methods.append("oauth")
        # Identity providers that can cascade in
        for rel in provider.get("identity_relationships", []):
            if rel not in methods:
                methods.append(rel)
    elif auth_type == "password":
        methods.append("password")
    elif auth_type == "pat":
        methods.append("pat")
    else:
        methods.append("unknown")
    return methods


def _derive_credential_type(auth_type: str) -> str | None:
    if auth_type == "api_key":
        return "api_key"
    if auth_type == "oauth":
        return "oauth_token"
    if auth_type == "pat":
        return "pat"
    if auth_type == "password":
        return "password"
    return None


def _derive_checkpoint_types(provider: dict) -> list[str]:
    """Derive possible human checkpoints from verification requirements."""
    mapping = {
        "email": "email_verification",
        "phone": "phone_verification",
        "captcha": "captcha",
        "id_document": "id_document",
        "manual_review": "manual_review",
    }
    out = []
    for v in provider.get("verification_requirements", []):
        ct = mapping.get(v)
        if ct and ct not in out:
            out.append(ct)
    if provider.get("auth_type") == "oauth":
        out.append("manual_oauth")
    # Consent is always possible during signup
    out.append("consent")
    return out


def _classify_registration_state(cap: ProviderCapability, reasons: list[str]) -> str:
    """Classify the provider's catalog standing (NOT whether we attempted)."""
    if cap.policy_status == POLICY_DISALLOWED:
        return REG_STATE_BLOCKED
    if cap.policy_status == POLICY_RESTRICTED:
        return REG_STATE_RESTRICTED
    if cap.policy_status == POLICY_UNKNOWN:
        if cap.support_status in (SUPPORT_SUPPORTED, SUPPORT_PARTIAL):
            return REG_STATE_SUPPORTED
        return REG_STATE_UNKNOWN
    # policy allowed / classified
    if cap.support_status == SUPPORT_UNSUPPORTED:
        return REG_STATE_CLASSIFIED  # understood but we can't do it yet
    if cap.support_status in (SUPPORT_SUPPORTED, SUPPORT_PARTIAL):
        return REG_STATE_ELIGIBLE
    return REG_STATE_CLASSIFIED


def _classify_readiness(cap: ProviderCapability) -> tuple[str, list[str]]:
    """Composite readiness: can the engine attempt registration now?

    Returns (readiness, extra_reasons).
    """
    reasons: list[str] = []

    # Policy gates first
    if cap.policy_status == POLICY_DISALLOWED:
        return READINESS_BLOCKED_POLICY, ["policy disallows automation"]
    if cap.policy_status == POLICY_RESTRICTED:
        return READINESS_NEEDS_REVIEW, ["policy restricted — manual review required"]

    # Support gates
    if cap.support_status == SUPPORT_UNSUPPORTED:
        return READINESS_UNSUPPORTED, ["no workflow / OmniRoute support for this provider"]
    if cap.support_status == SUPPORT_UNKNOWN:
        return READINESS_UNKNOWN, ["support unknown — cannot assess readiness"]

    # Policy unknown but technically possible -> needs review, NOT auto
    if cap.policy_status == POLICY_UNKNOWN:
        return READINESS_NEEDS_REVIEW, ["policy unknown — manual verification required"]

    # allowed + supported
    if cap.credential_state == CRED_STATE_EXTRACTABLE or cap.credential_type in (None, "none"):
        reasons.append("policy allowed and engine supported")
        return READINESS_READY, reasons

    # allowed + supported but manual credential copy
    reasons.append("policy allowed and engine supported (manual credential handling)")
    return READINESS_READY, reasons


# ── Convenience accessors ───────────────────────────────────────────────────

def can_register(provider_id: str, catalog: dict | None = None) -> bool:
    return build_capability(provider_id, catalog).can_register_now


def get_auth_methods(provider_id: str, catalog: dict | None = None) -> list[str]:
    return build_capability(provider_id, catalog).auth_methods


def requires_browser(provider_id: str, catalog: dict | None = None) -> bool:
    return build_capability(provider_id, catalog).browser_required


def can_require_human_checkpoint(provider_id: str, catalog: dict | None = None) -> bool:
    return build_capability(provider_id, catalog).human_checkpoint_possible


def expected_credential_type(provider_id: str, catalog: dict | None = None) -> str | None:
    return build_capability(provider_id, catalog).credential_type


def can_extract_credential(provider_id: str, catalog: dict | None = None) -> bool:
    return build_capability(provider_id, catalog).extraction_supported


def is_ready_for_automation(provider_id: str, catalog: dict | None = None) -> bool:
    return build_capability(provider_id, catalog).is_ready_for_automation()
