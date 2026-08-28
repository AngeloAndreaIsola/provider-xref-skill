"""
reconcile.py — Read-only cross-system reconciliation (Phase 12).

Goal: answer, for every provider/account, what exists in Hermes, what exists
in 1Password, what exists in OmniRoute, and where the lifecycle is inconsistent.

This module is a READ MODEL. It NEVER:
  * writes/updates/deletes 1Password items
  * writes/updates/deletes OmniRoute connections
  * mutates Hermes provider state
  * returns credential VALUES (only metadata + op:// references)

It reuses existing architecture:
  * engine.state.load_state / provider_state.json shape
  * adapters.omniroute.get_connected_providers (normalized connections)
  * adapters.onepassword search/metadata (no secrets)
  * engine.audit.reconcile_real_state() for the live discovery path
  * engine.capability for capability context (optional)

Normalized model
----------------
  Provider -> Account -> {
      identity (id/email metadata only),
      login credential ref (1Password),
      api key credential ref (1Password / Hermes),
      OmniRoute connection,
      Hermes provider-account reference,
  }

Reconciliation states
---------------------
  complete | missing_login | missing_api_key | missing_omniroute_connection |
  missing_hermes_reference | duplicate | orphaned | conflicting_identity |
  unknown

Ambiguous states are NEVER collapsed into ``complete``.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Any

from .catalog import load_catalog
from .state import load_state


# ── Reconciliation state vocabulary ──────────────────────────────────────────

STATE_COMPLETE = "complete"
STATE_MISSING_LOGIN = "missing_login"
STATE_MISSING_API_KEY = "missing_api_key"
STATE_MISSING_OMNIROUTE = "missing_omniroute_connection"
STATE_MISSING_HERMES = "missing_hermes_reference"
STATE_DUPLICATE = "duplicate"
STATE_ORPHANED = "orphaned"
STATE_CONFLICTING_IDENTITY = "conflicting_identity"
STATE_UNKNOWN = "unknown"

RECON_STATES = (
    STATE_COMPLETE, STATE_MISSING_LOGIN, STATE_MISSING_API_KEY,
    STATE_MISSING_OMNIROUTE, STATE_MISSING_HERMES, STATE_DUPLICATE,
    STATE_ORPHANED, STATE_CONFLICTING_IDENTITY, STATE_UNKNOWN,
)


# ── Normalized input shapes ──────────────────────────────────────────────────

@dataclass
class ReconciledAccount:
    """One normalized account for a provider, merged across the three systems.

    All credential fields are METADATA / REFERENCES only. No secret values.
    """
    provider_id: str
    account_id: str                       # stable key: hermes pa id if present else omni conn id
    identity_id: str | None = None
    identity_email: str | None = None
    hermes_account_id: str | None = None
    omniroute_connection_id: str | None = None
    login_ref: dict | None = None         # {item_id, title, reference} or None
    api_key_ref: dict | None = None       # {item_id, title, reference} or None
    has_login: bool = False
    has_api_key: bool = False
    has_omniroute: bool = False
    has_hermes_ref: bool = False
    ownership_status: str = "unknown"
    state: str = STATE_UNKNOWN
    issues: list[str] = field(default_factory=list)
    references: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ReconciledProvider:
    """All reconciled accounts for one provider."""
    provider_id: str
    accounts: list[ReconciledAccount] = field(default_factory=list)

    @property
    def account_count(self) -> int:
        return len(self.accounts)

    def to_dict(self) -> dict:
        return {
            "provider_id": self.provider_id,
            "account_count": self.account_count,
            "accounts": [a.to_dict() for a in self.accounts],
        }


# ── Normalizers (pure functions over already-discovered data) ───────────────

def _provider_id_from_title(title: str, catalog_provider_ids: set[str]) -> str | None:
    """Match a 1Password item title to a provider id (metadata evidence only).

    Prefers the LONGEST matching id (e.g. 'cloudflare-ai' beats 'cloudflare')
    to avoid fragment collisions.
    """
    low = (title or "").lower()
    matches = [pid for pid in catalog_provider_ids if pid in low]
    if not matches:
        return None
    # longest id first => most specific
    matches.sort(key=len, reverse=True)
    return matches[0]


def normalize_onepassword_items(op_items: list[dict], catalog=None) -> list[dict]:
    """Normalize 1Password metadata items into a safe, typed shape.

    Each returned item: {item_id, title, username, vault, provider_id,
    kind} where kind in {login, api_key, unknown}. No secret values.
    """
    if catalog is None:
        catalog = load_catalog()
    cat_ids = {p["id"] for p in catalog.get("providers", [])}

    out = []
    for item in op_items:
        item_id = item.get("item_id") or item.get("id")
        title = item.get("title", "")
        username = item.get("username")
        vault = item.get("vault")
        pid = _provider_id_from_title(title, cat_ids)
        kind = "unknown"
        tlow = title.lower()
        if "api key" in tlow or "apikey" in tlow or "token" in tlow:
            kind = "api_key"
        elif any(k in tlow for k in ("login", "account", "password")):
            kind = "login"
        out.append({
            "item_id": item_id,
            "title": title,
            "username": username,
            "vault": vault,
            "provider_id": pid,
            "kind": kind,
        })
    return out


def normalize_omniroute_connections(omni_connections: list[dict]) -> list[dict]:
    """Normalize OmniRoute connections into a safe shape (no secrets).

    Already-normalized by adapters.omniroute.get_connected_providers, but we
    defensively keep only non-sensitive fields.
    """
    safe = []
    for c in omni_connections:
        safe.append({
            "provider_id": c.get("provider_id"),
            "connection_id": c.get("connection_id"),
            "auth_type": c.get("auth_type"),
            "display_name": c.get("display_name"),
            "is_active": c.get("is_active"),
        })
    return safe


def _cred_ref_to_metadata(ref: dict | None) -> dict | None:
    """Convert a Hermes credential_ref into safe metadata (no value)."""
    if not ref:
        return None
    return {
        "item_id": ref.get("item_id"),
        "title": ref.get("item_title"),
        "reference": ref.get("reference"),   # op://... acceptable
        "vault": ref.get("vault"),
        "field": ref.get("field"),
    }


# ── Core reconciliation ──────────────────────────────────────────────────────

def reconcile_account(
    provider_id: str,
    hermes_account: dict | None,
    omni_conn: dict | None,
    login_items: list[dict],
    api_key_items: list[dict],
) -> ReconciledAccount:
    """Reconcile a single account from its three-system fragments.

    Deterministic. Metadata-only. Never fabricates.
    """
    identity_id = None
    identity_email = None
    hermes_account_id = None
    ownership_status = "unknown"
    api_key_ref = None

    if hermes_account:
        hermes_account_id = hermes_account.get("id")
        identity_id = hermes_account.get("identity_id")
        ownership_status = hermes_account.get("ownership_status", "unknown")
        cred_ref = _cred_ref_to_metadata(hermes_account.get("credential_ref"))
        if cred_ref:
            api_key_ref = cred_ref

    # Email from OmniRoute display name as a best-effort hint when no identity
    # email is otherwise known. Safe because reconcile_provider assigns each
    # account only its OWN connection (no cross-account overwrite).
    if omni_conn:
        dn = omni_conn.get("display_name") or ""
        if "@" in dn and identity_email is None:
            identity_email = dn

    # 1Password login / api key refs
    login_ref = login_items[0] if login_items else None
    if api_key_items and api_key_ref is None:
        ak = api_key_items[0]
        api_key_ref = {
            "item_id": ak.get("item_id"),
            "title": ak.get("title"),
            "reference": f"op://{ak.get('vault')}/{ak.get('title')}" if ak.get("vault") else None,
        }

    account_id = hermes_account_id or (omni_conn or {}).get("connection_id") or f"{provider_id}:unknown"
    omniroute_connection_id = (omni_conn or {}).get("connection_id")

    has_login = login_ref is not None
    has_api_key = api_key_ref is not None
    has_omniroute = omni_conn is not None
    has_hermes_ref = hermes_account is not None

    issues: list[str] = []
    # Duplicate detection (multiple items of same kind)
    if len(login_items) > 1:
        issues.append(f"duplicate_login_items:{len(login_items)}")
    if len(api_key_items) > 1:
        issues.append(f"duplicate_api_key_items:{len(api_key_items)}")

    # ── State resolution (do not collapse ambiguity into complete) ──
    if has_hermes_ref and has_omniroute and has_login and has_api_key:
        state = STATE_COMPLETE
    elif not has_hermes_ref and (has_omniroute or login_ref or api_key_ref):
        state = STATE_MISSING_HERMES
    elif has_hermes_ref and not has_omniroute:
        state = STATE_MISSING_OMNIROUTE
    elif has_hermes_ref and not has_login:
        state = STATE_MISSING_LOGIN
    elif has_hermes_ref and not has_api_key:
        state = STATE_MISSING_API_KEY
    else:
        state = STATE_UNKNOWN

    if issues:
        state = STATE_DUPLICATE if state == STATE_COMPLETE else state

    return ReconciledAccount(
        provider_id=provider_id,
        account_id=account_id,
        identity_id=identity_id,
        identity_email=identity_email,
        hermes_account_id=hermes_account_id,
        omniroute_connection_id=omniroute_connection_id,
        login_ref=login_ref,
        api_key_ref=api_key_ref,
        has_login=has_login,
        has_api_key=has_api_key,
        has_omniroute=has_omniroute,
        has_hermes_ref=has_hermes_ref,
        ownership_status=ownership_status,
        state=state,
        issues=issues,
        references={
            "omniroute_connection_id": omniroute_connection_id,
            "hermes_account_id": hermes_account_id,
            "login_item_id": (login_ref or {}).get("item_id"),
            "api_key_item_id": (api_key_ref or {}).get("item_id"),
            "api_key_reference": (api_key_ref or {}).get("reference"),
        },
    )


def reconcile_provider(
    provider_id: str,
    hermes_accounts: list[dict],
    omni_connections: list[dict],
    op_items: list[dict],
    identity_email_by_id: dict[str, str] | None = None,
) -> ReconciledProvider:
    """Reconcile all accounts for one provider across the three systems.

    Deterministic account keying:
      * Hermes provider_accounts are the primary anchors (keyed by id).
      * OmniRoute connections without a Hermes match become their own account.
      * 1Password items are matched to a provider by title, then to an account
        by identity email / display name when possible.
    """
    identity_email_by_id = identity_email_by_id or {}
    # Group 1Password items by provider + kind
    op_by_provider = defaultdict(lambda: {"login": [], "api_key": []})
    for it in op_items:
        pid = it.get("provider_id")
        if pid != provider_id:
            continue
        kind = it.get("kind", "unknown")
        if kind == "login":
            op_by_provider[pid]["login"].append(it)
        elif kind == "api_key":
            op_by_provider[pid]["api_key"].append(it)

    # OmniRoute connections for this provider
    omni_for_provider = [c for c in omni_connections if c.get("provider_id") == provider_id]

    accounts: list[ReconciledAccount] = []

    # 1) Anchor on Hermes accounts (supports multiple accounts per provider)
    consumed_op_ids: set[str] = set()
    for ha in hermes_accounts:
        pid = ha.get("provider_id")
        if pid != provider_id:
            continue
        conn = None
        # match omniroute by connection id (strict: only the account's own
        # connection). No fallback to omni_for_provider[0] — that would make two
        # accounts sharing a provider inherit the SAME connection and overwrite
        # each other's distinct identities/emails.
        for c in omni_for_provider:
            if c.get("connection_id") and c.get("connection_id") == ha.get("omniroute_account_id"):
                conn = c
                break
        # Resolve identity email for this account
        acc_email = identity_email_by_id.get(ha.get("identity_id")) if ha.get("identity_id") else None
        if acc_email is None and conn:
            dn = conn.get("display_name") or ""
            acc_email = dn if "@" in dn else None
        # Match 1Password items to THIS account by email/username (deterministic)
        prov_op = op_by_provider.get(provider_id, {"login": [], "api_key": []})
        login_match, api_match = _match_op_items_to_account(
            prov_op["login"], prov_op["api_key"], acc_email, ha,
        )
        for it in (login_match or []) + (api_match or []):
            consumed_op_ids.add(it.get("item_id"))
        acc = reconcile_account(
            provider_id, ha, conn,
            login_items=login_match or [],
            api_key_items=api_match or [],
        )
        if acc.identity_id:
            # Prefer the resolved identity email over any OmniRoute display_name
            # hint (the display_name is only a fallback when identity unknown).
            acc.identity_email = acc_email or acc.identity_email
        accounts.append(acc)

    # 2) OmniRoute connections not yet anchored to a Hermes account
    anchored_conn_ids = {a.omniroute_connection_id for a in accounts if a.omniroute_connection_id}
    for c in omni_for_provider:
        if c.get("connection_id") in anchored_conn_ids:
            continue
        dn = c.get("display_name") or ""
        conn_email = dn if "@" in dn else None
        prov_op = op_by_provider.get(provider_id, {"login": [], "api_key": []})
        login_match, api_match = _match_op_items_to_account(
            prov_op["login"], prov_op["api_key"], conn_email, None,
        )
        for it in (login_match or []) + (api_match or []):
            consumed_op_ids.add(it.get("item_id"))
        acc = reconcile_account(provider_id, None, c,
                                 login_items=login_match or [],
                                 api_key_items=api_match or [])
        if conn_email:
            acc.identity_email = conn_email
        accounts.append(acc)

    # 3) Orphaned 1Password items (provider matched, but not attached to any
    #    account by email/username/credential_ref). Surface explicitly.
    #    If multiple items of a kind exist for the provider and none could be
    #    disambiguated, mark as duplicate rather than plain orphan.
    prov_op_all = op_by_provider.get(provider_id, {"login": [], "api_key": []})
    multi_login = len(prov_op_all["login"]) > 1
    multi_api = len(prov_op_all["api_key"]) > 1
    for kind in ("login", "api_key"):
        for it in prov_op_all[kind]:
            if it.get("item_id") in consumed_op_ids:
                continue
            acc = reconcile_account(provider_id, None, None,
                                    login_items=[it] if kind == "login" else [],
                                    api_key_items=[it] if kind == "api_key" else [])
            is_dup = (kind == "login" and multi_login) or (kind == "api_key" and multi_api)
            acc.state = STATE_DUPLICATE if is_dup else STATE_ORPHANED
            acc.issues.append("duplicate_1password_item" if is_dup else "orphaned_1password_item")
            accounts.append(acc)

    # 4) Conflicting identity detection across accounts for this provider
    _mark_conflicting_identities(accounts)

    return ReconciledProvider(provider_id=provider_id, accounts=accounts)


def _match_op_items_to_account(
    login_items: list[dict],
    api_key_items: list[dict],
    account_email: str | None,
    hermes_account: dict | None,
) -> tuple[list[dict], list[dict]]:
    """Deterministically pick the 1Password items that belong to one account.

    Priority:
      1. By email/username equality (most reliable, metadata-only).
      2. If exactly one item of a kind exists and no email signal, attach it
         (single-account provider assumption — conservative, surfaced as a match).
      3. If multiple items and no email signal, return none (caller records
         duplicate/unknown — we do NOT guess which belongs to this account).
    """
    def _pick(items: list[dict]) -> list[dict]:
        if not items:
            return []
        if account_email:
            matched = [it for it in items
                       if (it.get("username") or "").lower() == account_email.lower()]
            if matched:
                return matched
        if hermes_account and hermes_account.get("credential_ref"):
            ref_id = hermes_account["credential_ref"].get("item_id")
            matched = [it for it in items if it.get("item_id") == ref_id]
            if matched:
                return matched
        if len(items) == 1:
            return items
        return []  # ambiguous: don't guess

    return _pick(login_items), _pick(api_key_items)


def _mark_conflicting_identities(accounts: list[ReconciledAccount]) -> None:
    """Mark duplicate-identity / conflicting-identity situations.

    Duplicate: two accounts share the same identity_id.
    Conflict: two accounts share the SAME OmniRoute connection id but carry
    DIFFERENT non-null identity_ids — i.e. one connection is claimed by two
    distinct identities (ambiguous ownership). Metadata-only.
    """
    by_identity: dict[str, list[ReconciledAccount]] = defaultdict(list)
    for a in accounts:
        if a.identity_id:
            by_identity[a.identity_id].append(a)
    for ident, group in by_identity.items():
        if len(group) > 1:
            for a in group:
                if a.state == STATE_COMPLETE:
                    a.state = STATE_DUPLICATE
                a.issues.append(f"duplicate_identity:{ident}")

    # Conflict: same OmniRoute connection, different identities
    by_conn: dict[str, list[ReconciledAccount]] = defaultdict(list)
    for a in accounts:
        if a.omniroute_connection_id:
            by_conn[a.omniroute_connection_id].append(a)
    for conn_id, group in by_conn.items():
        if len(group) < 2:
            continue
        idents = {a.identity_id for a in group if a.identity_id}
        if len(idents) > 1:
            for a in group:
                if a.state not in (STATE_DUPLICATE,):
                    a.state = STATE_CONFLICTING_IDENTITY
                a.issues.append(f"conflicting_identity_connection:{conn_id}")


def reconcile_all(
    state: dict | None = None,
    omni_connections: list[dict] | None = None,
    op_items: list[dict] | None = None,
) -> dict[str, ReconciledProvider]:
    """Reconcile every provider present across Hermes/OmniRoute/1Password.

    Pure (no adapter calls). Inputs are already-discovered data so it is
    fully testable and deterministic.
    """
    if state is None:
        state = load_state()
    if omni_connections is None:
        omni_connections = []
    if op_items is None:
        op_items = []

    catalog = load_catalog()
    norm_op = normalize_onepassword_items(op_items, catalog)
    norm_omni = normalize_omniroute_connections(omni_connections)

    # identity email lookup
    identity_email_by_id = {}
    for ident in state.get("identities", []):
        val = ident.get("value")
        if ident.get("type") == "email" and val:
            identity_email_by_id[ident["id"]] = val

    hermes_accounts = state.get("provider_accounts", [])

    # Union of all provider ids seen in any system
    provider_ids: set[str] = set()
    for a in hermes_accounts:
        if a.get("provider_id"):
            provider_ids.add(a["provider_id"])
    for c in norm_omni:
        if c.get("provider_id"):
            provider_ids.add(c["provider_id"])
    for it in norm_op:
        if it.get("provider_id"):
            provider_ids.add(it["provider_id"])

    result: dict[str, ReconciledProvider] = {}
    for pid in sorted(provider_ids):
        result[pid] = reconcile_provider(
            pid, hermes_accounts, norm_omni, norm_op, identity_email_by_id,
        )
    return result


# ── Live discovery path (read-only) ─────────────────────────────────────────

def reconcile_from_sources(state: dict | None = None) -> dict[str, ReconciledProvider]:
    """Build the reconciled model by READ-ONLY discovery from live adapters.

    Reuses engine.audit.reconcile_real_state() for the discovery, then
    normalizes. NEVER mutates any system.
    """
    if state is None:
        state = load_state()

    omni_connections: list[dict] = []
    op_items: list[dict] = []
    try:
        from .audit import reconcile_real_state
        real = reconcile_real_state()
        # Pull normalized connections directly from the adapter (read-only)
        from adapters.omniroute import get_connected_providers
        omni_connections = get_connected_providers() or []
        # 1Password metadata (no secrets)
        from adapters.onepassword import search_items
        raw_op = search_items("api key") + search_items("login") + search_items("token")
        op_items = [{
            "item_id": it.get("id"),
            "title": it.get("title", ""),
            "username": it.get("username"),
            "vault": it.get("vault"),
        } for it in raw_op if isinstance(it, dict)]
    except Exception:
        # Read-only best-effort: if discovery fails, reconcile with what we have.
        pass

    return reconcile_all(state, omni_connections, op_items)


def summarize_reconciliation(recon: dict[str, ReconciledProvider]) -> dict:
    """Produce a deterministic, secret-free summary of reconciliation states."""
    state_counts: dict[str, int] = defaultdict(int)
    provider_summary = {}
    for pid, rp in recon.items():
        counts = defaultdict(int)
        for a in rp.accounts:
            counts[a.state] += 1
            state_counts[a.state] += 1
        provider_summary[pid] = {
            "account_count": rp.account_count,
            "states": dict(counts),
        }
    return {
        "providers": len(recon),
        "total_accounts": sum(rp.account_count for rp in recon.values()),
        "state_counts": dict(state_counts),
        "by_provider": provider_summary,
    }
