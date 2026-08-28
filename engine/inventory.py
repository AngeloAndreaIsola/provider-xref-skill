"""
inventory.py — Cross-system credential and account inventory (Phase 16).

A canonical, READ-ONLY, secret-free, deterministic, multi-account-aware view
of what exists in the three systems:

    1Password : login items, API-key items, item ids, op:// references
    OmniRoute : providers, connections, account ids, connection state
    Hermes    : registration state, provider accounts, credential references

Shape:

    Provider
     └── Account
          ├── Identity
          ├── 1Password login
          ├── 1Password API key
          ├── Hermes reference
          └── OmniRoute connection

IMPORTANT: this module does NOT implement a second reconciliation engine. All
matching goes through the single canonical model:

    engine.reconcile (Phase 12) → engine.accounts (Phase 13)

`inventory.py` is a *discovery + normalization + presentation* layer on top of
that. It adds the raw per-system record views (which the account model does not
expose) and joins them by the ids the account model already resolved.

Never uses an API-key VALUE as an identifier. Never reads a secret value.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict

from .accounts import AccountView, account_summary, build_account_model
from .reconcile import (
    normalize_omniroute_connections,
    normalize_onepassword_items,
)
from .state import load_state
from .utils import now_iso


SYSTEM_ONEPASSWORD = "1password"
SYSTEM_OMNIROUTE = "omniroute"
SYSTEM_HERMES = "hermes"

SYSTEMS = (SYSTEM_ONEPASSWORD, SYSTEM_OMNIROUTE, SYSTEM_HERMES)


# ── Per-system record views (metadata only) ─────────────────────────────────

@dataclass
class OnePasswordRecord:
    """A 1Password item as inventory metadata. No secret value, ever."""
    item_id: str | None
    title: str | None
    kind: str                      # login | api_key | unknown
    provider_id: str | None
    username: str | None = None
    vault: str | None = None
    reference: str | None = None   # op://... acceptable

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class OmniRouteRecord:
    """An OmniRoute connection as inventory metadata."""
    connection_id: str | None
    provider_id: str | None
    display_name: str | None = None
    auth_type: str | None = None
    is_active: bool | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class HermesRecord:
    """A Hermes provider-account record as inventory metadata."""
    hermes_account_id: str | None
    provider_id: str | None
    identity_id: str | None = None
    status: str | None = None
    auth_type: str | None = None
    ownership_status: str = "unknown"
    omniroute_account_id: str | None = None
    credential_reference: str | None = None   # op://... only
    credential_item_id: str | None = None
    last_verified: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class InventoryAccount:
    """One account, joined across systems. Multi-account aware."""
    provider_id: str
    account_key: str
    identity: dict = field(default_factory=dict)
    onepassword_login: OnePasswordRecord | None = None
    onepassword_api_key: OnePasswordRecord | None = None
    omniroute_connection: OmniRouteRecord | None = None
    hermes_reference: HermesRecord | None = None
    reconciliation_state: str = "unknown"
    systems_present: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "provider_id": self.provider_id,
            "account_key": self.account_key,
            "identity": self.identity,
            "onepassword_login": self.onepassword_login.to_dict()
            if self.onepassword_login else None,
            "onepassword_api_key": self.onepassword_api_key.to_dict()
            if self.onepassword_api_key else None,
            "omniroute_connection": self.omniroute_connection.to_dict()
            if self.omniroute_connection else None,
            "hermes_reference": self.hermes_reference.to_dict()
            if self.hermes_reference else None,
            "reconciliation_state": self.reconciliation_state,
            "systems_present": self.systems_present,
            "issues": self.issues,
        }


@dataclass
class InventoryProvider:
    provider_id: str
    accounts: list[InventoryAccount] = field(default_factory=list)

    @property
    def account_count(self) -> int:
        return len(self.accounts)

    def to_dict(self) -> dict:
        return {
            "provider_id": self.provider_id,
            "account_count": self.account_count,
            "accounts": [a.to_dict() for a in self.accounts],
        }


# ── Discovery (read-only, best-effort) ──────────────────────────────────────

def discover_onepassword_items() -> list[dict]:
    """Read-only 1Password metadata discovery. Never reads a secret value."""
    try:
        from adapters.onepassword import search_items
    except Exception:
        return []
    items: list[dict] = []
    seen: set[str] = set()
    for query in ("api key", "login", "token"):
        try:
            found = search_items(query) or []
        except Exception:
            continue
        for it in found:
            if not isinstance(it, dict):
                continue
            iid = it.get("id") or it.get("item_id")
            if not iid or iid in seen:
                continue
            seen.add(iid)
            items.append({
                "item_id": iid,
                "title": it.get("title", ""),
                "username": it.get("username"),
                "vault": (it.get("vault") or {}).get("name")
                if isinstance(it.get("vault"), dict) else it.get("vault"),
            })
    return items


def discover_omniroute_connections() -> list[dict]:
    """Read-only OmniRoute connection discovery."""
    try:
        from adapters.omniroute import get_connected_providers
        return get_connected_providers() or []
    except Exception:
        return []


def discover_hermes_records(state: dict | None = None) -> list[HermesRecord]:
    """Read-only Hermes provider-account discovery from provider state."""
    if state is None:
        state = load_state()
    out: list[HermesRecord] = []
    for pa in state.get("provider_accounts", []):
        ref = pa.get("credential_ref") or {}
        out.append(HermesRecord(
            hermes_account_id=pa.get("id"),
            provider_id=pa.get("provider_id"),
            identity_id=pa.get("identity_id"),
            status=pa.get("status"),
            auth_type=pa.get("auth_type"),
            ownership_status=pa.get("ownership_status", "unknown"),
            omniroute_account_id=pa.get("omniroute_account_id"),
            credential_reference=ref.get("reference"),
            credential_item_id=ref.get("item_id"),
            last_verified=pa.get("last_verified"),
        ))
    return out


# ── Record view builders ────────────────────────────────────────────────────

def _op_records(op_items: list[dict], catalog=None) -> list[OnePasswordRecord]:
    """Normalize 1Password items via the canonical Phase 12 normalizer."""
    normalized = normalize_onepassword_items(op_items, catalog)
    return [
        OnePasswordRecord(
            item_id=n.get("item_id"),
            title=n.get("title"),
            kind=n.get("kind", "unknown"),
            provider_id=n.get("provider_id"),
            username=n.get("username"),
            vault=n.get("vault"),
        )
        for n in normalized
    ]


def _omni_records(omni_connections: list[dict]) -> list[OmniRouteRecord]:
    """Normalize OmniRoute connections via the canonical Phase 12 normalizer."""
    return [
        OmniRouteRecord(
            connection_id=n.get("connection_id"),
            provider_id=n.get("provider_id"),
            display_name=n.get("display_name"),
            auth_type=n.get("auth_type"),
            is_active=n.get("is_active"),
        )
        for n in normalize_omniroute_connections(omni_connections)
    ]


def _ref_record(ref: dict | None, kind: str, provider_id: str | None,
                op_by_id: dict[str, OnePasswordRecord]) -> OnePasswordRecord | None:
    """Turn a credential reference into a 1Password record (metadata only)."""
    if not ref:
        return None
    item_id = ref.get("item_id")
    known = op_by_id.get(item_id) if item_id else None
    return OnePasswordRecord(
        item_id=item_id,
        title=ref.get("title") or (known.title if known else None),
        kind=kind,
        provider_id=provider_id,
        username=known.username if known else None,
        vault=ref.get("vault") or (known.vault if known else None),
        reference=ref.get("reference"),
    )


def _account_from_view(
    acc: AccountView,
    op_by_id: dict[str, OnePasswordRecord],
    omni_by_id: dict[str, OmniRouteRecord],
    hermes_by_id: dict[str, HermesRecord],
) -> InventoryAccount:
    """Join one canonical AccountView with the raw per-system records.

    All ids come from the canonical account model — no re-matching here.
    """
    login = _ref_record(acc.login_ref, "login", acc.provider_id, op_by_id)
    api_key = _ref_record(acc.api_key_ref, "api_key", acc.provider_id, op_by_id)
    omni = omni_by_id.get(acc.omniroute_connection_id) \
        if acc.omniroute_connection_id else None
    hermes = hermes_by_id.get(acc.hermes_account_id) \
        if acc.hermes_account_id else None

    systems = []
    if login or api_key:
        systems.append(SYSTEM_ONEPASSWORD)
    if omni:
        systems.append(SYSTEM_OMNIROUTE)
    if hermes:
        systems.append(SYSTEM_HERMES)

    identity = {
        k: v for k, v in {
            "identity_id": acc.identity_id,
            "identity_email": acc.identity_email,
            "identity_type": acc.identity_type,
            "ownership_status": acc.ownership_status,
        }.items() if v is not None
    }

    return InventoryAccount(
        provider_id=acc.provider_id,
        account_key=acc.account_id,
        identity=identity,
        onepassword_login=login,
        onepassword_api_key=api_key,
        omniroute_connection=omni,
        hermes_reference=hermes,
        reconciliation_state=acc.reconciliation_state,
        systems_present=systems,
        issues=sorted(set(acc.issues)),
    )


# ── Main entry points ───────────────────────────────────────────────────────

def build_inventory(
    state: dict | None = None,
    omni_connections: list[dict] | None = None,
    op_items: list[dict] | None = None,
    catalog: dict | None = None,
) -> dict[str, InventoryProvider]:
    """Build the canonical provider → accounts[] inventory.

    Read-only, deterministic, secret-free. Reuses the Phase 13 account model
    (and therefore the Phase 12 reconciliation) as the ONLY matching engine.
    """
    if state is None:
        state = load_state()
    omni_connections = omni_connections or []
    op_items = op_items or []

    model = build_account_model(state, omni_connections, op_items)

    op_recs = _op_records(op_items, catalog)
    omni_recs = _omni_records(omni_connections)
    hermes_recs = discover_hermes_records(state)

    op_by_id = {r.item_id: r for r in op_recs if r.item_id}
    omni_by_id = {r.connection_id: r for r in omni_recs if r.connection_id}
    hermes_by_id = {r.hermes_account_id: r for r in hermes_recs
                    if r.hermes_account_id}

    inventory: dict[str, InventoryProvider] = {}
    for pid in sorted(model):
        accounts = [
            _account_from_view(acc, op_by_id, omni_by_id, hermes_by_id)
            for acc in sorted(model[pid], key=lambda a: a.account_id)
        ]
        inventory[pid] = InventoryProvider(provider_id=pid, accounts=accounts)
    return inventory


def build_inventory_from_sources(state: dict | None = None,
                                catalog: dict | None = None) -> dict[str, InventoryProvider]:
    """Discover live (read-only) then build the inventory."""
    if state is None:
        state = load_state()
    return build_inventory(
        state=state,
        omni_connections=discover_omniroute_connections(),
        op_items=discover_onepassword_items(),
        catalog=catalog,
    )


def unmatched_records(
    inventory: dict[str, InventoryProvider],
    op_items: list[dict] | None = None,
    omni_connections: list[dict] | None = None,
    catalog: dict | None = None,
) -> dict:
    """Records that exist in a system but are not attached to any account.

    These are candidate orphans — reported, never repaired.
    """
    op_recs = _op_records(op_items or [], catalog)
    omni_recs = _omni_records(omni_connections or [])

    used_items: set[str] = set()
    used_conns: set[str] = set()
    for prov in inventory.values():
        for acc in prov.accounts:
            for rec in (acc.onepassword_login, acc.onepassword_api_key):
                if rec and rec.item_id:
                    used_items.add(rec.item_id)
            if acc.omniroute_connection and acc.omniroute_connection.connection_id:
                used_conns.add(acc.omniroute_connection.connection_id)

    return {
        "onepassword": [r.to_dict() for r in op_recs
                        if r.item_id and r.item_id not in used_items],
        "omniroute": [r.to_dict() for r in omni_recs
                      if r.connection_id and r.connection_id not in used_conns],
    }


def inventory_summary(inventory: dict[str, InventoryProvider]) -> dict:
    """Deterministic, secret-free coverage summary."""
    total_accounts = 0
    coverage = {"onepassword_login": 0, "onepassword_api_key": 0,
                "omniroute_connection": 0, "hermes_reference": 0}
    multi_account = []
    for pid in sorted(inventory):
        prov = inventory[pid]
        total_accounts += prov.account_count
        if prov.account_count > 1:
            multi_account.append(pid)
        for acc in prov.accounts:
            if acc.onepassword_login:
                coverage["onepassword_login"] += 1
            if acc.onepassword_api_key:
                coverage["onepassword_api_key"] += 1
            if acc.omniroute_connection:
                coverage["omniroute_connection"] += 1
            if acc.hermes_reference:
                coverage["hermes_reference"] += 1
    return {
        "generated_at": now_iso(),
        "read_only": True,
        "providers": len(inventory),
        "total_accounts": total_accounts,
        "multi_account_providers": multi_account,
        "coverage": coverage,
    }


def inventory_to_dict(inventory: dict[str, InventoryProvider]) -> dict:
    """Full JSON-serializable inventory payload."""
    return {
        "schema_version": 1,
        "read_only": True,
        "summary": inventory_summary(inventory),
        "providers": {pid: prov.to_dict() for pid, prov in sorted(inventory.items())},
    }
