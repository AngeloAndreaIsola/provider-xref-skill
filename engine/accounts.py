"""
accounts.py — Multi-account / multi-identity model (Phase 13).

Phase 12 established a read-only three-system reconciliation. Phase 13 makes
multiple identities / accounts per provider a FIRST-CLASS concept rather than
an implicit provider→one-credential mapping.

Conceptual model
----------------
  provider
    → accounts[]            (NOT provider → one credential)
        → identity           (who authenticates: email / google / github / ...)
        → credentials        (login ref + api key ref, metadata only)
        → omniroute_connection
        → hermes_reference

Matching is DETERMINISTIC and METADATA-BASED. Signals, in priority order:
  1. provider_id + identity (canonical email / identity id)
  2. provider_id + OmniRoute connection id
  3. provider_id + 1Password login item id / api key item id
  4. provider_id + Hermes provider-account id

NEVER an API-key VALUE as an account identifier.

This module is read-only and secret-free. It reuses:
  * engine.reconcile.reconcile_all  (three-system merge)
  * engine.identity.canonical_identity_id / _normalize_email (deterministic keys)
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Any

from .identity import canonical_identity_id, _normalize_email
from .reconcile import reconcile_all, STATE_DUPLICATE, STATE_CONFLICTING_IDENTITY


@dataclass
class AccountView:
    """A first-class account for a provider, normalized across systems.

    Secret-free: credential fields are references / metadata only.
    """
    provider_id: str
    account_id: str                       # deterministic stable key (see account_key)
    identity_id: str | None = None
    identity_email: str | None = None
    identity_type: str | None = None
    login_ref: dict | None = None         # {item_id, title, reference} or None
    api_key_ref: dict | None = None       # {item_id, title, reference} or None
    omniroute_connection_id: str | None = None
    hermes_account_id: str | None = None
    has_login: bool = False
    has_api_key: bool = False
    has_omniroute: bool = False
    has_hermes_ref: bool = False
    ownership_status: str = "unknown"
    reconciliation_state: str = "unknown"
    issues: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def account_key(
    provider_id: str,
    identity_email: str | None = None,
    omniroute_connection_id: str | None = None,
    hermes_account_id: str | None = None,
    identity_id: str | None = None,
) -> str:
    """Deterministic account key. Never uses an API-key value.

    Priority of the identity/anchor component:
      identity_id  >  normalized identity email  >  omniroute connection id
      >  hermes account id  >  'unknown'
    """
    if identity_id:
        anchor = identity_id
    elif identity_email:
        anchor = canonical_identity_id("email", identity_email)
    elif omniroute_connection_id:
        anchor = f"omni:{omniroute_connection_id}"
    elif hermes_account_id:
        anchor = f"hermes:{hermes_account_id}"
    else:
        anchor = "unknown"
    return f"{provider_id}::{anchor}"


def _account_from_reconciled(provider_id: str, acc) -> AccountView:
    """Convert a Phase 12 ReconciledAccount into a Phase 13 AccountView."""
    key = account_key(
        provider_id,
        identity_email=acc.identity_email,
        omniroute_connection_id=acc.omniroute_connection_id,
        hermes_account_id=acc.hermes_account_id,
        identity_id=acc.identity_id,
    )
    identity_type = None
    if acc.identity_id:
        # identity_<type>_...
        parts = acc.identity_id.split("_")
        identity_type = parts[1] if len(parts) > 1 else None
    return AccountView(
        provider_id=provider_id,
        account_id=key,
        identity_id=acc.identity_id,
        identity_email=acc.identity_email,
        identity_type=identity_type,
        login_ref=acc.login_ref,
        api_key_ref=acc.api_key_ref,
        omniroute_connection_id=acc.omniroute_connection_id,
        hermes_account_id=acc.hermes_account_id,
        has_login=acc.has_login,
        has_api_key=acc.has_api_key,
        has_omniroute=acc.has_omniroute,
        has_hermes_ref=acc.has_hermes_ref,
        ownership_status=acc.ownership_status,
        reconciliation_state=acc.state,
        issues=list(acc.issues),
    )


def build_account_model(
    state: dict | None = None,
    omni_connections: list[dict] | None = None,
    op_items: list[dict] | None = None,
) -> dict[str, list[AccountView]]:
    """Build the provider → accounts[] model from the three systems.

    Reuses engine.reconcile.reconcile_all (no re-implementation of the
    three-system merge). Accounts are kept DISTINCT even for the same provider
    (keyed by identity / connection / hermes id).
    """
    recon = reconcile_all(state, omni_connections, op_items)
    model: dict[str, list[AccountView]] = {}
    for pid, rp in recon.items():
        model[pid] = [_account_from_reconciled(pid, a) for a in rp.accounts]
    # Post-process duplicate / conflict detection across accounts per provider
    for pid, accounts in model.items():
        _annotate_duplicates_and_conflicts(accounts)
    return model


# ── Duplicate / conflict detection (read-only) ──────────────────────────────

def _annotate_duplicates_and_conflicts(accounts: list[AccountView]) -> None:
    """Annotate duplicate / conflicting accounts in place (metadata only).

    Duplicate: two accounts for the same provider resolve to the SAME
    account_key (same identity email / same omni connection / same hermes id).
    Two DIFFERENT emails for the same provider is the NORMAL multi-account case
    and is NOT a conflict.

    Conflict: two accounts for the same provider share the SAME OmniRoute
    connection id OR the same Hermes account id, but claim DIFFERENT non-null
    identity emails — i.e. the same underlying connection/account has
    contradictory ownership evidence.
    """
    # 1) Duplicates (same account_key)
    by_key: dict[str, list[AccountView]] = defaultdict(list)
    for a in accounts:
        by_key[a.account_id].append(a)
    for key, group in by_key.items():
        if len(group) > 1:
            for a in group:
                if a.reconciliation_state == "complete":
                    a.reconciliation_state = STATE_DUPLICATE
                _add_issue(a, f"duplicate_account:{key}")

    # 2) Conflicts (same connection/account, different identities)
    by_omni: dict[str, list[AccountView]] = defaultdict(list)
    by_hermes: dict[str, list[AccountView]] = defaultdict(list)
    for a in accounts:
        if a.omniroute_connection_id:
            by_omni[a.omniroute_connection_id].append(a)
        if a.hermes_account_id:
            by_hermes[a.hermes_account_id].append(a)

    for group in (list(by_omni.values()) + list(by_hermes.values())):
        if len(group) < 2:
            continue
        emails = {a.identity_email for a in group if a.identity_email}
        if len(emails) > 1:
            for a in group:
                if a.reconciliation_state not in (STATE_DUPLICATE,):
                    a.reconciliation_state = STATE_CONFLICTING_IDENTITY
                _add_issue(a, f"conflicting_identity:{sorted(emails)}")


def _add_issue(acc: AccountView, issue: str) -> None:
    if issue not in acc.issues:
        acc.issues.append(issue)


def find_duplicate_accounts(model: dict[str, list[AccountView]]) -> list[dict]:
    """Return duplicate-account findings across the model (secret-free)."""
    out = []
    for pid, accounts in model.items():
        by_key: dict[str, list[AccountView]] = defaultdict(list)
        for a in accounts:
            by_key[a.account_id].append(a)
        for key, group in by_key.items():
            if len(group) > 1:
                out.append({
                    "provider_id": pid,
                    "account_key": key,
                    "duplicate_count": len(group),
                    "identity_emails": [g.identity_email for g in group],
                    "omniroute_connection_ids": [g.omniroute_connection_id for g in group],
                })
    return out


def find_conflicting_identities(model: dict[str, list[AccountView]]) -> list[dict]:
    """Return conflicting-identity findings across the model (secret-free).

    Only reports REAL conflicts: two accounts that share the SAME OmniRoute
    connection id OR the same Hermes account id but claim DIFFERENT non-null
    identities. Two distinct identities for the same provider (the normal
    multi-account case) is NOT a conflict and is not reported.
    """
    out = []
    for pid, accounts in model.items():
        by_omni: dict[str, list[AccountView]] = defaultdict(list)
        by_hermes: dict[str, list[AccountView]] = defaultdict(list)
        for a in accounts:
            if a.omniroute_connection_id:
                by_omni[a.omniroute_connection_id].append(a)
            if a.hermes_account_id:
                by_hermes[a.hermes_account_id].append(a)
        for group in (list(by_omni.values()) + list(by_hermes.values())):
            if len(group) < 2:
                continue
            emails = {a.identity_email for a in group if a.identity_email}
            if len(emails) > 1:
                out.append({
                    "provider_id": pid,
                    "conflicting_emails": sorted(emails),
                    "account_ids": [a.account_id for a in group],
                })
    return out


def account_summary(model: dict[str, list[AccountView]]) -> dict:
    """Deterministic, secret-free summary of the multi-account model."""
    provider_counts = {pid: len(accs) for pid, accs in model.items()}
    multi_account_providers = sorted([pid for pid, n in provider_counts.items() if n > 1])
    return {
        "providers": len(model),
        "total_accounts": sum(provider_counts.values()),
        "accounts_per_provider": provider_counts,
        "multi_account_providers": multi_account_providers,
        "duplicate_findings": find_duplicate_accounts(model),
        "conflict_findings": find_conflicting_identities(model),
    }
