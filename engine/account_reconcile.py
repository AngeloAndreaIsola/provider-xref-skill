"""
account_reconcile.py — Account-level reconciliation view (Phase 17).

Phase 12 reconciles, Phase 13 models accounts, Phase 16 inventories records.
Phase 17 assembles them into the complete per-account status view a human
reads, and feeds it straight into the Phase 14 review queue.

    Groq
      Account: lazymause@gmail.com

      Identity:                  ✓
      1Password login:           ✓
      1Password API key:         ✓
      Hermes reference:          ✓
      OmniRoute connection:      ✓

      Status: COMPLETE

There is exactly ONE canonical matching model. This module performs no
matching of its own: it consumes `engine.inventory.build_inventory()` (which
consumes `engine.accounts` → `engine.reconcile`) and projects it.

Read-only. It repairs nothing, and detects/reports:

    missing | duplicate | orphaned | conflicting | unknown
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict

from .inventory import InventoryAccount, InventoryProvider, build_inventory
from .reconcile import (
    STATE_COMPLETE,
    STATE_CONFLICTING_IDENTITY,
    STATE_DUPLICATE,
    STATE_MISSING_API_KEY,
    STATE_MISSING_HERMES,
    STATE_MISSING_LOGIN,
    STATE_MISSING_OMNIROUTE,
    STATE_ORPHANED,
    STATE_UNKNOWN,
)
from .review import build_findings
from .state import load_state


# ── Account-level status vocabulary ─────────────────────────────────────────

STATUS_COMPLETE = "COMPLETE"
STATUS_MISSING = "MISSING"
STATUS_DUPLICATE = "DUPLICATE"
STATUS_ORPHANED = "ORPHANED"
STATUS_CONFLICTING = "CONFLICTING"
STATUS_UNKNOWN = "UNKNOWN"

ACCOUNT_STATUSES = (
    STATUS_COMPLETE, STATUS_MISSING, STATUS_DUPLICATE,
    STATUS_ORPHANED, STATUS_CONFLICTING, STATUS_UNKNOWN,
)

# Canonical reconciliation state → account-level status.
_STATE_TO_STATUS = {
    STATE_COMPLETE: STATUS_COMPLETE,
    STATE_MISSING_LOGIN: STATUS_MISSING,
    STATE_MISSING_API_KEY: STATUS_MISSING,
    STATE_MISSING_OMNIROUTE: STATUS_MISSING,
    STATE_MISSING_HERMES: STATUS_MISSING,
    STATE_DUPLICATE: STATUS_DUPLICATE,
    STATE_ORPHANED: STATUS_ORPHANED,
    STATE_CONFLICTING_IDENTITY: STATUS_CONFLICTING,
    STATE_UNKNOWN: STATUS_UNKNOWN,
}

# The five component checks shown per account, in display order.
COMPONENTS = (
    "identity",
    "onepassword_login",
    "onepassword_api_key",
    "hermes_reference",
    "omniroute_connection",
)

COMPONENT_LABELS = {
    "identity": "Identity",
    "onepassword_login": "1Password login",
    "onepassword_api_key": "1Password API key",
    "hermes_reference": "Hermes reference",
    "omniroute_connection": "OmniRoute connection",
}


@dataclass
class AccountReconciliation:
    """The complete account-level reconciliation row. Secret-free."""
    provider_id: str
    account_key: str
    account_label: str
    identity: dict = field(default_factory=dict)
    components: dict = field(default_factory=dict)     # component → bool
    missing_components: list[str] = field(default_factory=list)
    status: str = STATUS_UNKNOWN
    reconciliation_state: str = STATE_UNKNOWN
    systems_present: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    repaired: bool = False              # always False — Phase 17 never repairs
    requires_human_approval: bool = True

    def to_dict(self) -> dict:
        return asdict(self)


def _account_label(acc: InventoryAccount) -> str:
    return (acc.identity.get("identity_email")
            or acc.identity.get("identity_id")
            or acc.account_key)


def _components_for(acc: InventoryAccount) -> dict:
    return {
        "identity": bool(acc.identity.get("identity_id")
                         or acc.identity.get("identity_email")),
        "onepassword_login": acc.onepassword_login is not None,
        "onepassword_api_key": acc.onepassword_api_key is not None,
        "hermes_reference": acc.hermes_reference is not None,
        "omniroute_connection": acc.omniroute_connection is not None,
    }


def reconcile_inventory_account(acc: InventoryAccount) -> AccountReconciliation:
    """Project one inventory account into its account-level status row.

    Status derives from the canonical reconciliation state. When that state is
    `complete` but a component is missing, the status is downgraded to MISSING
    rather than reported as success — ambiguity never becomes success.
    """
    components = _components_for(acc)
    missing = [c for c in COMPONENTS if not components[c]]
    status = _STATE_TO_STATUS.get(acc.reconciliation_state, STATUS_UNKNOWN)
    if status == STATUS_COMPLETE and missing:
        status = STATUS_MISSING
    return AccountReconciliation(
        provider_id=acc.provider_id,
        account_key=acc.account_key,
        account_label=_account_label(acc),
        identity=dict(acc.identity),
        components=components,
        missing_components=missing,
        status=status,
        reconciliation_state=acc.reconciliation_state,
        systems_present=list(acc.systems_present),
        issues=list(acc.issues),
        repaired=False,
    )


def reconcile_accounts(
    state: dict | None = None,
    omni_connections: list[dict] | None = None,
    op_items: list[dict] | None = None,
    catalog: dict | None = None,
    inventory: dict[str, InventoryProvider] | None = None,
) -> dict[str, list[AccountReconciliation]]:
    """Full provider → account-level reconciliation view (read-only)."""
    if inventory is None:
        if state is None:
            state = load_state()
        inventory = build_inventory(state, omni_connections, op_items, catalog)
    out: dict[str, list[AccountReconciliation]] = {}
    for pid in sorted(inventory):
        out[pid] = [reconcile_inventory_account(a) for a in inventory[pid].accounts]
    return out


def status_counts(view: dict[str, list[AccountReconciliation]]) -> dict:
    counts = {s: 0 for s in ACCOUNT_STATUSES}
    for rows in view.values():
        for r in rows:
            counts[r.status] = counts.get(r.status, 0) + 1
    return counts


def detect_problems(view: dict[str, list[AccountReconciliation]]) -> dict:
    """Group non-complete accounts by problem class. Nothing is repaired."""
    problems = {
        "missing": [], "duplicate": [], "orphaned": [],
        "conflicting": [], "unknown": [],
    }
    mapping = {
        STATUS_MISSING: "missing",
        STATUS_DUPLICATE: "duplicate",
        STATUS_ORPHANED: "orphaned",
        STATUS_CONFLICTING: "conflicting",
        STATUS_UNKNOWN: "unknown",
    }
    for pid in sorted(view):
        for r in view[pid]:
            bucket = mapping.get(r.status)
            if bucket is None:
                continue
            problems[bucket].append({
                "provider_id": r.provider_id,
                "account_key": r.account_key,
                "account_label": r.account_label,
                "missing_components": r.missing_components,
                "reconciliation_state": r.reconciliation_state,
                "issues": r.issues,
            })
    return problems


def account_reconciliation_report(
    state: dict | None = None,
    omni_connections: list[dict] | None = None,
    op_items: list[dict] | None = None,
    catalog: dict | None = None,
) -> dict:
    """Full JSON-serializable account reconciliation report (read-only)."""
    if state is None:
        state = load_state()
    inventory = build_inventory(state, omni_connections, op_items, catalog)
    view = reconcile_accounts(inventory=inventory)
    return {
        "schema_version": 1,
        "read_only": True,
        "repaired_anything": False,
        "status_counts": status_counts(view),
        "problems": detect_problems(view),
        "providers": {
            pid: [r.to_dict() for r in rows] for pid, rows in sorted(view.items())
        },
    }


def to_review_findings(
    state: dict | None = None,
    omni_connections: list[dict] | None = None,
    op_items: list[dict] | None = None,
    catalog: dict | None = None,
):
    """Feed the account-level view into the Phase 14 review system.

    Delegates to `engine.review.build_findings` over the SAME canonical account
    model, so there is no second finding generator.
    """
    from .accounts import build_account_model
    if state is None:
        state = load_state()
    model = build_account_model(state, omni_connections, op_items)
    return build_findings(model=model, catalog=catalog)


def render_report(view: dict[str, list[AccountReconciliation]]) -> str:
    """Human-readable rendering (the Phase 17 target format)."""
    lines: list[str] = []
    for pid in sorted(view):
        lines.append(pid.capitalize() if pid.islower() else pid)
        for r in view[pid]:
            lines.append(f"  Account: {r.account_label}")
            lines.append("")
            for comp in COMPONENTS:
                mark = "✓" if r.components.get(comp) else "✗"
                label = COMPONENT_LABELS[comp] + ":"
                lines.append(f"  {label:<27}{mark}")
            lines.append("")
            lines.append(f"  Status: {r.status}")
            lines.append("")
    lines.append("Read-only: nothing was repaired.")
    return "\n".join(lines)
