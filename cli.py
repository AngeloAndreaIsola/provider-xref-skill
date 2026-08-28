"""
cli.py — Read-only command line interface for provider-xref (Phase 14).

Commands (all READ-ONLY with respect to providers, 1Password, OmniRoute and
Hermes provider state):

    provider-xref audit        — capability/policy classification per provider
    provider-xref reconcile    — Phase 12 three-system reconciliation
    provider-xref accounts     — Phase 13 multi-account model
    provider-xref review       — Phase 14 review queue
    provider-xref review-set   — record review STATUS metadata only

Every command supports --json for machine-readable output.

`review-set` writes ONLY to data/review_state.json (review metadata). It
never mutates provider_state.json, 1Password, OmniRoute or any provider.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SKILL_ROOT = Path(__file__).parent.resolve()
if str(SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT))

from engine.accounts import account_summary, build_account_model  # noqa: E402
from engine.capability import build_capabilities  # noqa: E402
from engine.reconcile import reconcile_all, summarize_reconciliation  # noqa: E402
from engine.onboarding import (  # noqa: E402
    PROVIDER_WAVE_1,
    plan_onboarding,
    plan_wave,
)
from engine.review import (  # noqa: E402
    REVIEW_STATUSES,
    get_review_queue,
    set_review_status,
)
from engine.state import load_state  # noqa: E402


def _emit(payload, as_json: bool, render) -> int:
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
    else:
        render(payload)
    return 0


# ── audit ────────────────────────────────────────────────────────────────────

def cmd_audit(args) -> int:
    caps = build_capabilities()
    payload = {pid: cap.to_dict() for pid, cap in sorted(caps.items())}

    def render(p):
        print(f"{'PROVIDER':<26} {'POLICY':<12} {'SUPPORT':<12} READINESS")
        for pid, c in p.items():
            print(f"{pid:<26} {c.get('policy_status',''):<12} "
                  f"{c.get('support_status',''):<12} {c.get('readiness','')}")
        print(f"\n{len(p)} providers classified (read-only).")

    return _emit(payload, args.json, render)


# ── reconcile ────────────────────────────────────────────────────────────────

def cmd_reconcile(args) -> int:
    recon = reconcile_all(load_state())
    payload = {
        "summary": summarize_reconciliation(recon),
        "providers": {pid: rp.to_dict() for pid, rp in sorted(recon.items())},
    }

    def render(p):
        for pid, rp in p["providers"].items():
            print(f"{pid}  ({rp['account_count']} account(s))")
            for a in rp["accounts"]:
                who = a.get("identity_email") or a.get("account_id")
                print(f"    {who:<36} {a['state']}")
        print("\nstate counts:", p["summary"]["state_counts"])

    return _emit(payload, args.json, render)


# ── accounts ─────────────────────────────────────────────────────────────────

def cmd_accounts(args) -> int:
    model = build_account_model(load_state())
    payload = {
        "summary": account_summary(model),
        "providers": {pid: [a.to_dict() for a in accs]
                      for pid, accs in sorted(model.items())},
    }

    def render(p):
        for pid, accs in p["providers"].items():
            print(f"{pid}")
            for a in accs:
                who = a.get("identity_email") or "(unknown identity)"
                print(f"    {who:<36} {a['reconciliation_state']}")
        s = p["summary"]
        print(f"\n{s['total_accounts']} account(s) across {s['providers']} provider(s)")
        if s["multi_account_providers"]:
            print("multi-account:", ", ".join(s["multi_account_providers"]))

    return _emit(payload, args.json, render)


# ── review ───────────────────────────────────────────────────────────────────

def cmd_review(args) -> int:
    statuses = tuple(args.status) if args.status else None
    queue = get_review_queue(load_state(), include_statuses=statuses)

    def render(q):
        if not q["findings"]:
            print("No findings. (read-only review — nothing was modified)")
            return
        for f in q["findings"]:
            print(f"[{f['severity']:<8}] {f['category']:<30} {f['provider_id']}")
            print(f"           account: {f['account_key']}")
            print(f"           systems: {', '.join(f['systems']) or '(none)'}")
            print(f"           proposed action: {f['recommended_action']} "
                  f"(requires approval; automation_safe={f['automation_safe']})")
            print(f"           review status: {f['review_status']}   id: {f['finding_id']}")
            print()
        print("severity:", q["severity_counts"])
        print(f"{q['total_findings']} finding(s). Read-only: no system was modified.")

    return _emit(queue, args.json, render)


def cmd_review_set(args) -> int:
    entry = set_review_status(args.finding_id, args.status, note=args.note)
    payload = {"finding_id": args.finding_id, "entry": entry,
               "mutated_external_systems": False}

    def render(p):
        print(f"{p['finding_id']} → {p['entry']['status']}")
        print("Review metadata only — no provider, 1Password, OmniRoute or "
              "Hermes state was modified.")

    return _emit(payload, args.json, render)


# ── onboard (dry-run only) ───────────────────────────────────────────────────

def cmd_onboard(args) -> int:
    """Dry-run onboarding plan. Registers nothing, connects nothing."""
    if args.provider_id:
        payload = plan_onboarding(args.provider_id).to_dict()
    else:
        payload = plan_wave(PROVIDER_WAVE_1)

    def render(p):
        plans = [p] if "provider_id" in p else list(p["plans"].values())
        for pl in plans:
            print(f"{pl['provider_id']}  status={pl['status']}  "
                  f"auto_enable_allowed={pl['auto_enable_allowed']}")
            for s in pl["stages"]:
                mark = "OK " if s["ok"] else "!! "
                print(f"   {mark}{s['stage']:<24} {s['detail']}")
            for r in pl["approval_required_reasons"]:
                print(f"   approval: {r}")
            print()
        print("DRY RUN — no provider, 1Password, OmniRoute or Hermes state "
              "was modified. Execution requires explicit approval.")

    return _emit(payload, args.json, render)


# ── parser ───────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="provider-xref",
        description="Read-only provider cross-reference and review tool.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    def add(name, fn, help_):
        sp = sub.add_parser(name, help=help_)
        sp.add_argument("--json", action="store_true", help="machine-readable output")
        sp.set_defaults(func=fn)
        return sp

    add("audit", cmd_audit, "provider capability/policy classification")
    add("reconcile", cmd_reconcile, "three-system reconciliation (read-only)")
    add("accounts", cmd_accounts, "multi-account model (read-only)")

    sp_review = add("review", cmd_review, "inconsistency review queue (read-only)")
    sp_review.add_argument("--status", action="append", choices=list(REVIEW_STATUSES),
                           help="filter by review status (repeatable)")

    sp_onb = add("onboard", cmd_onboard,
                 "DRY-RUN onboarding plan (registers nothing)")
    sp_onb.add_argument("provider_id", nargs="?", default=None,
                        help="provider id; omit to plan wave 1")

    sp_set = add("review-set", cmd_review_set, "set review status metadata only")
    sp_set.add_argument("finding_id")
    sp_set.add_argument("status", choices=list(REVIEW_STATUSES))
    sp_set.add_argument("--note", default=None)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
