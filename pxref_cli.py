"""
pxref_cli.py — Command line interface for provider-xref.

Usage (read-only commands):
    provider-xref audit        — capability/policy classification per provider
    provider-xref reconcile    — three-system reconciliation
    provider-xref accounts     — multi-account model
    provider-xref inventory    — cross-system credential/account inventory
    provider-xref review       — inconsistency review queue
    provider-xref remediate    — approval-gated remediation candidates (dry-run)
    provider-xref onboard      — dry-run onboarding plan
    provider-xref review-set   — set review status metadata only

Usage (approval-gated execution commands):
    provider-xref plan <provider>       — create a plan (PLAN mode)
    provider-xref approve <plan_id>     — approve a plan (APPROVE mode)
    provider-xref execute <plan_id>     — execute an approved plan (EXECUTE mode)
    provider-xref resume <exec_id>      — resume at a checkpoint (RESUME mode)
    provider-xref status <exec_id>      — query execution/checkpoint status (READ mode)

Every command supports --json for machine-readable output.

The approval-gated execution commands use the same deterministic engine as
the Hermes slash-command interface.  See docs/SYSTEM_OVERVIEW.md for details.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Ensure the skill root is on sys.path before importing engine/*.
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
from engine.automation import (  # noqa: E402
    plan_remediation,
)
from engine.account_reconcile import (  # noqa: E402
    account_reconciliation_report,
    reconcile_accounts,
    render_report,
)
from engine.inventory import (  # noqa: E402
    build_inventory,
    inventory_to_dict,
    unmatched_records,
)
from engine.review import (  # noqa: E402
    REVIEW_STATUSES,
    get_review_queue,
    set_review_status,
)
from engine.state import load_state  # noqa: E402
from engine.execution_context import (  # noqa: E402
    ExecutionContext, Mode, CommandRegistry, command_for, build_context,
)
from engine.executor import (  # noqa: E402
    create_execution_request, preflight, approve, execute, resume,
    registration_status, signal_checkpoint_cleared, cancel,
    list_execution_requests,
)
from engine.plan import Plan, load_plan, list_plans, plan_to_execution_request  # noqa: E402


def _emit(payload, as_json: bool, render) -> int:
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
    else:
        render(payload)
    return 0


# ── audit ────────────────────────────────────────────────────────────────────

def cmd_audit(args) -> int:
    caps = build_capabilities()
    payload = {pid: c.to_dict() for pid, c in sorted(caps.items())}

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


# ── remediate (plan only) ────────────────────────────────────────────────────

def cmd_remediate(args) -> int:
    """Show what COULD be remediated. Executes nothing."""
    payload = plan_remediation(load_state())

    def render(p):
        if not p["items"]:
            print("Nothing to remediate.")
            return
        for i in p["items"]:
            gate = "human-only" if i["human_only"] else (
                "executable with approval" if i["executable"] else "not executable")
            print(f"{i['finding_id']}  {i['category']}  ({gate})")
            print(f"    provider: {i['provider_id']}")
            print(f"    account:  {i['account_key']}")
            print(f"    proposed: {i['proposed_action']}")
            for c in i["preconditions"]:
                if not c["ok"]:
                    print(f"    blocked:  {c['check']} — {c['detail']}")
            print()
        print("Nothing was executed. Every action requires explicit approval.")

    return _emit(payload, args.json, render)


# ── account-reconcile ────────────────────────────────────────────────────────

def cmd_account_reconcile(args) -> int:
    """Account-level reconciliation view (read-only; repairs nothing)."""
    st = load_state()
    payload = account_reconciliation_report(st)

    def render(p):
        print(render_report(reconcile_accounts(st)))
        print("status counts:", p["status_counts"])

    return _emit(payload, args.json, render)


# ── inventory ────────────────────────────────────────────────────────────────

def cmd_inventory(args) -> int:
    """Canonical cross-system inventory (read-only)."""
    inv = build_inventory(load_state())
    payload = inventory_to_dict(inv)
    payload["unmatched"] = unmatched_records(inv)

    def render(p):
        for pid, prov in p["providers"].items():
            print(f"{pid}  ({prov['account_count']} account(s))")
            for a in prov["accounts"]:
                who = a["identity"].get("identity_email") or a["account_key"]
                print(f"    {who}")
                print(f"        1Password login:      "
                      f"{'yes' if a['onepassword_login'] else 'no'}")
                print(f"        1Password API key:    "
                      f"{'yes' if a['onepassword_api_key'] else 'no'}")
                print(f"        Hermes reference:     "
                      f"{'yes' if a['hermes_reference'] else 'no'}")
                print(f"        OmniRoute connection: "
                      f"{'yes' if a['omniroute_connection'] else 'no'}")
        s = p["summary"]
        print(f"\n{s['total_accounts']} account(s), {s['providers']} provider(s) "
              f"— read-only inventory.")

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


# ── plan (PLAN mode) ──────────────────────────────────────────────────────────

def cmd_plan(args) -> int:
    """Create a deterministic, immutable plan for provider registration."""
    # Build a PLAN-mode context from the slash-command registry
    cmd_spec = command_for(f"plan_signup {args.provider_id}")
    ctx = build_context(cmd_spec, args.provider_id, request_id=None)

    # Create the plan using the formal Plan model
    plan = Plan.create(
        operation="register_provider",
        provider_id=args.provider_id,
        ctx=ctx,
    )

    # Persist the plan
    plan.save(ctx=ctx)

    payload = {
        "command": "/plan_signup",
        "operation": "register_provider",
        "status": plan.status,
        "plan_id": plan.plan_id,
        "plan_hash": plan.plan_hash_label,
        "plan_version": plan.plan_version,
        "provider_id": plan.provider_id,
        "provider_name": plan.provider_name,
        "next_commands": [
            f"/approve {plan.plan_id}",
            f"/status {plan.plan_id}",
        ],
    }

    def render(p):
        print(plan.to_display())
        print(f"\nNext step: /approve {plan.plan_id}")

    return _emit(payload, args.json, render)


def cmd_plan_list(args) -> int:
    """List all plans."""
    plans = list_plans()
    payload = {
        "plans": [p.to_dict() for p in plans],
    }

    def render(p):
        if not p["plans"]:
            print("No plans found.")
            return
        for plan_dict in p["plans"]:
            print(f"{plan_dict['plan_id']}  {plan_dict['operation']:<20} "
                  f"{plan_dict['provider_id']:<16} {plan_dict['status']}")
        print(f"\n{len(p['plans'])} plan(s).")

    return _emit(payload, args.json, render)


# ── approve (APPROVE mode) ────────────────────────────────────────────────────

def cmd_approve(args) -> int:
    """Approve a plan for execution. Does NOT execute."""
    cmd_spec = command_for("approve")
    ctx = build_context(cmd_spec, None, request_id=args.plan_id)

    plan = load_plan(args.plan_id)
    if plan is None:
        print(f"Plan '{args.plan_id}' not found.", file=sys.stderr)
        return 1

    # Transition plan to approved
    approved_plan = plan.approve(approver=args.approver or "user")
    if approved_plan.approval is None:
        print("Plan approval failed — no approval record generated.", file=sys.stderr)
        return 1

    # Save the approved plan
    approved_plan.save(ctx=ctx)

    payload = {
        "command": "/approve",
        "operation": "approve",
        "status": "APPROVED",
        "plan_id": approved_plan.plan_id,
        "plan_hash": approved_plan.plan_hash_label,
        "plan_version": approved_plan.plan_version,
        "approved_by": approved_plan.approval["approved_by"],
        "approved_at": approved_plan.approval["approved_at"],
        "next_commands": [
            f"/execute {approved_plan.plan_id}",
            f"/status {approved_plan.plan_id}",
        ],
    }

    def render(p):
        print(f"Plan {p['plan_id']} → APPROVED")
        print(f"  hash: {p['plan_hash']}")
        print(f"  approved by: {p['approved_by']} at {p['approved_at']}")
        print(f"\nNext step: /execute {p['plan_id']}")

    return _emit(payload, args.json, render)


# ── execute (EXECUTE mode) ───────────────────────────────────────────────────

def cmd_execute(args) -> int:
    """Execute an approved plan. Creates an execution record."""
    cmd_spec = command_for("execute")
    ctx = build_context(cmd_spec, None, request_id=args.plan_id)

    plan = load_plan(args.plan_id)
    if plan is None:
        print(f"Plan '{args.plan_id}' not found.", file=sys.stderr)
        return 1

    if plan.status != "approved":
        print(f"Plan '{args.plan_id}' is not approved (status={plan.status}). "
              f"Use /approve first.", file=sys.stderr)
        return 1

    # Verify the plan hash hasn't changed
    if not plan.verify_hash():
        print(f"Plan hash verification failed — plan was modified after approval.",
              file=sys.stderr)
        return 1

    # Create execution request from the plan
    exec_request = plan_to_execution_request(plan)
    # Use the executor to create the execution record
    from engine.executor import _save_request, _ensure_exec_dir
    _ensure_exec_dir()
    _save_request(exec_request)

    if args.dry_run or args.dry:
        result = execute(plan.plan_id, dry_run=True, ctx=ctx)
    else:
        result = execute(plan.plan_id, dry_run=False, ctx=ctx)

    payload = {
        "command": "/execute",
        "operation": "execute",
        "status": result.get("status"),
        "plan_id": plan.plan_id,
        "plan_hash": plan.plan_hash_label,
        "request_id": result.get("request_id", plan.plan_id),
        "result": result,
    }
    payload.update(result)

    def render(p):
        status = p.get("status", "unknown")
        if status == "partial" or status == "human_checkpoint":
            cp = p.get("checkpoint", {})
            print(f"Execution paused at checkpoint: {cp.get('checkpoint_type', '?')}")
            print(f"  checkpoint_id: {cp.get('checkpoint_id')}")
            print(f"  state: {cp.get('current_state', 'unknown')}")
            print(f"\nNext step: /resume {p.get('request_id', p.get('plan_id'))}")
            if cp.get("browser_profile"):
                print(f"  browser_profile: {cp['browser_profile']}")
        elif status == "completed":
            print(f"Execution completed: {p.get('request_id')}")
        elif status == "blocked":
            print(f"Execution blocked: {p.get('reason', 'unknown')}")
        else:
            print(f"Execution status: {status}")

    return _emit(payload, args.json, render)


# ── resume (RESUME mode) ─────────────────────────────────────────────────────

def cmd_resume(args) -> int:
    """Resume an execution at a human checkpoint."""
    cmd_spec = command_for("resume")
    ctx = build_context(cmd_spec, None, request_id=args.exec_id)

    result = resume(
        args.exec_id,
        checkpoint_cleared=args.signal_checkpoint_cleared,
        ctx=ctx,
    )

    payload = {
        "command": "/resume",
        "operation": "resume",
        "status": result.get("status"),
        "request_id": args.exec_id,
        "result": result,
    }
    payload.update({k: v for k, v in result.items() if k != "status"})

    def render(p):
        status = p.get("status", "unknown")
        if status == "completed":
            print(f"Execution completed: {p.get('request_id')}")
        elif status == "partial" or status == "human_checkpoint":
            cp = p.get("checkpoint", {})
            print(f"Still waiting at checkpoint: {cp.get('checkpoint_type', '?')}")
            print(f"  state: {cp.get('current_state', 'unknown')}")
            print(f"\nNext step: /resume {args.exec_id}")
        elif status == "blocked":
            print(f"Blocked: {p.get('reason', 'unknown')}")
        else:
            print(f"Resume status: {status}")

    return _emit(payload, args.json, render)


# ── status (READ mode) ───────────────────────────────────────────────────────

def cmd_status(args) -> int:
    """Query the status of an execution request or plan."""
    cmd_spec = command_for("status")
    ctx = build_context(cmd_spec, None, request_id=args.exec_id)

    status = registration_status(args.exec_id, ctx=ctx)

    payload = {
        "command": "/status",
        "operation": "status",
        "plan_id": status.get("plan_id"),
        "plan_hash": status.get("plan_hash"),
        "plan_version": status.get("plan_version"),
        "status": status.get("status"),
        "provider_id": status.get("provider_id"),
        "approved": status.get("approved"),
        "checkpoint": status.get("checkpoint"),
    }

    def render(p):
        s = p.get("status", "unknown")
        print(f"Execution: {p.get('plan_id', args.exec_id)}")
        print(f"  status:  {s}")
        print(f"  plan_hash: {p.get('plan_hash', 'N/A')}")
        print(f"  approved: {p.get('approved', False)}")
        if p.get("checkpoint"):
            cp = p["checkpoint"]
            print(f"  checkpoint: {cp.get('type', '?')} — {cp.get('state', '?')}")
            if cp.get("is_awaiting_human"):
                print(f"  Waiting for human action. Signal completion with:")
                print(f"    /resume {args.exec_id} --signal-checkpoint-cleared")
        else:
            print(f"  checkpoint: (none)")

    return _emit(payload, args.json, render)


# ── MCP server command ────────────────────────────────────────────────────

def cmd_mcp(args) -> int:
    """Launch the MCP server (stdio transport)."""
    from mcp_server import run_mcp_server
    run_mcp_server()
    return 0


# ── Web dashboard command ──────────────────────────────────────────────────

def cmd_web(args) -> int:
    """Launch the localhost web dashboard."""
    from web.server import run_web_server
    run_web_server(port=args.port)
    return 0


# ── parser ───────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="provider-xref",
        description="Provider cross-reference and registration tool.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    def add(name, fn, help_):
        sp = sub.add_parser(name, help=help_)
        sp.add_argument("--json", action="store_true", help="machine-readable output")
        sp.set_defaults(func=fn)
        return sp

    # Read-only commands
    add("audit", cmd_audit, "provider capability/policy classification")
    add("reconcile", cmd_reconcile, "three-system reconciliation (read-only)")
    add("accounts", cmd_accounts, "multi-account model (read-only)")

    sp_review = add("review", cmd_review, "inconsistency review queue (read-only)")
    sp_review.add_argument("--status", action="append", choices=list(REVIEW_STATUSES),
                           help="filter by review status (repeatable)")

    add("remediate", cmd_remediate,
        "list approval-gated remediation candidates (executes nothing)")

    add("account-reconcile", cmd_account_reconcile,
        "account-level reconciliation view (read-only)")
    add("inventory", cmd_inventory, "cross-system credential/account inventory")

    sp_onb = add("onboard", cmd_onboard,
                 "DRY-RUN onboarding plan (registers nothing)")
    sp_onb.add_argument("provider_id", nargs="?", default=None,
                        help="provider id; omit to plan wave 1")

    sp_set = add("review-set", cmd_review_set, "set review status metadata only")
    sp_set.add_argument("finding_id")
    sp_set.add_argument("status", choices=list(REVIEW_STATUSES))
    sp_set.add_argument("--note", default=None)

    # Approval-gated execution commands (Phase 9)
    sp_plan = add("plan", cmd_plan, "create a plan for provider registration (PLAN mode)")
    sp_plan.add_argument("provider_id", help="provider to register with")
    sp_plan.set_defaults(func=cmd_plan)

    # plan-list sub-subcommand
    sp_plan_list = sub.add_parser("plan-list", help="list all plans")
    sp_plan_list.add_argument("--json", action="store_true")
    sp_plan_list.set_defaults(func=cmd_plan_list)

    sp_approve = add("approve", cmd_approve, "approve a plan (APPROVE mode)")
    sp_approve.add_argument("plan_id")
    sp_approve.add_argument("--approver", default="user",
                            help="who is approving (default: user)")

    sp_exec = add("execute", cmd_execute, "execute an approved plan (EXECUTE mode)")
    sp_exec.add_argument("plan_id")
    sp_exec.add_argument("--dry-run", action="store_true", dest="dry_run",
                         help="dry-run: validate but make no external mutations")
    sp_exec.add_argument("--dry", action="store_true",
                         help="alias for --dry-run")

    sp_resume = add("resume", cmd_resume, "resume a paused execution (RESUME mode)")
    sp_resume.add_argument("exec_id")
    sp_resume.add_argument("--signal-checkpoint-cleared", action="store_true",
                           dest="signal_checkpoint_cleared",
                           help="explicitly signal that the human checkpoint is cleared")

    sp_status = add("status", cmd_status, "query execution/plan status (READ mode)")
    sp_status.add_argument("exec_id", help="plan_id or request_id")

    # MCP server (stdio transport)
    sp_mcp = add("mcp", cmd_mcp, "launch MCP server (stdio transport)")
    sp_mcp.add_argument("--port", type=int, default=None,
                        help="Not used for stdio mode; reserved for future HTTP MCP")

    # Web dashboard
    sp_web = add("web", cmd_web, "launch localhost web dashboard")
    sp_web.add_argument("--port", type=int, default=8080,
                        help="Port to listen on (default: 8080)")

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
