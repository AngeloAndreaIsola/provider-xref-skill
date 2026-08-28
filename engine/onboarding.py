"""
onboarding.py — Data-driven provider onboarding pipeline (Phase 15).

Goal: adding a provider should require CATALOG / EXTRACTION data, not engine
edits. This module composes the existing layers into one declarative pipeline:

    provider catalog          (provider_catalog.json)
        ↓
    capability model          (engine.capability — Phase 11)
        ↓
    policy check             (engine.policy)
        ↓
    registration workflow     (engine.registry / workflows/*)
        ↓
    browser/checkpoint reqs   (capability.checkpoint_types, browser_required)
        ↓
    credential extraction     (adapters.credential_extractor rules)
        ↓
    1Password                (adapters.onepassword)
        ↓
    OmniRoute                (adapters.omniroute)
        ↓
    reconciliation           (engine.reconcile — Phase 12)
        ↓
    review queue             (engine.review — Phase 14)

Phase 15 is PLANNING + VALIDATION ONLY. `plan_onboarding()` is a pure dry-run:
it performs no registration, creates no account, writes no credential and
touches no external system. Execution requires an explicit approval object
(see `ApprovalRequest` / Phase 18 for the mutating side).

Policy gate: providers whose policy is `disallowed`, `restricted`, or
`unknown` are never auto-enabled. They may be *planned* (so a human can read
the plan) but `approval_required_reasons` will say why, and
`auto_enable_allowed` stays False.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict

from .capability import (
    POLICY_ALLOWED,
    POLICY_DISALLOWED,
    POLICY_RESTRICTED,
    POLICY_UNKNOWN,
    SUPPORT_SUPPORTED,
    build_capability,
)
from .catalog import get_provider, load_catalog
from .utils import now_iso


# ── Vocabulary ───────────────────────────────────────────────────────────────

STAGE_CATALOG = "catalog"
STAGE_CAPABILITY = "capability"
STAGE_POLICY = "policy"
STAGE_WORKFLOW = "registration_workflow"
STAGE_BROWSER = "browser_checkpoints"
STAGE_EXTRACTION = "credential_extraction"
STAGE_ONEPASSWORD = "onepassword_storage"
STAGE_OMNIROUTE = "omniroute_connection"
STAGE_RECONCILE = "reconciliation"
STAGE_REVIEW = "review"

PIPELINE_STAGES = (
    STAGE_CATALOG, STAGE_CAPABILITY, STAGE_POLICY, STAGE_WORKFLOW,
    STAGE_BROWSER, STAGE_EXTRACTION, STAGE_ONEPASSWORD, STAGE_OMNIROUTE,
    STAGE_RECONCILE, STAGE_REVIEW,
)

READY = "ready"
BLOCKED = "blocked"
NEEDS_DATA = "needs_data"
NEEDS_REVIEW = "needs_review"

# Wave 1 — providers that already ship extraction rules.
PROVIDER_WAVE_1 = ("deepinfra", "siliconflow", "nebius")


# ── Validation results ───────────────────────────────────────────────────────

@dataclass
class StageCheck:
    stage: str
    ok: bool
    detail: str = ""
    data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class OnboardingPlan:
    """A dry-run onboarding plan. Contains no secrets and executes nothing."""
    provider_id: str
    name: str
    status: str = NEEDS_REVIEW
    dry_run: bool = True
    executed: bool = False
    auto_enable_allowed: bool = False
    approval_required: bool = True
    approval_required_reasons: list[str] = field(default_factory=list)
    stages: list[StageCheck] = field(default_factory=list)
    steps: list[dict] = field(default_factory=list)
    checkpoints: list[str] = field(default_factory=list)
    browser_required: bool = False
    credential_type: str | None = None
    blocking_reasons: list[str] = field(default_factory=list)
    created_at: str = ""

    def stage(self, name: str) -> StageCheck | None:
        for s in self.stages:
            if s.stage == name:
                return s
        return None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["stages"] = [s.to_dict() for s in self.stages]
        return d


# ── Individual data-driven validations ───────────────────────────────────────

def validate_catalog_entry(provider_id: str, catalog: dict | None = None) -> StageCheck:
    """Stage 1 — is the provider described in the catalog at all?"""
    if catalog is None:
        catalog = load_catalog()
    p = get_provider(catalog, provider_id)
    if p is None:
        return StageCheck(STAGE_CATALOG, False, "provider not in catalog")
    missing = [f for f in ("id", "name", "auth_type", "signup_url") if not p.get(f)]
    if missing:
        return StageCheck(STAGE_CATALOG, False,
                          f"catalog entry missing fields: {sorted(missing)}")
    return StageCheck(STAGE_CATALOG, True, "catalog entry present", {
        "auth_type": p.get("auth_type"),
        "category": p.get("category"),
        "has_registration_block": isinstance(p.get("registration"), dict),
        "has_extraction_block": isinstance(p.get("extraction"), dict),
        "omniroute_supported": bool(
            (p.get("omniroute_support") or {}).get("supported")),
    })


def validate_capability(provider_id: str, catalog: dict | None = None) -> StageCheck:
    """Stage 2 — the Phase 11 capability model must classify the provider."""
    cap = build_capability(provider_id, catalog)
    ok = cap.support_status == SUPPORT_SUPPORTED and bool(cap.auth_methods)
    detail = "capability classified" if ok else \
        f"support_status={cap.support_status}, auth_methods={cap.auth_methods}"
    return StageCheck(STAGE_CAPABILITY, ok, detail, cap.to_dict())


def validate_policy(provider_id: str, catalog: dict | None = None) -> StageCheck:
    """Stage 3 — the policy gate. Only `allowed` may ever be auto-enabled."""
    cap = build_capability(provider_id, catalog)
    status = cap.policy_status
    ok = status == POLICY_ALLOWED
    if status == POLICY_DISALLOWED:
        detail = "policy disallows registration — never auto-enable"
    elif status == POLICY_RESTRICTED:
        detail = "policy restricted — manual review required"
    elif status == POLICY_UNKNOWN:
        detail = "policy unknown — human verification required"
    else:
        detail = "policy allows registration"
    return StageCheck(STAGE_POLICY, ok, detail, {
        "policy_status": status,
        "automation_allowed": cap.automation_allowed,
        "multiple_accounts": cap.multiple_accounts,
    })


def validate_workflow(provider_id: str, catalog: dict | None = None) -> StageCheck:
    """Stage 4 — a registration workflow must resolve from data."""
    from .registry import get_workflow
    if catalog is None:
        catalog = load_catalog()
    wf = get_workflow(provider_id, catalog)
    if wf is None:
        return StageCheck(STAGE_WORKFLOW, False, "no workflow resolves for provider")
    return StageCheck(STAGE_WORKFLOW, True, "workflow resolved", {
        "workflow": getattr(wf, "name", type(wf).__name__),
    })


def validate_browser_checkpoints(provider_id: str, catalog: dict | None = None) -> StageCheck:
    """Stage 5 — browser and human-checkpoint requirements are declared."""
    cap = build_capability(provider_id, catalog)
    return StageCheck(STAGE_BROWSER, True, "checkpoint requirements derived", {
        "browser_required": cap.browser_required,
        "human_checkpoint_possible": cap.human_checkpoint_possible,
        "checkpoint_types": list(cap.checkpoint_types),
        "headed_browser_required": bool(
            cap.browser_required or cap.human_checkpoint_possible),
    })


def validate_extraction(provider_id: str, catalog: dict | None = None) -> StageCheck:
    """Stage 6 — credential extraction must be data-driven, not hardcoded."""
    from adapters.credential_extractor import get_extraction_rules
    if catalog is None:
        catalog = load_catalog()
    p = get_provider(catalog, provider_id) or {}
    ext = p.get("extraction") if isinstance(p.get("extraction"), dict) else {}
    rules_ref = (ext or {}).get("rules_ref") or provider_id
    rules = get_extraction_rules(rules_ref)
    if not rules:
        return StageCheck(STAGE_EXTRACTION, False,
                          f"no extraction rules for {rules_ref!r} — manual extraction",
                          {"rules_ref": rules_ref, "rule_count": 0})
    return StageCheck(STAGE_EXTRACTION, True, "extraction rules present", {
        "rules_ref": rules_ref,
        "rule_count": len(rules),
        # Rule metadata only — prefixes/patterns are format descriptors,
        # never credential values.
        "credential_types": sorted({r.credential_type for r in rules}),
        "pages": sorted({r.page for r in rules if r.page}),
    })


def validate_onepassword_target(provider_id: str, catalog: dict | None = None) -> StageCheck:
    """Stage 7 — where the credential would be stored (metadata only)."""
    if catalog is None:
        catalog = load_catalog()
    p = get_provider(catalog, provider_id) or {}
    cap = build_capability(provider_id, catalog)
    # Naming convention from Phase 9: "<Provider Name> Api Key".
    return StageCheck(STAGE_ONEPASSWORD, True, "1Password target derived", {
        "planned_login_title": f"{p.get('name', provider_id)} Login",
        "planned_api_key_title": f"{p.get('name', provider_id)} Api Key",
        "credential_type": cap.credential_type,
        "write_requires_approval": True,
    })


def validate_omniroute_target(provider_id: str, catalog: dict | None = None) -> StageCheck:
    """Stage 8 — is the provider connectable in OmniRoute per catalog data?"""
    if catalog is None:
        catalog = load_catalog()
    p = get_provider(catalog, provider_id) or {}
    supported = bool((p.get("omniroute_support") or {}).get("supported"))
    return StageCheck(
        STAGE_OMNIROUTE, supported,
        "omniroute supported" if supported else "omniroute support not declared",
        {
            "omniroute_support": p.get("omniroute_support") or {},
            "connect_requires_approval": True,
        },
    )


def _reconcile_stage() -> StageCheck:
    return StageCheck(STAGE_RECONCILE, True,
                      "post-execution reconciliation is required and read-only",
                      {"module": "engine.reconcile", "read_only": True})


def _review_stage() -> StageCheck:
    return StageCheck(STAGE_REVIEW, True,
                      "result is surfaced through the Phase 14 review queue",
                      {"module": "engine.review", "read_only": True})


# ── Pipeline assembly ────────────────────────────────────────────────────────

_STAGE_VALIDATORS = {
    STAGE_CATALOG: validate_catalog_entry,
    STAGE_CAPABILITY: validate_capability,
    STAGE_POLICY: validate_policy,
    STAGE_WORKFLOW: validate_workflow,
    STAGE_BROWSER: validate_browser_checkpoints,
    STAGE_EXTRACTION: validate_extraction,
    STAGE_ONEPASSWORD: validate_onepassword_target,
    STAGE_OMNIROUTE: validate_omniroute_target,
}

# Stages that must pass for the plan to be *executable at all* (with approval).
_REQUIRED_STAGES = (STAGE_CATALOG, STAGE_CAPABILITY, STAGE_WORKFLOW, STAGE_OMNIROUTE)


def onboarding_steps(provider_id: str, catalog: dict | None = None) -> list[dict]:
    """The ordered, data-derived onboarding steps (declarative; not executed)."""
    cap = build_capability(provider_id, catalog)
    steps: list[dict] = [
        {"step": "validate_catalog_entry", "mutating": False},
        {"step": "validate_capability_model", "mutating": False},
        {"step": "policy_check", "mutating": False},
        {"step": "dry_run_plan", "mutating": False},
        {"step": "require_explicit_approval", "mutating": False,
         "human_approval": True},
    ]
    if cap.browser_required or cap.human_checkpoint_possible:
        steps.append({"step": "open_headed_browser", "mutating": False,
                      "headed": True})
    for ct in cap.checkpoint_types:
        steps.append({"step": f"human_checkpoint:{ct}", "mutating": False,
                      "human_checkpoint": True})
    steps += [
        {"step": "acquire_credential", "mutating": True, "human_approval": True},
        {"step": "store_in_1password", "mutating": True, "human_approval": True},
        {"step": "connect_omniroute", "mutating": True, "human_approval": True},
        {"step": "reconcile", "mutating": False},
        {"step": "verify_account", "mutating": False},
    ]
    return steps


def plan_onboarding(provider_id: str, catalog: dict | None = None) -> OnboardingPlan:
    """Build a DRY-RUN onboarding plan. Mutates nothing, registers nothing."""
    if catalog is None:
        catalog = load_catalog()
    p = get_provider(catalog, provider_id) or {}
    plan = OnboardingPlan(
        provider_id=provider_id,
        name=p.get("name", provider_id),
        created_at=now_iso(),
    )

    for stage in PIPELINE_STAGES:
        validator = _STAGE_VALIDATORS.get(stage)
        if validator is None:
            continue
        try:
            plan.stages.append(validator(provider_id, catalog))
        except Exception as exc:  # never let a data problem look like success
            plan.stages.append(StageCheck(stage, False, f"validation error: {exc}"))
    plan.stages.append(_reconcile_stage())
    plan.stages.append(_review_stage())

    cap = build_capability(provider_id, catalog)
    plan.browser_required = bool(cap.browser_required or cap.human_checkpoint_possible)
    plan.checkpoints = list(cap.checkpoint_types)
    plan.credential_type = cap.credential_type
    plan.steps = onboarding_steps(provider_id, catalog)

    # Blocking = a required stage failed.
    for stage_name in _REQUIRED_STAGES:
        st = plan.stage(stage_name)
        if st is not None and not st.ok:
            plan.blocking_reasons.append(f"{stage_name}: {st.detail}")

    policy_stage = plan.stage(STAGE_POLICY)
    extraction_stage = plan.stage(STAGE_EXTRACTION)

    reasons: list[str] = ["all mutating onboarding steps require explicit human approval"]
    if policy_stage is not None and not policy_stage.ok:
        reasons.append(f"policy: {policy_stage.detail}")
    if extraction_stage is not None and not extraction_stage.ok:
        reasons.append(f"extraction: {extraction_stage.detail}")
    if plan.browser_required:
        reasons.append("headed browser + human checkpoints required")
    plan.approval_required_reasons = reasons
    plan.approval_required = True

    # Auto-enable is ONLY conceivable when policy is explicitly allowed and
    # nothing blocks. Even then Phase 15 never executes.
    plan.auto_enable_allowed = bool(
        policy_stage is not None and policy_stage.ok and not plan.blocking_reasons
    )

    if plan.blocking_reasons:
        plan.status = BLOCKED
    elif policy_stage is not None and not policy_stage.ok:
        plan.status = NEEDS_REVIEW
    elif extraction_stage is not None and not extraction_stage.ok:
        plan.status = NEEDS_DATA
    else:
        plan.status = READY

    return plan


def plan_wave(provider_ids=PROVIDER_WAVE_1, catalog: dict | None = None) -> dict:
    """Plan a wave of providers ONE AT A TIME (no bulk registration).

    Returns plans only. Nothing is registered; nothing is connected.
    """
    if catalog is None:
        catalog = load_catalog()
    plans = {pid: plan_onboarding(pid, catalog) for pid in provider_ids}
    return {
        "wave": list(provider_ids),
        "dry_run": True,
        "bulk_registration": False,
        "sequential_only": True,
        "plans": {pid: pl.to_dict() for pid, pl in sorted(plans.items())},
        "summary": {
            pid: {
                "status": pl.status,
                "auto_enable_allowed": pl.auto_enable_allowed,
                "blocking_reasons": pl.blocking_reasons,
            }
            for pid, pl in sorted(plans.items())
        },
    }


def can_onboard_from_data_only(provider_id: str, catalog: dict | None = None) -> tuple[bool, list[str]]:
    """True when catalog+extraction data alone suffice (no engine changes).

    Used by tests to prove onboarding is data-driven.
    """
    plan = plan_onboarding(provider_id, catalog)
    gaps = list(plan.blocking_reasons)
    ext = plan.stage(STAGE_EXTRACTION)
    if ext is not None and not ext.ok:
        gaps.append(ext.detail)
    return (not gaps), gaps
