"""
planner.py — Opportunity detection, scoring, and ranking.

This is the core intelligence of provider-xref.

For every provider:
  Can I create an account?
    ├── already connected → skip
    ├── known duplicate → skip/block
    ├── policy prohibits → block
    ├── policy unknown → manual review
    └── eligible → opportunity

When a new phone/email/identity is reported, the planner builds an
opportunity graph and ranks opportunities by:

  score =
      quota_value       (from catalog.tier_value)
    + usefulness        (from catalog.usefulness)
    + downstream        (number of cascaded providers × weight)
    + compatibility     (from catalog.compatibility, normalized)
    + account_freshness (bonus for unused/fresh identities)
    - registration_cost  (from signup_difficulty)
    - verification_cost  (phone/email verification effort)
    - policy_risk       (from policy_risk_score)

Normalized to 0–100.

The planner does NOT execute registrations.  It produces a plan
that Hermes presents to the user for approval.
"""

from __future__ import annotations

from typing import Any
from datetime import datetime, timezone

from .state import load_state, save_state, now_iso, uuid_id
from .catalog import load_catalog, get_provider, get_all_providers, get_downstream_providers
from .graph import ProviderGraph
from .policy import (
    get_policy, can_automate_registration, can_create_multiple_accounts,
    policy_risk_score, get_opportunity_policy_status,
)
from .audit import _score_opportunity, _has_compatible_identity
from .identity import canonical_identity_id


# ── Opportunity object ─────────────────────────────────────────────────

def make_opportunity(provider: dict, identity: dict | None, catalog: dict) -> dict:
    """
    Create an opportunity dict for a provider + identity pair.
    """
    policy = get_policy(catalog, provider["id"])
    policy_status = get_opportunity_policy_status(catalog, provider["id"])
    can_auto, _ = can_automate_registration(catalog, provider["id"])
    score = _score_opportunity(
        ProviderGraph(load_state(), catalog),
        catalog,
        provider,
    )

    requirements = []
    for req in provider.get("identity_requirements", []):
        if req not in requirements:
            requirements.append(req)
    for rel in provider.get("identity_relationships", []):
        if rel not in requirements:
            requirements.append(rel)

    return {
        "provider": provider["id"],
        "name": provider["name"],
        "auth_type": provider["auth_type"],
        "identity": identity["id"] if identity else None,
        "identity_label": identity["value"] if identity else "any eligible",
        "value": score["total"],
        "confidence": score["confidence"],
        "policy_status": policy_status,
        "can_automate": can_auto,
        "requirements": requirements,
        "free_quota": provider.get("free_tier", {}).get("quota", "Unknown"),
        "omniroute_support": (provider.get("omniroute_support", {}) or {}).get("supported", False) if isinstance(provider.get("omniroute_support"), dict) else bool(provider.get("omniroute_support")),
        "downstream_count": len(provider.get("cascades_to", [])),
        "signup_difficulty": provider.get("signup_difficulty", "unknown"),
        "verification_requirements": provider.get("verification_requirements", []),
    }


# ── Core opportunity detection ─────────────────────────────────────────

def find_opportunities(state: dict | None = None, catalog: dict | None = None) -> list[dict]:
    """
    Find all eligible (not yet connected) provider opportunities.

    An opportunity exists when:
    1. The provider is in the catalog
    2. The provider is NOT already connected in state (or has spare capacity)
    3. The user has a compatible identity
    4. The provider is not policy_disallowed
    """
    if state is None:
        state = load_state()
    if catalog is None:
        catalog = load_catalog()

    graph = ProviderGraph(state, catalog)
    opportunities = []

    connected_provider_ids = {
        pa["provider_id"] for pa in state.get("provider_accounts", [])
        if pa.get("omniroute_connected")
    }

    # Track which identities are already used for a provider
    used_identity_provider_pairs = set()
    for pa in state.get("provider_accounts", []):
        if pa.get("identity_id") and pa.get("provider_id"):
            used_identity_provider_pairs.add((pa["identity_id"], pa["provider_id"]))

    for p in get_all_providers(catalog):
        # Skip already-connected providers (unless multiple accounts allowed)
        multi_ok, _ = can_create_multiple_accounts(catalog, p["id"])

        if p["id"] in connected_provider_ids and not multi_ok:
            continue

        # Find compatible identities
        compatible_ids = _find_compatible_identities(graph, p)

        if not compatible_ids:
            continue  # Can't create account without identity

        # Check policy — skip disallowed
        ps = get_opportunity_policy_status(catalog, p["id"])
        if ps == "disallowed":
            continue

        # Create opportunity for each compatible identity
        # If multiple identities are available, prefer the most "fresh" one for scoring
        for id in compatible_ids:
            pair = (id["id"], p["id"])

            if p["id"] in connected_provider_ids and multi_ok and pair in used_identity_provider_pairs:
                # Already have this identity+provider combo
                continue

            opp = make_opportunity(p, id, catalog)
            opp["identity"] = id["id"]
            opp["identity_label"] = id["value"]
            opportunities.append(opp)

    # Deduplicate by provider_id (keep highest-scoring)
    seen = {}
    for opp in opportunities:
        key = opp["provider"]
        if key not in seen or opp["value"] > seen[key]["value"]:
            seen[key] = opp

    return sorted(seen.values(), key=lambda x: x["value"], reverse=True)


def _find_compatible_identities(graph: ProviderGraph, provider: dict) -> list[dict]:
    """
    Find all identities that satisfy this provider's requirements.
    """
    reqs = set(provider.get("identity_requirements", []))
    rels = set(provider.get("identity_relationships", []))
    needed_types = reqs | rels

    if "none" in needed_types:
        # No identity needed — return any email identity
        return [i for i in graph.identities.values() if i["type"] in ("email", "google")]

    compatible = []
    for id in graph.identities.values():
        if id["type"] in needed_types:
            # For OAuth, check if already used for this provider
            if id.get("status") == "available" or id.get("status") == "active":
                compatible.append(id)

    return compatible


# ── New phone workflow ─────────────────────────────────────────────────

def plan_new_phone(phone_number: str, state: dict | None = None, catalog: dict | None = None) -> dict:
    """
    When Hermes receives "I got a new phone number +31...":

    1. Add the phone as 'available' (not consumed)
    2. Find providers requiring phone verification
    3. Find identity creation opportunities (Google, Microsoft, GitHub)
    4. Calculate downstream value
    5. Produce a ranked plan

    Returns an opportunity graph + ranked plan.
    """
    if state is None:
        state = load_state()
    if catalog is None:
        catalog = load_catalog()

    graph = ProviderGraph(state, catalog)

    # ── Step 1: Classify phone identity status ────────────────────────
    phone_id = canonical_identity_id("phone", phone_number)

    existing = [i for i in state["identities"] if i.get("value") == phone_number]
    phone_classification = "new_phone_identity"
    if existing:
        existing_phone = existing[0]
        if existing_phone.get("status") == "available":
            phone_classification = "existing_available_phone"
        elif existing_phone.get("status") == "consumed":
            phone_classification = "update_existing_phone"
        elif existing_phone.get("status") == "retired":
            phone_classification = "update_existing_phone"
        else:
            phone_classification = "update_existing_phone"
        phone_id = existing_phone["id"]

    # Check if phone is already used by an existing account
    phone_in_use_by_account = any(
        pa.get("metadata", {}).get("phone_number") == phone_number
        for pa in state.get("provider_accounts", [])
    )

    # ── Step 2: Add phone to planning state (shallow copy, NOT saved) ──
    if not existing:
        new_phone = {
            "id": phone_id,
            "type": "phone",
            "label": phone_number,
            "value": phone_number,
            "created_at": now_iso(),
            "status": "available",
            "verification": {"phone_verified": False},
            "constraints": ["new_number"],
            "source": "planning",
            "metadata": {"consumed_for": []},
        }
        state = {k: v for k, v in state.items()}  # shallow copy
        state["identities"] = list(state.get("identities", [])) + [new_phone]
        graph = ProviderGraph(state, catalog)  # rebuild graph with new phone

    # ── Step 2 & 3: Find identity creation opportunities ────────────────
    # Phone can verify: Google, Microsoft, GitHub (if eligible)
    identity_idps = ["google", "microsoft"]

    opportunity_nodes = []
    opportunity_edges = []

    for idp_id in identity_idps:
        idp = get_provider(catalog, idp_id)
        if not idp:
            continue

        # Check if phone can verify this identity
        if "phone" not in idp.get("verification_requirements", []) and idp_id == "microsoft":
            pass  # Microsoft also requires phone

        # Check policy
        ps = get_opportunity_policy_status(catalog, idp_id)
        if ps == "disallowed":
            continue

        can_auto, _ = can_automate_registration(catalog, idp_id)
        score = _score_opportunity(graph, catalog, idp)

        node_id = f"node_{idp_id}"
        opportunity_nodes.append({
            "id": node_id,
            "type": "identity",
            "identity_type": idp_id,
            "provider_id": idp_id,
            "label": f"Create {idp['name']} identity",
            "score": score["total"],
            "confidence": score["confidence"],
            "policy_status": ps,
            "downstream_count": len(idp.get("cascades_to", [])),
            "requirements": ["phone", "email"],
        })

        opportunity_edges.append({
            "source": "new_phone",
            "target": node_id,
            "relationship": "enables",
        })

        # Add downstream provider nodes
        for cascade_id in idp.get("cascades_to", []):
            cascade_p = get_provider(catalog, cascade_id)
            if not cascade_p:
                continue

            cascade_ps = get_opportunity_policy_status(catalog, cascade_id)

            # Check if already connected
            already_connected = any(
                pa["provider_id"] == cascade_id and pa.get("omniroute_connected")
                for pa in state.get("provider_accounts", [])
            )

            downstream_node_id = f"node_{cascade_id}"
            opportunity_nodes.append({
                "id": downstream_node_id,
                "type": "provider",
                "provider_id": cascade_id,
                "label": cascade_p["name"],
                "score": _score_opportunity(graph, catalog, cascade_p)["total"],
                "confidence": 0.7,
                "policy_status": cascade_ps,
                "already_connected": already_connected,
                "auth_type": cascade_p["auth_type"],
            })

            opportunity_edges.append({
                "source": node_id,
                "target": downstream_node_id,
                "relationship": "enables",
            })

    # ── Also find direct provider opportunities ─────────────────────────
    direct_opps = find_opportunities(state, catalog)

    for opp in direct_opps:
        if opp["requirements"] == ["phone"] or opp["auth_type"] == "api_key":
            # Phone-only or direct API key providers
            node_id = f"node_direct_{opp['provider']}"
            opportunity_nodes.append({
                "id": node_id,
                "type": "provider",
                "provider_id": opp["provider"],
                "label": opp["name"],
                "score": opp["value"],
                "confidence": opp["confidence"],
                "policy_status": opp["policy_status"],
                "auth_type": opp["auth_type"],
                "direct": True,
                "already_connected": False,
            })

            opportunity_edges.append({
                "source": "new_phone",
                "target": node_id,
                "relationship": "enables",
            })

    # ── Build ranked plan ────────────────────────────────────────────────
    # Rank by: value × compatibility × downstream × confidence
    plan_nodes = [n for n in opportunity_nodes if n["type"] == "identity"]
    plan_nodes.sort(key=lambda n: n["score"], reverse=True)

    ranked_plan = []
    for node in plan_nodes[:3]:  # Top 3 identity creation opportunities
        downstream = [n["label"] for n in opportunity_nodes
                      if n.get("type") == "provider"
                      and any(e["source"] == node["id"] and e["relationship"] == "enables"
                              for e in opportunity_edges)]
        ranked_plan.append({
            "step": node["label"],
            "description": f"Creates {node['identity_type']} identity, unlocks {node['downstream_count']} downstream providers",
            "unlocks": downstream[:5],
        })

    # Add direct provider opportunities
    direct_nodes = [n for n in opportunity_nodes if n.get("type") == "provider" and n.get("direct")]
    direct_nodes.sort(key=lambda n: n["score"], reverse=True)
    for node in direct_nodes[:5]:
        ranked_plan.append({
            "step": f"Register directly with {node['label']}",
            "description": f"Direct {node['auth_type']} registration",
            "unlocks": [],
        })

    total_new = sum(n["downstream_count"] for n in plan_nodes[:3])
    total_new += sum(1 for n in direct_nodes if not n.get("already_connected"))

    result = {
        "id": uuid_id("plan"),
        "trigger_event": "new_phone",
        "phone_number": phone_number,
        "phone_id": phone_id,
        "phone_classification": phone_classification,
        "phone_in_use_by_account": phone_in_use_by_account,
        "created_at": now_iso(),
        "created": now_iso(),  # alias for compatibility
        "graph": {
            "nodes": opportunity_nodes,
            "edges": opportunity_edges + [{"source": "new_phone", "target": "new_phone", "relationship": "verifies"}],
        },
        "ranked_plan": ranked_plan,
        "summary": {
            "identity_opportunities": len(plan_nodes),
            "direct_provider_opportunities": len(direct_nodes),
            "downstream_provider_opportunities": len([n for n in opportunity_nodes if n["type"] == "provider" and not n.get("direct")]),
            "estimated_total_new_accounts": total_new,
        },
        "status": "planned",
    }

    # Save plan to data/
    from pathlib import Path
    plans_dir = Path(_get_skill_path("data/plans"))
    plans_dir.mkdir(parents=True, exist_ok=True)
    # result['id'] is already prefixed with "plan_" via uuid_id("plan").
    plan_file = plans_dir / f"{result['id']}.json"
    from .utils import save_json_atomic
    save_json_atomic(str(plan_file), result)

    return result


# ── New email workflow ─────────────────────────────────────────────────

def plan_new_email(email_address: str, state: dict | None = None, catalog: dict | None = None) -> dict:
    """
    When Hermes receives "I got a new email":

    1. Add the email as 'available'
    2. Find all providers that accept this email type
    3. Find identity creation opportunities
    4. Calculate downstream value
    5. Produce a ranked plan
    """
    if state is None:
        state = load_state()
    if catalog is None:
        catalog = load_catalog()

    graph = ProviderGraph(state, catalog)

    # Add email to planning state
    existing = [i for i in state["identities"] if i.get("value") == email_address]
    if existing:
        email_id = existing[0]["id"]
    else:
        email_id = canonical_identity_id("email", email_address)
        new_email = {
            "id": email_id,
            "type": "email",
            "label": email_address,
            "value": email_address,
            "created_at": now_iso(),
            "status": "available",
            "verification": {"email_verified": False},
            "constraints": ["unverified"],
            "source": "planning",
        }
        state = {k: v for k, v in state.items()}
        state["identities"] = list(state.get("identities", [])) + [new_email]
        graph = ProviderGraph(state, catalog)

    # Find all opportunit
    direct_opps = find_opportunities(state, catalog)

    # Build graph
    nodes = [{"id": "new_email", "type": "identity", "identity_type": "email",
              "label": f"New email: {email_address}", "score": 100, "confidence": 1.0}]
    edges = []

    for opp in direct_opps:
        node_id = f"node_{opp['provider']}"
        # Check if it cascades
        p = get_provider(catalog, opp["provider"])
        downstream = p.get("cascades_to", []) if p else []

        nodes.append({
            "id": node_id,
            "type": "provider",
            "provider_id": opp["provider"],
            "label": opp["name"],
            "score": opp["value"],
            "confidence": opp["confidence"],
            "policy_status": opp["policy_status"],
            "auth_type": opp["auth_type"],
            "downstream_count": len(downstream),
        })

        edges.append({"source": "new_email", "target": node_id, "relationship": "enables"})

        for ds_id in downstream:
            ds_p = get_provider(catalog, ds_id)
            if ds_p:
                nodes.append({
                    "id": f"node_{ds_id}",
                    "type": "provider",
                    "provider_id": ds_id,
                    "label": ds_p["name"],
                    "score": _score_opportunity(graph, catalog, ds_p)["total"],
                    "confidence": 0.5,
                    "policy_status": get_opportunity_policy_status(catalog, ds_id),
                    "auth_type": ds_p["auth_type"],
                })
                edges.append({"source": node_id, "target": f"node_{ds_id}", "relationship": "enables"})

    # Ranked plan
    ranked_plan = []
    for opp in direct_opps[:5]:
        ranked_plan.append({
            "step": f"Register for {opp['name']}",
            "description": f"Direct {opp['auth_type']} registration, unlocks {opp['downstream_count']} downstream providers",
            "unlocks": [],
        })

    result = {
        "id": uuid_id("plan"),
        "trigger_event": "new_email",
        "email_address": email_address,
        "email_id": email_id,
        "created_at": now_iso(),
        "graph": {"nodes": nodes, "edges": edges},
        "ranked_plan": ranked_plan,
        "summary": {
            "direct_opportunities": len(direct_opps),
            "estimated_total_new_accounts": min(len(direct_opps), 6),
        },
        "status": "planned",
    }

    # Save plan to data/
    from pathlib import Path
    plans_dir = Path(_get_skill_path("data/plans"))
    plans_dir.mkdir(parents=True, exist_ok=True)
    # result['id'] is already prefixed with "plan_" via uuid_id("plan").
    plan_file = plans_dir / f"{result['id']}.json"
    from .utils import save_json_atomic
    save_json_atomic(str(plan_file), result)

    return result


# ── Registration planning ──────────────────────────────────────────────

def plan_registration(provider_id: str, state: dict | None = None, catalog: dict | None = None) -> dict:
    """
    Plan registration for a specific provider.

    Checks:
    1. Is it already connected?
    2. Do we have the required identities?
    3. Is policy known and allows automation?
    4. What workflow steps are needed?
    """
    if state is None:
        state = load_state()
    if catalog is None:
        catalog = load_catalog()

    graph = ProviderGraph(state, catalog)
    provider = get_provider(catalog, provider_id)

    if provider is None:
        return {
            "status": "failed",
            "error": f"Provider '{provider_id}' not found in catalog",
            "provider_id": provider_id,
        }

    # Check if already connected
    existing = [pa for pa in state.get("provider_accounts", [])
                if pa["provider_id"] == provider_id and pa.get("omniroute_connected")]
    if existing:
        return {
            "status": "completed",
            "message": f"Provider '{provider_id}' is already connected to OmniRoute",
            "provider_id": provider_id,
            "provider_name": provider["name"],
            "omniroute_account_id": existing[0].get("omniroute_account_id"),
        }

    # Check identity requirements
    reqs = set(provider.get("identity_requirements", []))
    available_identities = []
    missing_identities = []

    for req_type in reqs:
        matching = [i for i in graph.identities.values()
                    if i["type"] == req_type and i.get("status") in ("available", "active")]
        if matching:
            available_identities.append({"type": req_type, "identities": [i["id"] for i in matching]})
        else:
            missing_identities.append(req_type)

    # Check policy
    policy = get_policy(catalog, provider_id)
    ps = get_opportunity_policy_status(catalog, provider_id)
    can_auto, auto_reason = can_automate_registration(catalog, provider_id)

    # Determine workflow type
    auth_type = provider["auth_type"]
    if auth_type == "api_key":
        workflow = "api_key"
    elif auth_type == "oauth":
        workflow = "oauth"
    elif auth_type == "password":
        workflow = "password"
    else:
        workflow = "unknown"

    # Build step list
    steps = _build_registration_steps(workflow, provider, can_auto)

    plan_id = uuid_id("plan")
    plan = {
        "id": plan_id,
        "provider_id": provider_id,
        "provider_name": provider["name"],
        "auth_type": auth_type,
        "workflow": workflow,
        "status": "planned" if (ps != "disallowed") else "policy_blocked",
        "policy_status": ps,
        "can_automate": can_auto,
        "can_automate_reason": auto_reason,
        "required_identities": list(reqs),
        "available_identities": available_identities,
        "missing_identities": missing_identities,
        "missing_identity_count": len(missing_identities),
        "identity_blocker": len(missing_identities) > 0,
        "steps": steps,
        "created_at": now_iso(),
        "approval_required": not can_auto or ps != "allowed",
        "free_quota": provider.get("free_tier", {}).get("quota", "Unknown"),
    }

    # Save plan
    from pathlib import Path
    plans_dir = Path(_get_skill_path("data/plans"))
    plans_dir.mkdir(parents=True, exist_ok=True)
    # plan_id is already prefixed with "plan_" via uuid_id("plan").
    plan_file = plans_dir / f"{plan_id}.json"
    from .utils import save_json_atomic
    save_json_atomic(str(plan_file), plan)

    return plan


def _build_registration_steps(workflow: str, provider: dict, can_auto: bool) -> list[dict]:
    """Build the step list for a registration workflow."""
    steps = []

    base_steps = [
        ("discover", "DISCOVER"),
        ("eligibility_check", "ELIGIBILITY_CHECK"),
        ("select_identity", "SELECT_IDENTITY"),
        ("prepare_credentials", "PREPARE_CREDENTIALS"),
    ]

    if workflow == "api_key":
        flow_steps = [
            ("open_provider", "OPEN_PROVIDER"),
            ("registration", "REGISTRATION"),
            ("email_verification", "EMAIL_VERIFICATION"),
            ("api_key_extraction", "API_KEY_EXTRACTION"),
            ("omniroute_connection", "OMNIROUTE_CONNECTION"),
            ("onepassword_storage", "1PASSWORD_STORAGE"),
            ("state_update", "STATE_UPDATE"),
            ("verify", "VERIFY"),
            ("complete", "COMPLETE"),
        ]
    elif workflow == "oauth":
        flow_steps = [
            ("open_provider", "OPEN_PROVIDER"),
            ("registration", "REGISTRATION"),
            ("oauth", "OAUTH"),
            ("omniroute_connection", "OMNIROUTE_CONNECTION"),
            ("onepassword_storage", "1PASSWORD_STORAGE"),
            ("state_update", "STATE_UPDATE"),
            ("verify", "VERIFY"),
            ("complete", "COMPLETE"),
        ]
    else:
        flow_steps = [
            ("open_provider", "OPEN_PROVIDER"),
            ("registration", "REGISTRATION"),
            ("email_verification", "EMAIL_VERIFICATION"),
            ("phone_verification", "PHONE_VERIFICATION"),
            ("omniroute_connection", "OMNIROUTE_CONNECTION"),
            ("onepassword_storage", "1PASSWORD_STORAGE"),
            ("state_update", "STATE_UPDATE"),
            ("verify", "VERIFY"),
            ("complete", "COMPLETE"),
        ]

    for name, label in base_steps + flow_steps:
        steps.append({
            "name": name,
            "label": label,
            "status": "pending",
        })

    return steps


# ── Helper ─────────────────────────────────────────────────────────────

def _get_skill_path(relative: str) -> str:
    """Get an absolute path within the skill directory."""
    import os
    from pathlib import Path
    return str(Path(os.path.expanduser(f"~/.hermes/skills/provider-xref/{relative}")))


# ── Phase 7: Batch Planning ─────────────────────────────────────────────
#
# plan_recommended_batch() is a thin composition over the existing
# execution-request system.  It creates one execution request per
# recommendation but NEVER approves or executes them.  Each request
# starts in 'awaiting_approval' — the user must review and approve
# individual requests before any real work happens.


def plan_recommended_batch(
    recommendations: list[dict],
    state: dict | None = None,
    catalog: dict | None = None,
) -> dict:
    """Create execution requests for a batch of recommendations.

    This is a *planning* operation — it creates execution requests in
    'awaiting_approval' status but does NOT approve or execute them.

    For each recommendation:
      - If the provider already has a connection in state, the
        recommendation is skipped (idempotency at the batch level).
      - If the provider is not connected, a new execution request is
        created via create_execution_request().
      - Requests that cannot be created (e.g., missing identity) are
        recorded with an error in the batch summary.

    Returns a dict with:
      - batch_id: unique identifier for this batch
      - created: list of {request_id, provider, status, plan}
      - skipped: list of {provider, reason}
      - errors: list of {provider, error}
      - total_requested: number of recommendations
      - total_created: number of execution requests created
      - total_skipped: number of recommendations skipped
    """
    # Lazy import to avoid circular dependency
    from .executor import create_execution_request
    from .state import load_state as _load_state
    from .catalog import load_catalog as _load_catalog

    if state is None:
        state = _load_state()
    if catalog is None:
        catalog = _load_catalog()

    batch_id = uuid_id("batch")
    connected_provider_ids = {
        pa["provider_id"] for pa in state.get("provider_accounts", [])
        if pa.get("omniroute_connected")
    }

    created = []
    skipped = []
    errors = []

    for rec in recommendations:
        provider_id = rec.get("provider")
        identity_id = rec.get("identity")

        # Skip already-connected providers
        if provider_id in connected_provider_ids:
            skipped.append({
                "provider": provider_id,
                "reason": "already_connected",
            })
            continue

        try:
            req = create_execution_request(
                operation="register_provider",
                provider_id=provider_id,
                identity_id=identity_id,
            )
            created.append({
                "request_id": req["request_id"],
                "provider": provider_id,
                "status": req["status"],
                "policy_status": req.get("policy_status"),
                "can_automate": req.get("plan", {}).get("can_automate"),
            })
        except Exception as e:
            errors.append({
                "provider": provider_id,
                "error": str(e),
            })

    return {
        "batch_id": batch_id,
        "created": created,
        "skipped": skipped,
        "errors": errors,
        "total_requested": len(recommendations),
        "total_created": len(created),
        "total_skipped": len(skipped),
        "total_errors": len(errors),
        "status": "planned",  # Not approved — awaiting user review
        "created_at": now_iso(),
    }
