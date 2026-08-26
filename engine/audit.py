"""
audit.py — Structured reconciliation of provider-xref state against reality.

Real-state audit pipeline:
  LOAD local state + catalog
  DISCOVER OmniRoute connections (observed)
  DISCOVER 1Password login items (evidence)
  COMPARE local state ↔ OmniRoute ↔ 1Password ↔ catalog
  CLASSIFY ownership: KNOWN | UNKNOWN | REQUIRES_REVIEW
  REPORT structured results (no secrets)

Key distinction (enforced by the engine):
  Observation (OmniRoute sees a Cursor connection)
    ≠ Ownership (this Cursor account belongs to identity X)
    ≠ Evidence (1Password has a cursor.com login)

The audit reports all three layers independently.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from .state import load_state
from .catalog import load_catalog, get_provider, get_all_providers
from .graph import ProviderGraph
from .policy import (
    get_policy as _get_policy,
    can_automate_registration,
    can_create_multiple_accounts,
    policy_risk_score,
    get_opportunity_policy_status,
)

try:
    from engine.utils import now_iso
except ImportError:
    from ..engine.utils import now_iso


# ── Ownership status values ──────────────────────────────────────────────

OWNERSHIP_STATUSES = ("known", "unknown", "inferred", "requires_review")


# ── Observation / reconciliation core ────────────────────────────────────

def reconcile_real_state() -> dict:
    """
    Perform a read-only reconciliation of local state against OmniRoute,
    1Password, and the catalog.

    This function:
      - Loads local provider_state.json (never writes it)
      - Queries OmniRoute /api/providers (GET only)
      - Queries 1Password for login item metadata (no secrets)
      - Compares all sources against the catalog

    Returns a structured dict with observations, ownership classifications,
    and reconciliation differences.

    NO external mutations are performed.
    """
    state = load_state()
    catalog = load_catalog()
    graph = ProviderGraph(state, catalog)

    # ── Local state summary ─────────────────────────────────────────────
    local_pas = state.get("provider_accounts", [])
    local_pa_map = {pa["provider_id"]: pa for pa in local_pas}
    local_pa_by_omni_id = {
        pa.get("omniroute_account_id"): pa
        for pa in local_pas
        if pa.get("omniroute_account_id")
    }
    local_pa_by_conn_id = {
        pa.get("metadata", {}).get("connection_id"): pa
        for pa in local_pas
        if pa.get("metadata", {}).get("connection_id")
    }

    # ── OmniRoute discovery ─────────────────────────────────────────────
    omni_state = _discover_omniroute(state)
    omni_providers = omni_state["all_omniroute_providers"]
    omni_ids = {p["provider_id"] for p in omni_providers}
    omni_conn_ids = {p.get("connection_id") for p in omni_providers if p.get("connection_id")}

    # ── 1Password discovery (metadata only) ───────────────────────────────
    op_vaults, op_items = _discover_onepassword()

    # ── Match OmniRoute ↔ local state (by UUID, then provider_id) ────────
    matches_omni_state = []
    omri_only = []
    changed = []

    for omni_pa in omni_providers:
        omni_pid = omni_pa["provider_id"]
        omni_conn = omni_pa.get("connection_id")

        # Match 1: by OmniRoute connection UUID
        matched_local = None
        match_method = None

        if omni_conn and omni_conn in local_pa_by_omni_id:
            matched_local = local_pa_by_omni_id[omni_conn]
            match_method = "omniroute_uuid"
        elif omni_conn and omni_conn in local_pa_by_conn_id:
            matched_local = local_pa_by_conn_id[omni_conn]
            match_method = "omniroute_uuid"
        elif omni_pid in local_pa_map:
            matched_local = local_pa_map[omni_pid]
            match_method = "provider_id"

        if matched_local:
            matches_omni_state.append({
                "provider_id": omni_pid,
                "connection_id": omni_conn,
                "match_method": match_method,
                "local_account_id": matched_local.get("id"),
                "local_ownership_status": matched_local.get("ownership_status", "unknown"),
                "local_identity_id": matched_local.get("identity_id"),
                "local_external_account_id": matched_local.get("external_account_id"),
                "local_match_confidence": matched_local.get("match_confidence", "unknown"),
                "auth_type": omni_pa.get("auth_type"),
            })
            # Check if anything changed
            _detect_changes(matched_local, omni_pa, changed)
        else:
            omri_only.append({
                "provider_id": omni_pid,
                "connection_id": omni_conn,
                "auth_type": omni_pa.get("auth_type"),
                "display_name": omni_pa.get("display_name"),
            })

    # ── State-only (in local state but not in OmniRoute) ─────────────────
    state_only = []
    for pid, local_pa in local_pa_map.items():
        if pid not in omni_ids:
            state_only.append({
                "provider_id": pid,
                "account_id": local_pa.get("id"),
                "ownership_status": local_pa.get("ownership_status", "unknown"),
                "identity_id": local_pa.get("identity_id"),
            })

    # ── Catalog coverage ──────────────────────────────────────────────────
    catalog_ids = {p["id"] for p in get_all_providers(catalog)}
    known_omni = [pid for pid in omni_ids if pid in catalog_ids]
    uncatalogued_omni = [pid for pid in omni_ids if pid not in catalog_ids]

    # ── Ownership classification ─────────────────────────────────────────
    ownership = _classify_ownership(omni_providers, local_pas, op_items, catalog)

    # ── 1Password evidence linking ───────────────────────────────────────
    op_evidence = _match_onepassword_to_omni(op_items, omni_providers)

    # ── Auth type distribution ───────────────────────────────────────────
    auth_dist = _auth_distribution(omni_providers)

    # ── Assemble result ───────────────────────────────────────────────────
    return {
        "timestamp": now_iso(),
        "omniroute": {
            "reachable": omni_state["reachable"],
            "connections_observed": len(omni_providers),
            "auth_distribution": auth_dist,
            "known_in_catalog": len(known_omni),
            "uncatalogued": uncatalogued_omni,
            "uncatalogued_count": len(uncatalogued_omni),
        },
        "local_state": {
            "provider_accounts": len(local_pas),
            "identities": len(state.get("identities", [])),
            "external_accounts": len(state.get("external_accounts", [])),
            "credentials": len(state.get("credentials", [])),
        },
        "ownership": {
            "known": len(ownership["known"]),
            "unknown": len(ownership["unknown"]),
            "requires_review": len(ownership["requires_review"]),
            "inferred": len(ownership["inferred"]),
        },
        "reconciliation": {
            "matching_connections": len(matches_omni_state),
            "omniroute_only": len(omri_only),
            "local_only": len(state_only),
            "changed": len(changed),
            "uncatalogued": len(uncatalogued_omni),
        },
        "matches_omni_state": matches_omni_state,
        "omni_only": omri_only,
        "state_only": state_only,
        "ownership_categories": ownership,
        "onepassword": {
            "reachable": bool(op_items) or len(op_vaults) > 0,
            "vaults_discovered": [v["name"] for v in op_vaults],
            "vault_count": len(op_vaults),
            "relevant_items": len(op_items),
            "items": op_items,
            "evidence_links": op_evidence,
        },
        "changed": changed,
        # ── Catalog coverage ─────────────────────────────────────────
        "catalog_coverage": {
            "total_catalog_providers": len([p for p in get_all_providers(catalog)]),
            "observed": [pid for pid in omni_ids if pid in catalog_ids],
            "observed_count": len([pid for pid in omni_ids if pid in catalog_ids]),
            "unobserved": sorted([pid for pid in catalog_ids if pid not in omni_ids]),
            "unobserved_count": len([pid for pid in catalog_ids if pid not in omni_ids]),
            "coverage_percentage": round(len([pid for pid in omni_ids if pid in catalog_ids]) / len(omni_ids) * 100, 1) if omni_ids else 0.0,
            "uncatalogued": sorted(uncatalogued_omni),
            "uncatalogued_count": len(uncatalogued_omni),
        },
        # ── Policy distribution ──────────────────────────────────────
        "policy_distribution": _policy_distribution(omni_providers, catalog),
        # ── Opportunities ────────────────────────────────────────────
        "opportunities": _find_opportunities(omni_providers, ownership, catalog, state, graph),
    }


def _policy_distribution(omni_providers, catalog) -> dict:
    """Count observed providers by policy status."""
    from collections import defaultdict
    dist = defaultdict(int)
    catalog_map = {p["id"]: p for p in get_all_providers(catalog)}
    for p in omni_providers:
        pid = p["provider_id"]
        cat_entry = catalog_map.get(pid)
        if cat_entry:
            policy = cat_entry.get("policy", {})
            auth = policy.get("automation_allowed", "unknown")
            if auth == "allowed":
                dist["ALLOW"] += 1
            elif auth == "disallowed":
                dist["DENY"] += 1
            elif auth == "restricted":
                dist["REQUIRES_REVIEW"] += 1
            else:
                dist["UNKNOWN"] += 1
        else:
            dist["UNKNOWN"] += 1
    return dict(dist)


def _find_opportunities(omni_providers, ownership, catalog, state, graph) -> list:
    """Find registration opportunities using Planner and PolicyEngine."""
    try:
        from .planner import find_opportunities as _find_ops
        return _find_ops(state, catalog)
    except Exception:
        return []


def _discover_omniroute(state: dict) -> dict:
    """Query OmniRoute API for current connections. Returns normalized dict."""
    try:
        from adapters.omniroute import is_running, get_connected_providers
    except ImportError:
        from ..adapters.omniroute import is_running, get_connected_providers

    reachable = is_running()
    if not reachable:
        return {"reachable": False, "all_omniroute_providers": []}

    state_pids = {pa["provider_id"] for pa in state.get("provider_accounts", [])}
    discovery = get_omniroute_state_safe(state_pids)
    return {
        "reachable": True,
        **discovery,
    }


def _discover_onepassword() -> tuple[list[dict], list[dict]]:
    """Query 1Password for vault list and login-item metadata (no secrets)."""
    try:
        from adapters.onepassword import list_vaults, search_items
    except ImportError:
        from ..adapters.onepassword import list_vaults, search_items

    vaults = []
    items = []
    try:
        from adapters.onepassword import ensure_signed_in
    except ImportError:
        from ..adapters.onepassword import ensure_signed_in

    if not ensure_signed_in():
        return vaults, items

    try:
        vaults = list_vaults()
    except Exception:
        vaults = []

    # Search for provider-related login items
    search_terms = ["api key", "provider", "token", "login"]
    seen_ids = set()
    for term in search_terms:
        try:
            found = search_items(term)
            for item in found:
                item_id = item.get("id")
                if item_id and item_id not in seen_ids:
                    seen_ids.add(item_id)
                    items.append(_extract_safe_item_metadata(item))
        except Exception:
            pass

    return vaults, items


def _extract_safe_item_metadata(item: dict) -> dict:
    """
    Extract safe metadata from a 1Password item.

    Explicitly does NOT retrieve:
    - passwords
    - API keys stored as secrets
    - OAuth tokens
    - recovery codes
    - TOTP secrets
    - session cookies

    Only returns: title, id, vault, category, tags, username/email if present.
    """
    vault = item.get("vault", {})
    if isinstance(vault, dict):
        vault_name = vault.get("name", vault.get("id", "?"))
    else:
        vault_name = vault or "?"

    # Extract username/email from the item if available
    # The 'op item list --format json' returns fields with 'reference' but not values
    username = item.get("additional", {}).get("username") or \
               item.get("additional", {}).get("email") or \
               item.get("username") or \
               item.get("email")

    return {
        "item_id": item.get("id"),
        "title": item.get("title", ""),
        "vault": vault_name,
        "category": item.get("category", ""),
        "tags": item.get("tags", []),
        "username": username,  # may be None
    }


def get_omniroute_state_safe(state_provider_ids: set[str] | None = None) -> dict:
    """
    Safe wrapper around discover_omniroute_state that never raises.
    """
    try:
        from adapters.omniroute import discover_omniroute_state
    except ImportError:
        from ..adapters.omniroute import discover_omniroute_state

    try:
        return discover_omniroute_state(state_provider_ids)
    except Exception as e:
        return {
            "reachable": False,
            "all_omniroute_providers": [],
            "total_omniroute_providers": 0,
            "omniroute_only": [],
            "state_only": [],
            "matches": [],
            "uncatalogued": [],
            "ownership_breakdown": {"known": 0, "unknown": 0, "requires_review": 0, "inferred": 0},
            "error": str(e),
        }


def _classify_ownership(
    omni_providers: list[dict],
    local_pas: list[dict],
    op_items: list[dict],
    catalog: dict,
) -> dict:
    """
    Classify each OmniRoute connection's ownership status.

    Returns:
    {
        "known": [...],       # ownership known from local state
        "unknown": [...],       # connection observed but no ownership evidence
        "requires_review": [...],  # 1Password evidence exists but no deterministic match
        "inferred": [...],      # ownership inferred from matching evidence
    }
    """
    # Build local lookup by connection_id and provider_id
    local_by_conn = {}
    local_by_pid = {}
    for pa in local_pas:
        cid = pa.get("omniroute_account_id")
        if cid:
            local_by_conn[cid] = pa
        pid = pa.get("provider_id")
        if pid:
            local_by_pid[pid] = pa

    known = []
    unknown = []
    requires_review = []
    inferred = []

    # Build 1Password evidence map: provider_id → list of items
    op_by_provider = defaultdict(list)
    for item in op_items:
        title = (item.get("title") or "").lower()
        matched_provider = None
        for p in get_all_providers(catalog):
            pid = p["id"].lower()
            pname = p.get("name", "").lower()
            if pid in title or pname in title:
                matched_provider = p["id"]
                break
        if matched_provider:
            op_by_provider[matched_provider].append(item)

    for omni_pa in omni_providers:
        pid = omni_pa.get("provider_id", "")
        conn_id = omni_pa.get("connection_id")

        entry = {
            "provider_id": pid,
            "connection_id": conn_id,
            "auth_type": omni_pa.get("auth_type"),
            "display_name": omni_pa.get("display_name") or pid,
        }

        # Check 1: match by OmniRoute connection UUID in local state
        local_pa = None
        match_method = None
        if conn_id and conn_id in local_by_conn:
            local_pa = local_by_conn[conn_id]
            match_method = "omniroute_uuid"
        elif pid in local_by_pid:
            local_pa = local_by_pid[pid]
            match_method = "provider_id"

        if local_pa:
            # We have a local record for this connection
            identity_id = local_pa.get("identity_id")
            ext_id = local_pa.get("external_account_id")
            ownership = local_pa.get("ownership_status", "unknown")

            if identity_id:
                # Ownership is known
                entry["ownership"] = "known"
                entry["match_method"] = match_method
                entry["identity_id"] = identity_id
                entry["match_confidence"] = "high"
                known.append(entry)
            elif ownership == "requires_review":
                entry["ownership"] = "requires_review"
                entry["match_method"] = match_method
                entry["identity_id"] = None
                entry["match_confidence"] = local_pa.get("match_confidence", "unknown")
                requires_review.append(entry)
            elif ownership == "inferred":
                entry["ownership"] = "inferred"
                entry["match_method"] = match_method
                entry["identity_id"] = identity_id
                entry["match_confidence"] = local_pa.get("match_confidence", "low")
                inferred.append(entry)
            else:
                entry["ownership"] = "known"
                entry["match_method"] = match_method
                entry["identity_id"] = identity_id
                entry["match_confidence"] = local_pa.get("match_confidence", "unknown")
                known.append(entry)
        else:
            # No local record — check if 1Password has evidence
            op_items_for_provider = op_by_provider.get(pid, [])
            if op_items_for_provider:
                # 1Password has a login for this provider, but no local ownership assignment
                usernames = [item.get("username") for item in op_items_for_provider if item.get("username")]
                entry["ownership"] = "requires_review"
                entry["match_method"] = None
                entry["identity_id"] = None
                entry["match_confidence"] = "unknown"
                entry["evidence"] = {
                    "source": "1password",
                    "usernames": usernames if usernames else None,
                    "item_count": len(op_items_for_provider),
                }
                requires_review.append(entry)
            else:
                entry["ownership"] = "unknown"
                entry["match_method"] = None
                entry["identity_id"] = None
                entry["match_confidence"] = "unknown"
                unknown.append(entry)

    return {
        "known": known,
        "unknown": unknown,
        "requires_review": requires_review,
        "inferred": inferred,
    }


def _match_onepassword_to_omni(op_items: list[dict], omni_providers: list[dict]) -> list[dict]:
    """
    Find 1Password items that could be evidence for OmniRoute connections.

    This does NOT assign ownership — it only reports possible evidence links.
    """
    links = []
    for item in op_items:
        title = (item.get("title") or "").lower()
        username = item.get("username")
        for omni_pa in omni_providers:
            pid = omni_pa.get("provider_id", "")
            if pid in title:
                links.append({
                    "provider_id": pid,
                    "connection_id": omni_pa.get("connection_id"),
                    "op_item_id": item.get("item_id"),
                    "op_title": item.get("title"),
                    "op_username": username,
                    "match_type": "title_match",
                })
    return links


def _auth_distribution(omni_providers: list[dict]) -> dict:
    """Count auth types across OmniRoute providers."""
    dist = defaultdict(int)
    for p in omni_providers:
        at = p.get("auth_type") or "unknown"
        dist[at] += 1
    return dict(dist)


def _detect_changes(local_pa: dict, omni_pa: dict, changes: list) -> None:
    """Detect changes between local state and OmniRoute observation."""
    if local_pa.get("auth_type") != omni_pa.get("auth_type"):
        changes.append({
            "provider_id": omni_pa.get("provider_id"),
            "field": "auth_type",
            "old": local_pa.get("auth_type"),
            "new": omni_pa.get("auth_type"),
        })
    if local_pa.get("omniroute_connected") is not True:
        changes.append({
            "provider_id": omni_pa.get("provider_id"),
            "field": "omniroute_connected",
            "old": local_pa.get("omniroute_connected"),
            "new": True,
        })


# ── Legacy audit (kept for backward compatibility) ──────────────────────

def audit() -> dict:
    """
    Legacy audit — produces a structured report from local state + catalog only.
    Use reconcile_real_state() for a full cross-system audit.
    """
    state = load_state()
    catalog = load_catalog()
    graph = ProviderGraph(state, catalog)

    identities = state.get("identities", [])
    ext_accounts = state.get("external_accounts", [])
    provider_accounts = state.get("provider_accounts", [])

    # Identity breakdown
    id_type_count: dict[str, int] = defaultdict(int)
    for id in identities:
        id_type_count[id["type"]] += 1

    connected = sum(1 for pa in provider_accounts if pa.get("omniroute_connected"))
    partially = sum(1 for pa in provider_accounts if pa.get("status") == "partially_configured")
    inactive = sum(1 for pa in provider_accounts
                    if pa.get("omniroute_connected") is False and pa.get("status") != "error")
    error_accounts = sum(1 for pa in provider_accounts if pa.get("status") == "error")

    catalog_ids = {p["id"] for p in catalog.get("providers", [])}
    state_provider_ids = {pa["provider_id"] for pa in provider_accounts}
    unknown_providers = list(state_provider_ids - catalog_ids)
    known_but_unused = [p for p in catalog.get("providers", [])
                        if p["id"] not in state_provider_ids]

    unused_identities = graph.find_unused_identities()
    unused_identities_list = [
        {"id": i["id"], "type": i["type"], "label": i["value"]}
        for i in unused_identities
    ]

    unconnected = [
        {"provider_id": pa["provider_id"], "identity": pa.get("identity_id", "unknown")}
        for pa in provider_accounts
        if not pa.get("omniroute_connected", False)
    ]

    # Ownership breakdown
    ownership_breakdown = {
        "known": sum(1 for pa in provider_accounts if pa.get("ownership_status") == "known"),
        "unknown": sum(1 for pa in provider_accounts if pa.get("ownership_status") in (None, "unknown")),
        "requires_review": sum(1 for pa in provider_accounts if pa.get("ownership_status") == "requires_review"),
        "inferred": sum(1 for pa in provider_accounts if pa.get("ownership_status") == "inferred"),
    }

    # High-value opportunities
    high_value = []
    for p in get_all_providers(catalog):
        if p["id"] in state_provider_ids:
            continue
        policy_status = get_opportunity_policy_status(catalog, p["id"])
        has_identity = _has_compatible_identity(graph, p)
        if not has_identity:
            continue
        if policy_status == "disallowed":
            continue
        score = _score_opportunity(graph, catalog, p)
        high_value.append({
            "provider": p["id"],
            "name": p["name"],
            "auth_type": p["auth_type"],
            "free_quota": p.get("free_tier", {}).get("quota", "Unknown"),
            "policy_status": policy_status,
            "can_automate": _can_automate(catalog, p["id"]),
            "score": score["total"],
            "score_detail": score["components"],
            "confidence": score["confidence"],
        })

    high_value.sort(key=lambda x: x["score"], reverse=True)
    high_value_opportunities = [h for h in high_value if h["score"] > 30]

    blocked = [h for h in high_value if h["policy_status"] == "disallowed"]
    policy_unknown = [
        {"provider": h["provider"], "name": h["name"]}
        for h in high_value
        if h["policy_status"] == "unknown"
    ]

    bottlenecks = graph.find_verification_bottlenecks()
    duplicates = graph.find_duplicate_opportunities()
    manual_count = len(unknown_providers) + len([pa for pa in provider_accounts
                                                if pa.get("status") == "unknown"])

    result = {
        "summary": {
            "identities": len(identities),
            "external_accounts": len(ext_accounts),
            "provider_accounts": len(provider_accounts),
            "connected_providers": connected,
            "partially_configured": partially,
            "known_but_unused_providers": len(known_but_unused),
            "unknown_providers": len(unknown_providers),
            "available_opportunities": len(high_value_opportunities),
        },
        "identities": {
            "by_type": dict(id_type_count),
            "total": len(identities),
            "unused": len(unused_identities),
        },
        "provider_accounts": {
            "connected": connected,
            "partially_configured": partially,
            "disconnected": inactive,
            "error": error_accounts,
            "total": len(provider_accounts),
            "ownership_breakdown": ownership_breakdown,
        },
        "unused_identities": unused_identities_list,
        "unconnected_providers": unconnected,
        "unknown_providers": unknown_providers,
        "high_value_opportunities": high_value_opportunities,
        "blocked_opportunities": blocked,
        "policy_unknown": policy_unknown,
        "identity_bottlenecks": bottlenecks,
        "duplicate_opportunities_count": len(duplicates),
        "duplicate_opportunities": duplicates,
        "needs_manual_verification": manual_count,
    }

    return result


def _has_compatible_identity(graph: ProviderGraph, provider: dict) -> bool:
    """
    Check whether the user has at least one identity compatible with
    this provider's requirements.

    Important: having an email ≠ being able to create an account.
    """
    reqs = set(provider.get("identity_requirements", []))
    rels = set(provider.get("identity_relationships", []))
    needed_types = reqs | rels

    if "none" in needed_types:
        return True

    for id in graph.identities.values():
        if id["type"] in needed_types:
            if id["type"] == "email" and not id.get("verification", {}).get("email_verified"):
                continue
            return True
    return False


def _can_automate(catalog: dict, provider_id: str) -> bool:
    ok, _ = can_automate_registration(catalog, provider_id)
    return ok


def _score_opportunity(graph: ProviderGraph, catalog: dict, provider: dict) -> dict:
    """Score an opportunity using the scoring model from the spec."""
    weights = catalog.get("scoring_weights", {})
    components = {}
    total = 0

    qv = provider.get("tier_value", 25)
    w_qv = weights.get("quota_value", 15) / 15
    components["quota_value"] = int(qv * w_qv)
    total += components["quota_value"]

    us = provider.get("usefulness", 30)
    w_us = weights.get("usefulness", 15) / 15
    components["usefulness"] = int(us * w_us)
    total += components["usefulness"]

    downstream = provider.get("cascades_to", [])
    w_ds = weights.get("downstream_capabilities", 30) / 30
    ds_score = len(downstream) * 10
    components["downstream"] = int(ds_score * w_ds)
    total += components["downstream"]

    ci = provider.get("compatibility", 85)
    w_ci = weights.get("compatibility", 15) / 15
    components["compatibility"] = int((ci / 100) * 15 * w_ci)
    total += components["compatibility"]

    w_af = weights.get("account_freshness", 5) / 5
    unused_count = len(graph.find_unused_identities())
    components["account_freshness"] = int(min(unused_count * 2, 5) * w_af)
    total += components["account_freshness"]

    signup_diff = provider.get("signup_difficulty", "unknown")
    diff_map = {"trivial": 0, "easy": -2, "moderate": -5, "hard": -10, "unknown": -5}
    rc = diff_map.get(signup_diff, -5)
    w_rc = weights.get("registration_cost", -10) / 10
    components["registration_cost"] = int(rc * w_rc)
    total += components["registration_cost"]

    verifs = provider.get("verification_requirements", [])
    vc_map = {"email": -1, "phone": -3, "captcha": -5, "id_document": -10, "manual_review": -5, "none": 0}
    vc = sum(vc_map.get(v, -2) for v in verifs) if verifs else 0
    w_vc = weights.get("verification_cost", -5) / 5
    components["verification_cost"] = int(vc * w_vc)
    total += components["verification_cost"]

    pr = policy_risk_score(catalog, provider["id"])
    w_pr = weights.get("policy_risk", -10) / 10
    pr_scaled = (pr / 50) * 20
    components["policy_risk"] = int(-pr_scaled * w_pr)
    total += components["policy_risk"]

    total = max(0, min(100, total))

    policy = _get_policy(catalog, provider["id"])
    unknown_count = sum(1 for v in policy.values() if v == "unknown")
    total_fields = len(policy)
    confidence = 1.0 - (unknown_count / total_fields) if total_fields > 0 else 0.3
    confidence = max(0.1, confidence)

    return {
        "total": total,
        "components": components,
        "confidence": round(confidence, 2),
    }


# ── Human-readable audit output ────────────────────────────────────────

def audit_text() -> str:
    """
    Produce the human-readable audit report including ownership classification.
    """
    state = load_state()
    catalog = load_catalog()

    # Run the real reconciliation
    try:
        recon = reconcile_real_state()
        omni_reachable = recon["omniroute"]["reachable"]
    except Exception as e:
        recon = None
        omni_reachable = False

    lines = []
    lines.append("Provider Xref Audit")
    lines.append("────────────────────")
    lines.append("")

    # Local state
    local = state.get("provider_accounts", [])
    identities = state.get("identities", [])
    identity_by_type = defaultdict(int)
    for id in identities:
        identity_by_type[id["type"]] += 1

    lines.append("Local State")
    lines.append(f"  {'Identities:':30s} {len(identities):3d}")
    lines.append(f"  {'External accounts:':30s} {len(state.get('external_accounts', [])):3d}")
    lines.append(f"  {'Provider accounts:':30s} {len(local):3d}")
    lines.append(f"  {'Credentials:':30s} {len(state.get('credentials', [])):3d}")
    lines.append(f"  {'Capabilities:':30s} {len(state.get('capabilities', [])):3d}")
    lines.append("")

    # Identity breakdown
    lines.append("Identities by type")
    for id_type, count in sorted(identity_by_type.items()):
        label = {
            "google": "Google accounts",
            "email": "Email identities",
            "github": "GitHub identities",
            "phone": "Phone identities",
            "microsoft": "Microsoft accounts",
            "apple": "Apple accounts",
        }.get(id_type, id_type)
        lines.append(f"  {label:30s} {count:3d}")
    lines.append("")

    if omni_reachable and recon:
        om = recon["omniroute"]
        lines.append("OmniRoute (observed)")
        lines.append(f"  {'Connections:':30s} {om['connections_observed']:3d}")
        if om.get("auth_distribution"):
            for atype, count in sorted(om["auth_distribution"].items()):
                label = {"oauth": "OAuth", "api_key": "API key", "unknown": "Unknown"}.get(atype, atype)
                lines.append(f"  {'  ' + label + ':':30s} {count:3d}")
        lines.append(f"  {'Known in catalog:':30s} {om['known_in_catalog']:3d}")
        lines.append(f"  {'Uncatalogued:':30s} {om['uncatalogued_count']:3d}")
        lines.append("")

        # Ownership
        ow = recon["ownership"]
        lines.append("Ownership")
        lines.append(f"  {'Known:':30s} {ow['known']:3d}")
        lines.append(f"  {'Unknown:':30s} {ow['unknown']:3d}")
        lines.append(f"  {'Requires review:':30s} {ow['requires_review']:3d}")
        lines.append(f"  {'Inferred:':30s} {ow['inferred']:3d}")
        lines.append("")

        # Reconciliation
        rc = recon["reconciliation"]
        lines.append("Reconciliation")
        lines.append(f"  {'Matching connections:':30s} {rc['matching_connections']:3d}")
        lines.append(f"  {'OmniRoute-only:':30s} {rc['omniroute_only']:3d}")
        lines.append(f"  {'Local-only:':30s} {rc['local_only']:3d}")
        lines.append(f"  {'Changed:':30s} {rc['changed']:3d}")
        lines.append(f"  {'Uncatalogued:':30s} {rc['uncatalogued']:3d}")
        lines.append("")

        # 1Password
        op = recon["onepassword"]
        lines.append("1Password")
        lines.append(f"  {'Vaults:':30s} {op['vault_count']:3d}")
        for v in op["vaults_discovered"]:
            lines.append(f"    - {v}")
        lines.append(f"  {'Relevant items:':30s} {op['relevant_items']:3d}")
        lines.append(f"  {'Evidence links:':30s} {len(op.get('evidence_links', [])):3d}")
        lines.append("")

        # Requires review details
        if ow["requires_review"] > 0:
            lines.append("REQUIRES REVIEW")
            for item in recon["ownership_categories"]["requires_review"]:
                lines.append(f"  - {item['provider_id']} ({item.get('auth_type', '?')})")
                if "evidence" in item:
                    ev = item["evidence"]
                    if ev.get("usernames"):
                        lines.append(f"    candidate identity: {ev['usernames'][0]}")
                    lines.append(f"    evidence: 1Password login item")
                    lines.append(f"    confidence: {item.get('match_confidence', 'unknown')}")
            lines.append("")

        # Unknown details
        if ow["unknown"] > 0:
            lines.append("UNKNOWN")
            for item in recon["ownership_categories"]["unknown"]:
                lines.append(f"  - {item['provider_id']} ({item.get('auth_type', '?')})")
                lines.append(f"    OmniRoute connection exists, no ownership evidence")
            lines.append("")

        # Uncatalogued
        if om["uncatalogued_count"] > 0:
            lines.append("UNCATALOGUED (in OmniRoute but not in catalog)")
            for pid in om["uncatalogued"]:
                lines.append(f"  - {pid}")
            lines.append("")

        # OmniRoute-only
        if rc["omniroute_only"] > 0:
            lines.append("OMNIROUTE-ONLY (observed but not in local state)")
            for item in recon["omni_only"]:
                lines.append(f"  - {item['provider_id']} ({item.get('auth_type', '?')})")
                if item.get("connection_id"):
                    lines.append(f"    connection_id: {item['connection_id']}")
            lines.append("")

        # Changed
        if rc["changed"] > 0:
            lines.append("CHANGED (local state differs from OmniRoute)")
            for ch in recon.get("changed", []):
                lines.append(f"  - {ch['provider_id']}: {ch['field']} ({ch['old']} → {ch['new']})")
            lines.append("")
    else:
        lines.append("OmniRoute: not reachable")
        lines.append("")

    # Local opportunities
    result = audit()
    hv = result["high_value_opportunities"]
    if hv:
        lines.append("High-value opportunities")
        for opp in hv:
            lines.append(f"  {opp['name']:20s} {opp['auth_type']:10s} "
                        f"score: {opp['score']:3d}  policy: {opp['policy_status']}")
        lines.append("")
    else:
        lines.append("High-value opportunities: none")
        lines.append("")

    # Policy unknowns
    pu = result.get("policy_unknown", [])
    if pu:
        lines.append("Policy unknown (cannot automate)")
        for p in pu:
            lines.append(f"  - {p['name']} ({p['provider']})")
        lines.append("")

    # Important distinction
    lines.append("─" * 40)
    lines.append("")
    lines.append("Observation ≠ Ownership ≠ Evidence:")
    lines.append("  OmniRoute sees a connection")
    lines.append("    ≠ this account belongs to identity X")
    lines.append("    ≠ 1Password has a login for this provider")
    lines.append("")
    lines.append("Ownership is only assigned when there is")
    lines.append("deterministic evidence (UUID match, verified identity).")
    lines.append("Ambiguous matches are REQUIRES_REVIEW.")

    return "\n".join(lines)