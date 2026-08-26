"""
graph.py — Identity / external-account / provider-account relationship graph.

The state is modelled as a directed graph:

    Identity ──authenticates_with──▶ ExternalAccount ──owns──▶ ProviderAccount ──provides──▶ Capability

Additionally:

    Phone ──verifies──▶ Google Account ──enables──▶ GitHub Account ──enables──▶ Provider (OAuth)

The graph supports:
- find_identities()
- find_provider_accounts()
- find_unused_identities()
- find_capabilities()
- find_paths(source, target)
- find_dependents(resource_id)
- get_downstream_providers(identity_id)
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from .state import load_state
from .catalog import load_catalog, get_provider, get_downstream_providers, get_all_providers


# ── Graph construction ──────────────────────────────────────────────────

class ProviderGraph:
    """
    A lightweight in-memory graph built from provider_state.json + provider_catalog.json.

    Nodes: identities, external_accounts, provider_accounts, capabilities
    Edges: relationships as defined in the schema.
    """

    def __init__(self, state: dict | None = None, catalog: dict | None = None):
        self.state = state or load_state()
        self.catalog = catalog or load_catalog()
        self._build()

    def _build(self):
        """Build internal adjacency structures from state + catalog."""
        self.identities: dict[str, dict] = {}
        self.external_accounts: dict[str, dict] = {}
        self.provider_accounts: dict[str, dict] = {}
        self.credentials: dict[str, dict] = {}
        self.capabilities: dict[str, dict] = {}

        # Nodes
        for i in self.state.get("identities", []):
            self.identities[i["id"]] = i
        for ea in self.state.get("external_accounts", []):
            self.external_accounts[ea["id"]] = ea
        for pa in self.state.get("provider_accounts", []):
            self.provider_accounts[pa["id"]] = pa
        for c in self.state.get("credentials", []):
            self.credentials[c["id"]] = c
        for cap in self.state.get("capabilities", []):
            self.capabilities[cap["id"]] = cap

        # Edges: identity_id -> [external_account_ids]
        self.identity_to_external: dict[str, list[str]] = defaultdict(list)
        for ea in self.external_accounts.values():
            if ea.get("identity_id"):
                self.identity_to_external[ea["identity_id"]].append(ea["id"])

        # Edges: external_account_id -> [provider_account_ids]
        self.external_to_provider: dict[str, list[str]] = defaultdict(list)
        for pa in self.provider_accounts.values():
            if pa.get("external_account_id"):
                self.external_to_provider[pa["external_account_id"]].append(pa["id"])

        # Edges: provider_account_id -> [capability_ids]
        self.provider_to_capability: dict[str, list[str]] = defaultdict(list)
        for cap in self.capabilities.values():
            if cap.get("provider_account_id"):
                self.provider_to_capability[cap["provider_account_id"]].append(cap["id"])

        # Edges: identity_id -> [provider_account_ids] (direct link, may skip external)
        self.identity_to_provider: dict[str, list[str]] = defaultdict(list)
        for pa in self.provider_accounts.values():
            if pa.get("identity_id"):
                self.identity_to_provider[pa["identity_id"]].append(pa["id"])

        # Edges: provider_account_id -> [credential_ids]
        self.provider_to_credential: dict[str, list[str]] = defaultdict(list)
        for cred in self.credentials.values():
            if cred.get("provider_account_id"):
                self.provider_to_credential[cred["provider_account_id"]].append(cred["id"])

    # ── Node accessors ───────────────────────────────────────────────────

    def find_identities(self) -> list[dict]:
        """All identities."""
        return list(self.identities.values())

    def find_external_accounts(self) -> list[dict]:
        return list(self.external_accounts.values())

    def find_provider_accounts(self) -> list[dict]:
        return list(self.provider_accounts.values())

    def find_credentials(self) -> list[dict]:
        return list(self.credentials.values())

    def find_capabilities(self) -> list[dict]:
        return list(self.capabilities.values())

    def find_identity(self, identity_id: str) -> dict | None:
        return self.identities.get(identity_id)

    def find_provider_account(self, pa_id: str) -> dict | None:
        return self.provider_accounts.get(pa_id)

    def find_external_account(self, ea_id: str) -> dict | None:
        return self.external_accounts.get(ea_id)

    # ── Queries ───────────────────────────────────────────────────────────

    def find_unused_identities(self) -> list[dict]:
        """
        Return identities that are 'available' and have no associated
        external accounts or provider accounts.

        Important distinction: an unused email != a provider account is
        available. We just report identities with no connections.
        """
        unused = []
        for id in self.identities.values():
            if id.get("status") in ("available", "active"):
                # Check if this identity has any external accounts
                ext_ids = self.identity_to_external.get(id["id"], [])
                if ext_ids:
                    continue
                # Check if this identity is referenced directly in provider accounts
                has_provider = any(
                    pa.get("identity_id") == id["id"]
                    for pa in self.provider_accounts.values()
                )
                if has_provider:
                    continue
                unused.append(id)
        return unused

    def find_unused_emails(self) -> list[dict]:
        """Return email identities that are available and unused."""
        return [i for i in self.find_unused_identities() if i["type"] in ("email", "google")]

    def find_available_phones(self) -> list[dict]:
        """Return phone identities that are available (not consumed)."""
        return [i for i in self.identities.values()
                if i["type"] == "phone" and i.get("status") == "available"]

    def find_connected_providers(self) -> list[dict]:
        """Provider accounts with omniroute_connected=True."""
        return [pa for pa in self.provider_accounts.values() if pa.get("omniroute_connected")]

    def find_disconnected_providers(self) -> list[dict]:
        """Provider accounts in state but NOT connected to OmniRoute."""
        return [pa for pa in self.provider_accounts.values() if not pa.get("omniroute_connected")]

    def find_partially_configured(self) -> list[dict]:
        """Provider accounts with partial setup."""
        results = []
        for pa in self.provider_accounts.values():
            if pa.get("status") == "partially_configured":
                results.append(pa)
            # Also check for missing credential but account exists
            if pa.get("auth_type") == "api_key" and not self.provider_to_credential.get(pa["id"]):
                if pa not in results:
                    results.append(pa)
        return results

    def find_unknown_providers(self) -> list[str]:
        """
        Provider IDs in state that are not in the catalog.
        These need manual review.
        """
        catalog_ids = {p["id"] for p in self.catalog.get("providers", [])}
        state_ids = {pa["provider_id"] for pa in self.provider_accounts.values()}
        return list(state_ids - catalog_ids)

    def get_provider_for_account(self, pa_id: str) -> dict | None:
        """Get the catalog entry for a provider account."""
        pa = self.find_provider_account(pa_id)
        if pa:
            return get_provider(self.catalog, pa["provider_id"])
        return None

    # ── Path finding ─────────────────────────────────────────────────────

    def find_paths(self, source_id: str, target_type: str, visited: set | None = None) -> list[list[str]]:
        """
        Find all paths from a source node to any node of *target_type*.

        Uses BFS for shortest paths.  Paths are lists of node IDs.
        """
        if visited is None:
            visited = set()

        queue = [(source_id, [source_id])]
        paths = []
        visited_local = {source_id}

        while queue:
            node_id, path = queue.pop(0)

            # Check if we've reached the target type
            node = self._get_node(node_id)
            if node and node.get("_type") == target_type and node_id != source_id:
                paths.append(path)
                continue  # Don't traverse further from this node

            # Traverse neighbors
            for neighbor_id in self._get_neighbors(node_id):
                if neighbor_id not in visited_local:
                    visited_local.add(neighbor_id)
                    queue.append((neighbor_id, path + [neighbor_id]))

        return paths

    def _get_node(self, node_id: str) -> dict | None:
        """Get a node by ID from any node type."""
        collections = [
            (self.identities, "identity"),
            (self.external_accounts, "external_account"),
            (self.provider_accounts, "provider_account"),
            (self.credentials, "credential"),
            (self.capabilities, "capability"),
        ]
        for collection, type_name in collections:
            if node_id in collection:
                node = dict(collection[node_id])
                node["_type"] = type_name
                return node
        return None

    def _get_neighbors(self, node_id: str) -> list[str]:
        """Get all outgoing neighbor IDs for a node."""
        neighbors = []

        # Identity -> External Accounts
        if node_id in self.identity_to_external:
            neighbors.extend(self.identity_to_external[node_id])

        # Identity -> Provider Accounts (direct link)
        if node_id in self.identity_to_provider:
            neighbors.extend(self.identity_to_provider[node_id])

        # External Account -> Provider Accounts
        if node_id in self.external_to_provider:
            neighbors.extend(self.external_to_provider[node_id])

        # Provider Account -> Capabilities + Credentials
        if node_id in self.provider_to_capability:
            neighbors.extend(self.provider_to_capability[node_id])
        if node_id in self.provider_to_credential:
            neighbors.extend(self.provider_to_credential[node_id])

        # Provider Account -> Provider (catalog) -> cascades_to providers
        pa = self.find_provider_account(node_id)
        if pa:
            p = get_provider(self.catalog, pa["provider_id"])
            if p and p.get("cascades_to"):
                neighbors.extend(p["cascades_to"])

        return list(set(neighbors))

    # ── Downstream resolution ───────────────────────────────────────────

    def get_downstream_providers(self, provider_id: str) -> list[str]:
        """
        Return provider IDs that can be unlocked by *provider_id*,
        using the catalog's cascades_to field.
        """
        return get_downstream_providers(self.catalog, provider_id)

    def get_downstream_providers_for_identity(self, identity_id: str) -> list[str]:
        """
        Return all provider IDs that could be unlocked by an identity
        of this type, traversing the catalog's identity_relationships
        and cascades_to.
        """
        identity = self.find_identity(identity_id)
        if not identity:
            return []

        identity_type = identity["type"]
        result = set()

        # Find all providers whose identity_requirements include this type
        # or whose identity_relationships include this type
        for p in get_all_providers(self.catalog):
            reqs = p.get("identity_requirements", [])
            rels = p.get("identity_relationships", [])

            if identity_type in reqs or identity_type in rels:
                result.add(p["id"])
                # Add cascaded providers
                for cascade_id in p.get("cascades_to", []):
                    result.add(cascade_id)

        # Also check if this identity type is an upstream identity
        if identity_type in ("google", "github", "microsoft"):
            for p in get_all_providers(self.catalog):
                if p.get("upstream_identity") == identity_type:
                    result.add(p["id"])
                    for cascade_id in p.get("cascades_to", []):
                        result.add(cascade_id)

        return list(result)

    # ── Duplicate detection ──────────────────────────────────────────────

    def find_duplicate_opportunities(self) -> list[dict]:
        """
        Find potential duplicate-account opportunities.

        These are providers where the user has multiple identities
        of the same type that could each create a separate account
        but haven't yet.
        """
        results = []

        # Count identities by type
        type_count: dict[str, list[dict]] = defaultdict(list)
        for id in self.identities.values():
            if id.get("status") in ("available", "active"):
                type_count[id["type"]].append(id)

        # For each provider, check if it supports multiple identity types
        for p in get_all_providers(self.catalog):
            reqs = set(p.get("identity_requirements", []))
            rels = set(p.get("identity_relationships", []))

            # Count how many eligible identities of each type
            eligible = 0
            for t in (reqs | rels):
                eligible += len(type_count.get(t, []))

            if eligible > 1:
                # But check how many are already connected
                connected = [pa for pa in self.provider_accounts.values()
                             if pa["provider_id"] == p["id"] and pa.get("omniroute_connected")]
                if not connected:
                    results.append({
                        "provider_id": p["id"],
                        "provider_name": p["name"],
                        "eligible_identities": eligible,
                        "type": "unconnected_multi_identity",
                    })
                elif len(connected) < eligible:
                    results.append({
                        "provider_id": p["id"],
                        "provider_name": p["name"],
                        "connected_count": len(connected),
                        "eligible_identities": eligible,
                        "type": "partial_multi_identity",
                    })

        return results

    def find_verification_bottlenecks(self) -> list[dict]:
        """
        Find identities that are blocked by verification requirements.
        """
        bottlenecks = []
        for id in self.identities.values():
            if id.get("status") == "active":
                # Check constraints
                for constraint in id.get("constraints", []):
                    if "phone_verification" in constraint or "risk_limit" in constraint:
                        bottlenecks.append({
                            "identity_id": id["id"],
                            "type": id["type"],
                            "value": id["value"],
                            "constraint": constraint,
                            "severity": "high" if "phone" in constraint else "medium",
                        })

            # Check if identity has no phone verification but provider requires it
            if id.get("type") in ("email", "google") and not id.get("verification", {}).get("phone_verified"):
                # Check if any downstream provider requires phone
                downstream = self.get_downstream_providers_for_identity(id["id"])
                for dp_id in downstream:
                    dp = get_provider(self.catalog, dp_id)
                    if dp and "phone" in dp.get("verification_requirements", []):
                        bottlenecks.append({
                            "identity_id": id["id"],
                            "type": id["type"],
                            "value": id["value"],
                            "constraint": f"No phone verification, but downstream provider '{dp['name']}' requires it",
                            "severity": "medium",
                        })

        return bottlenecks

    def find_needs_manual_verification(self) -> int:
        """Count providers/accounts that need manual verification."""
        count = 0
        for pa in self.provider_accounts.values():
            if pa.get("status") in ("unknown", "partially_configured", "error"):
                count += 1
        # Also count unknown providers
        count += len(self.find_unknown_providers())
        return count
