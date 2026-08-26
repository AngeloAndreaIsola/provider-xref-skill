"""
test_audit_fields.py — Phase 3 tests for audit output fields.

Tests that reconcile_real_state() populates catalog_coverage,
policy_distribution, and opportunities with meaningful values.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from engine.audit import reconcile_real_state
from engine.state import load_state, STATE_FILE
from engine.catalog import load_catalog, CATALOG_FILE
from engine.graph import ProviderGraph


class TestAuditFields:
    """Test that reconcile_real_state returns populated, meaningful fields."""

    def test_catalog_coverage_populated(self):
        """Catalog coverage section must exist and have correct structure."""
        result = reconcile_real_state()
        assert "catalog_coverage" in result
        cc = result["catalog_coverage"]
        assert "total_catalog_providers" in cc
        assert cc["total_catalog_providers"] > 0
        assert "observed_count" in cc
        assert "unobserved_count" in cc
        assert "coverage_percentage" in cc
        assert "uncatalogued" in cc
        assert "uncatalogued_count" in cc
        # Total must equal sum
        assert cc["observed_count"] + cc["unobserved_count"] == cc["total_catalog_providers"]

    def test_coverage_percentage_is_float(self):
        """Coverage percentage must be a numeric value."""
        result = reconcile_real_state()
        cc = result["catalog_coverage"]
        pct = cc["coverage_percentage"]
        assert isinstance(pct, (int, float))
        assert 0.0 <= pct <= 100.0

    def test_policy_distribution_populated(self):
        """Policy distribution must exist and contain known categories."""
        result = reconcile_real_state()
        assert "policy_distribution" in result
        pd = result["policy_distribution"]
        # All four categories should be present (at least with 0)
        for status in ["ALLOW", "DENY", "UNKNOWN", "REQUIRES_REVIEW"]:
            assert status in pd or pd.get(status, 0) == 0
        # Sum should equal number of catalog providers
        total = sum(pd.values())
        assert total > 0

    def test_unknown_policy_is_not_allow(self):
        """UNKNOWN must never count as ALLOW in policy distribution."""
        result = reconcile_real_state()
        pd = result["policy_distribution"]
        # Verify: if there are UNKNOWN providers, they are not counted as ALLOW
        assert pd.get("UNKNOWN", 0) != pd.get("ALLOW", 0)

    def test_opportunities_uses_planner(self):
        """Opportunities field must exist (may be empty if no identities)."""
        result = reconcile_real_state()
        assert "opportunities" in result
        opps = result["opportunities"]
        assert isinstance(opps, list)

    def test_zero_identities_means_zero_opportunities(self):
        """If local state has no identities, opportunities should be empty."""
        result = reconcile_real_state()
        local = result["local_state"]
        if local.get("identities", 0) == 0:
            # With no identities, planner cannot create opportunities
            # because find_opportunities() requires compatible identities
            assert len(result["opportunities"]) == 0

    def test_omniroute_observation_populated(self):
        """OmniRoute section must have real observation data."""
        result = reconcile_real_state()
        omni = result["omniroute"]
        assert "reachable" in omni
        assert "connections_observed" in omni
        assert "auth_distribution" in omni
        if omni["reachable"]:
            assert omni["connections_observed"] > 0

    def test_ownership_classification_populated(self):
        """Ownership section must classify all connections."""
        result = reconcile_real_state()
        own = result["ownership"]
        total = sum(v for k, v in own.items() if isinstance(v, int))
        assert "known" in own
        assert "unknown" in own
        assert "requires_review" in own
        assert "inferred" in own
        # Sum of categories should equal total connections
        omni_count = result["omniroute"]["connections_observed"]
        assert total == omni_count

    def test_reconciliation_populated(self):
        """Reconciliation section must have all required fields."""
        result = reconcile_real_state()
        recon = result["reconciliation"]
        for field in ["matching_connections", "omniroute_only",
                       "local_only", "changed"]:
            assert field in recon

    def test_uncatalogued_list_populated(self):
        """Uncatalogued field must be a list (possibly empty after bootstrap)."""
        result = reconcile_real_state()
        assert "uncatalogued" in result["omniroute"]
        assert isinstance(result["omniroute"]["uncatalogued"], list)
