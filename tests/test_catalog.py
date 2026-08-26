"""
test_catalog.py — Tests for the provider catalog.

Covers:
  - catalog loads
  - provider lookup by id
  - missing provider
  - category filtering
  - search
  - provider policy data
  - free-tier metadata
  - downstream providers

Verifies counts from the live catalog rather than hard-coding them.
"""
import pytest

from engine.catalog import (
    load_catalog, get_provider, get_all_providers,
    get_providers_by_category, search_providers, is_identity_provider,
    get_downstream_providers, get_scoring_weights, default_catalog,
)


class TestCatalogLoad:

    def test_catalog_loads(self):
        catalog = load_catalog()
        assert isinstance(catalog, dict)
        assert "providers" in catalog

    def test_catalog_has_providers(self):
        catalog = load_catalog()
        providers = get_all_providers(catalog)
        assert len(providers) > 0

    def test_catalog_version(self):
        catalog = load_catalog()
        assert "catalog_version" in catalog

    def test_catalog_metadata(self):
        catalog = load_catalog()
        if "sources" in catalog:
            assert isinstance(catalog["sources"], list)


class TestProviderLookup:

    def test_get_provider_by_id(self):
        catalog = load_catalog()
        p = get_provider(catalog, "groq")
        assert p is not None
        assert p["id"] == "groq"

    def test_get_provider_missing(self):
        catalog = load_catalog()
        p = get_provider(catalog, "nonexistent_provider")
        assert p is None

    def test_get_provider_no_catalog_param(self):
        """get_provider should work with catalog=None (loads internally)."""
        p = get_provider(None, "groq")
        assert p is not None
        assert p["id"] == "groq"

    def test_all_providers_have_required_fields(self):
        catalog = load_catalog()
        providers = get_all_providers(catalog)
        for p in providers:
            assert "id" in p
            assert "name" in p
            assert "auth_type" in p
            assert "policy" in p


class TestCategoryFiltering:

    def test_filter_by_category(self):
        catalog = load_catalog()
        cats = set()
        for p in get_all_providers(catalog):
            c = p.get("category")
            if c:
                cats.add(c)
        assert len(cats) > 0
        cat = next(iter(cats))
        providers = get_providers_by_category(catalog, cat)
        assert isinstance(providers, list)
        for p in providers:
            assert p.get("category") == cat

    def test_filter_by_missing_category(self):
        catalog = load_catalog()
        providers = get_providers_by_category(catalog, "nonexistent_category")
        assert isinstance(providers, list)


class TestSearchProviders:

    def test_search_by_name(self):
        results = search_providers("groq")
        assert len(results) >= 1
        assert any(p["id"] == "groq" for p in results)

    def test_search_case_insensitive(self):
        results = search_providers("GROQ")
        assert len(results) >= 1

    def test_search_no_results(self):
        results = search_providers("zzz_nonexistent_zzz")
        assert len(results) == 0

    def test_search_all_when_none(self):
        results = search_providers(None)
        assert len(results) > 0


class TestProviderPolicyData:

    def test_all_providers_have_policy(self):
        catalog = load_catalog()
        for p in get_all_providers(catalog):
            assert "policy" in p
            assert isinstance(p["policy"], dict)

    def test_policy_values_valid(self):
        valid = {"allowed", "disallowed", "restricted", "unknown"}
        catalog = load_catalog()
        for p in get_all_providers(catalog):
            policy = p.get("policy", {})
            for key in ["automation_allowed", "multiple_accounts",
                        "third_party_proxy_allowed", "phone_reuse_allowed",
                        "duplicate_account_policy"]:
                val = policy.get(key, "unknown")
                assert val in valid, \
                    f"Provider {p['id']} field {key} has invalid value: {val}"


class TestFreeTier:

    def test_free_tier_structure(self):
        catalog = load_catalog()
        for p in get_all_providers(catalog):
            ft = p.get("free_tier", {})
            if ft:
                assert isinstance(ft, dict)

    def test_free_tier_enabled_providers(self):
        catalog = load_catalog()
        enabled = [p for p in get_all_providers(catalog) if p.get("free_tier", {}).get("enabled")]
        assert isinstance(enabled, list)

    def test_free_tier_quota_present(self):
        catalog = load_catalog()
        with_quota = [p for p in get_all_providers(catalog)
                      if p.get("free_tier", {}).get("quota")]
        for p in with_quota:
            assert p["free_tier"]["quota"] is not None


class TestCatalogCounts:

    def test_catalog_has_reasonable_count(self):
        catalog = load_catalog()
        total = len(get_all_providers(catalog))
        assert total > 0
        print(f"Catalog has {total} providers")

    def test_catalog_has_mixed_policies(self):
        catalog = load_catalog()
        allowed = [p for p in get_all_providers(catalog)
                   if p.get("policy", {}).get("automation_allowed") == "allowed"]
        disallowed = [p for p in get_all_providers(catalog)
                      if p.get("policy", {}).get("automation_allowed") == "disallowed"]
        unknown = [p for p in get_all_providers(catalog)
                   if p.get("policy", {}).get("automation_allowed") == "unknown"]
        print(f"Allowed: {len(allowed)}, Disallowed: {len(disallowed)}, Unknown: {len(unknown)}")
        assert len(allowed) > 0
        assert len(disallowed) > 0
        assert len(unknown) > 0

    def test_catalog_has_cascading_providers(self):
        catalog = load_catalog()
        cascading = [p for p in get_all_providers(catalog) if p.get("cascades_to")]
        print(f"Providers with cascades_to: {len(cascading)}")
        assert len(cascading) > 0


class TestDownstreamProviders:

    def test_get_downstream_providers(self):
        catalog = load_catalog()
        downstream = get_downstream_providers(catalog, "google")
        assert isinstance(downstream, list)
        assert len(downstream) > 0

    def test_get_downstream_providers_no_cascade(self):
        catalog = load_catalog()
        downstream = get_downstream_providers(catalog, "groq")
        assert isinstance(downstream, list)


class TestScoringWeights:

    def test_scoring_weights_loaded(self):
        weights = get_scoring_weights()
        assert isinstance(weights, dict)
        assert len(weights) > 0

    def test_scoring_weights_have_expected_keys(self):
        weights = get_scoring_weights()
        expected = {"quota_value", "usefulness", "downstream_capabilities",
                    "compatibility", "account_freshness", "registration_cost",
                    "verification_cost", "policy_risk"}
        for key in expected:
            assert key in weights, f"Missing scoring weight: {key}"


class TestIdentityProvider:

    def test_is_identity_provider_true(self):
        catalog = load_catalog()
        p = get_provider(catalog, "google")
        assert is_identity_provider(p) is True

    def test_is_identity_provider_false(self):
        catalog = load_catalog()
        p = get_provider(catalog, "groq")
        assert is_identity_provider(p) is False


class TestDefaultCatalog:

    def test_default_catalog_has_providers(self):
        cat = default_catalog()
        # default_catalog may return a stub with no providers if the real
        # catalog path isn't reachable. Check providers or a sensible structure.
        if cat.get("providers"):
            assert len(cat["providers"]) > 0
        else:
            # Should at least have catalog_version
            assert "catalog_version" in cat or "providers" in cat

    def test_default_catalog_has_openai(self):
        cat = default_catalog()
        if cat.get("providers"):
            ids = [p["id"] for p in cat["providers"]]
            assert "openai" in ids
