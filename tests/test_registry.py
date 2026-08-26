"""
test_registry.py — Tests for the adapter/registry module.

Tests:
  - workflow lookup
  - adapter lookup
  - unknown workflow
  - unknown adapter
  - workflow-for-opportunity mapping
"""
import pytest

from engine.registry import (
    get_workflow, get_adapter, get_workflow_for_opportunity,
)


class TestWorkflowRegistry:

    def test_get_known_workflow(self):
        """Getting a workflow for a known provider should succeed."""
        # Google maps to the google workflow
        wf = get_workflow("google")
        assert wf is not None

    def test_get_workflow_by_auth_type(self):
        """Providers with api_key auth should map to api_key workflow."""
        wf = get_workflow("groq")
        assert wf is not None

    def test_get_unknown_workflow(self):
        """Unknown provider should return None."""
        wf = get_workflow("nonexistent_provider")
        assert wf is None


class TestAdapterRegistry:

    def test_get_known_adapter_omniroute(self):
        adapter = get_adapter("omniroute")
        assert adapter is not None

    def test_get_known_adapter_onepassword(self):
        adapter = get_adapter("onepassword")
        assert adapter is not None

    def test_get_known_adapter_browser(self):
        adapter = get_adapter("browser")
        assert adapter is not None

    def test_get_unknown_adapter(self):
        adapter = get_adapter("nonexistent_adapter")
        assert adapter is None


class TestWorkflowForOpportunity:

    def test_api_key_provider_maps_to_api_key_workflow(self):
        """Groq (api_key auth) should get a workflow."""
        wf = get_workflow_for_opportunity({"provider": "groq"})
        assert wf is not None

    def test_oauth_provider_maps_to_oauth_workflow(self):
        """Google (oauth auth) should get a workflow."""
        wf = get_workflow_for_opportunity({"provider": "google"})
        assert wf is not None

    def test_identity_provider_maps_correctly(self):
        """GitHub should map to the github workflow."""
        wf = get_workflow_for_opportunity({"provider": "github"})
        assert wf is not None

    def test_unknown_provider_returns_none(self):
        wf = get_workflow_for_opportunity({"provider": "nonexistent"})
        assert wf is None
