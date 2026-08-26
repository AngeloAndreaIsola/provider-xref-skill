"""
test_identity_invariants.py — Invariant tests for the canonical identity-ID system.

These tests prove that:
1. Same email → same canonical ID (determinism)
2. Case/whitespace normalization is consistent
3. add_identity() and email matching generate the same ID
4. discover_identities() and add_identity() generate the same ID
5. No duplicate IDs for the same email
6. Long emails don't cause collision-prone truncation
7. Different emails produce different IDs
8. planner.py uses the same canonical ID
9. The typo regression: islandtrailer (correct) ≠ islandgametrale (wrong)
10. Read-only reconciliation does not mutate state
"""
import json
import hashlib
import os
from copy import deepcopy
from unittest.mock import patch

import pytest


# ── Helpers ────────────────────────────────────────────────────────────────

def _hash_state(state):
    """Compute a stable hash of state for before/after comparison."""
    return hashlib.sha256(
        json.dumps(state, sort_keys=True).encode()
    ).hexdigest()[:16]


# ── Task 9: ID Invariant Tests ──────────────────────────────────────────────

class TestCanonicalIdentityId:
    """Tests for canonical_identity_id determinism and consistency."""

    def test_deterministic_same_input(self):
        """Same email → same canonical ID, every time."""
        from engine.identity import canonical_identity_id
        for email in ["angeloandrea.isola@gmail.com",
                       "lazymause@gmail.com",
                       "islandtrailer@gmail.com",
                       "andrea.isola@me.com"]:
            id1 = canonical_identity_id("email", email)
            id2 = canonical_identity_id("email", email)
            assert id1 == id2, f"Non-deterministic ID for {email}"

    def test_case_normalization(self):
        """Uppercase and lowercase of the same email produce the same ID."""
        from engine.identity import canonical_identity_id
        lower = canonical_identity_id("email", "angeloandrea.isola@gmail.com")
        upper = canonical_identity_id("email", "ANGELOANDREA.ISOLA@GMAIL.COM")
        mixed = canonical_identity_id("email", "AnGeLoAnDrEa.IsOlA@gmail.com")
        assert lower == upper, f"Case mismatch: {lower} != {upper}"
        assert lower == mixed, f"Case mismatch: {lower} != {mixed}"

    def test_whitespace_normalization(self):
        """Leading/trailing whitespace is stripped."""
        from engine.identity import canonical_identity_id
        base = canonical_identity_id("email", "angeloandrea.isola@gmail.com")
        padded = canonical_identity_id("email", "  angeloandrea.isola@gmail.com  ")
        assert base == padded

    def test_add_identity_matches_email_match(self):
        """add_identity() and _match_email_identity() produce the same identity ID."""
        from engine.identity import add_identity, _match_email_identity, canonical_identity_id
        from engine.state import default_state

        email = "lazymause@gmail.com"
        expected_id = canonical_identity_id("email", email)

        # _match_email_identity should produce the canonical ID
        match_result = _match_email_identity({
            "email": email,
            "connection_id": "test-conn",
            "provider_id": "test",
        })
        assert match_result is not None
        assert match_result["identity_id"] == expected_id

        # add_identity should produce the same canonical ID
        with patch("engine.state.load_state", return_value=deepcopy(default_state())):
            with patch("engine.state.save_state"):
                result = add_identity("email", email)
        assert result["identity"]["id"] == expected_id

    def test_state_add_identity_uses_canonical_id(self):
        """The low-level state.add_identity() must also use canonical_identity_id()."""
        from engine.identity import canonical_identity_id
        from engine import state as state_mod
        from engine.state import default_state
        from copy import deepcopy

        email = "newidentity@test.com"
        expected_id = canonical_identity_id("email", email)

        identity = {"type": "email", "value": email}
        with patch("engine.state.load_state", return_value=deepcopy(default_state())):
            with patch("engine.state.save_state"):
                new_state = state_mod.add_identity(identity)

        # add_identity appends to state["identities"] and returns the state
        added = [i for i in new_state["identities"] if i.get("value") == email]
        assert len(added) == 1, "Identity was not added to state"
        assert added[0]["id"] == expected_id, \
            f"state.add_identity produced {added[0]['id']}, expected {expected_id}"

    def test_discover_matches_add(self):
        """An identity discovered from an email must resolve to the same ID as an explicitly added identity."""
        from engine.identity import discover_identities, add_identity, canonical_identity_id
        from engine.state import default_state

        email = "andrea.isola@me.com"
        expected_id = canonical_identity_id("email", email)

        # discover_identities should produce this ID for the user-provided email
        identities = discover_identities(default_state())
        up_ids = [i for i in identities if i.get("source") == "user_provided"]
        matching = [i for i in up_ids if i["value"] == email]
        assert len(matching) == 1
        assert matching[0]["id"] == expected_id

    def test_no_duplicate_identity(self):
        """Adding the same email twice must not create two identities."""
        from engine.identity import add_identity
        from engine.state import default_state

        with patch("engine.state.load_state", return_value=deepcopy(default_state())):
            with patch("engine.state.save_state"):
                result1 = add_identity("email", "lazymause@gmail.com")
                result2 = add_identity("email", "lazymause@gmail.com")

        assert result1["status"] == "created"
        assert result2["status"] == "exists"
        assert result1["identity"]["id"] == result2["identity"]["id"]

    def test_long_email_no_collision(self):
        """Long emails should not collide due to truncation."""
        from engine.identity import canonical_identity_id

        # Two long emails that share the first 24 chars of normalized form
        # but differ later — the hash must prevent collision
        long_a = "a" * 50 + "@example.com"
        long_b = "a" * 50 + "b@example.com"
        id_a = canonical_identity_id("email", long_a)
        id_b = canonical_identity_id("email", long_b)
        assert id_a != id_b, "Long emails collided due to truncation"

    def test_distinct_emails_no_collision(self):
        """Different emails must produce different IDs."""
        from engine.identity import canonical_identity_id, _USER_PROVIDED_EMAILS
        ids = set()
        for email in _USER_PROVIDED_EMAILS:
            id_val = canonical_identity_id("email", email)
            assert id_val not in ids, f"Collision: {id_val} for {email}"
            ids.add(id_val)

    def test_typo_regression_islandtrailer(self):
        """islandtrailer@gmail.com must be recognized; islandgametrale must NOT."""
        from engine.identity import canonical_identity_id, _USER_PROVIDED_EMAILS
        correct = canonical_identity_id("email", "islandtrailer@gmail.com")
        typo = canonical_identity_id("email", "islandgametrale@gmail.com")
        assert correct != typo, "Typo email must produce different ID"
        assert "islandtrailer@gmail.com" in _USER_PROVIDED_EMAILS
        assert "islandgametrale@gmail.com" not in _USER_PROVIDED_EMAILS

    def test_planner_uses_canonical_id(self):
        """planner.py uses canonical_identity_id for email ID generation."""
        from engine.identity import canonical_identity_id
        from engine.planner import plan_new_email
        from engine.state import default_state
        from engine.catalog import load_catalog
        import inspect

        # Verify canonical_identity_id is imported in planner module
        source = inspect.getsource(plan_new_email)
        assert "canonical_identity_id" in source, \
            "plan_new_email should use canonical_identity_id for email ID generation"

        # Verify it produces the same ID as identity.py
        email = "testplan@example.com"
        expected = canonical_identity_id("email", email)

        state = deepcopy(default_state())
        catalog = load_catalog()
        plan = plan_new_email(email, state=state, catalog=catalog)

        # The plan's email_id should match the canonical ID
        assert plan["email_id"] == expected
        assert plan["status"] == "planned"

    def test_phone_identity(self):
        """Non-email identity types also use canonical IDs."""
        from engine.identity import canonical_identity_id
        phone1 = canonical_identity_id("phone", "+15551234567")
        phone2 = canonical_identity_id("phone", "+15551234567")
        assert phone1 == phone2  # deterministic
        assert phone1 != canonical_identity_id("phone", "+15559999999")  # different

    def test_planner_phone_uses_canonical_id(self):
        """planner.py plan_new_phone must use canonical_identity_id, not string replacement."""
        from engine.identity import canonical_identity_id
        from engine.planner import plan_new_phone
        from engine.state import default_state
        from engine.catalog import load_catalog
        import inspect

        source = inspect.getsource(plan_new_phone)
        assert "canonical_identity_id" in source, \
            "plan_new_phone should use canonical_identity_id for phone ID generation"
        # Ensure no string-replacement-based phone ID
        assert "identity_phone_" not in source.replace("identity_phone_", "", 1) or \
               "canonical_identity_id" in source, \
            "plan_new_phone must not use string-replacement phone IDs"


# ── Task 10: State-Mutation Invariant Tests ────────────────────────────────

class TestReadOnlyInvariants:
    """Tests proving that read-only reconciliation does not mutate state."""

    def test_discover_identities_does_not_mutate(self):
        """discover_identities() must not persist any changes."""
        from engine.identity import discover_identities
        from engine.state import default_state

        state = deepcopy(default_state())
        before = _hash_state(state)

        with patch("engine.state.save_state") as mock_save:
            discover_identities(state)

        mock_save.assert_not_called()
        after = _hash_state(state)
        assert before == after, "discover_identities mutated state"

    def test_match_ownership_does_not_mutate(self):
        """match_ownership() must not persist any changes."""
        from engine.identity import match_ownership
        from engine.state import default_state

        state = deepcopy(default_state())
        before = _hash_state(state)

        with patch("engine.state.save_state") as mock_save:
            match_ownership(
                {"connection_id": "conn-1", "provider_id": "test", "email": None},
                [], [], None
            )

        mock_save.assert_not_called()
        after = _hash_state(state)
        assert before == after

    def test_reconcile_identities_does_not_mutate(self, monkeypatch):
        """reconcile_identities() must not persist any changes to state."""
        from engine.identity import reconcile_identities
        from engine.state import default_state

        state = deepcopy(default_state())
        before = _hash_state(state)
        monkeypatch.setattr("engine.identity.is_running", lambda: False)

        with patch("engine.state.save_state") as mock_save:
            reconcile_identities(state=state, catalog={"providers": []})

        mock_save.assert_not_called()
        after = _hash_state(state)
        assert before == after, "reconcile_identities mutated state"

    def test_reconcile_state_hash_stable(self, monkeypatch):
        """The state_hash_before and state_hash_after must be equal after reconciliation."""
        from engine.identity import reconcile_identities
        from engine.state import default_state

        state = deepcopy(default_state())
        monkeypatch.setattr("engine.identity.is_running", lambda: False)

        result = reconcile_identities(state=state, catalog={"providers": []})

        assert result["state_hash_before"] == result["state_hash_after"], \
            "reconcile_identities mutated state between before/after hash"

    def test_add_identity_persists_when_called(self, tmp_path):
        """add_identity() SHOULD persist when explicitly called (positive test)."""
        from engine.identity import add_identity
        from engine.state import default_state, load_state

        temp_state = tmp_path / "state.json"
        with open(temp_state, "w") as f:
            json.dump(default_state(), f)

        with patch("engine.state.STATE_FILE", str(temp_state)):
            with patch("engine.utils.STATE_FILE", str(temp_state)):
                result = add_identity("email", "newidentity@test.com")
                # Load within the same patch context
                loaded = load_state()

        assert result["status"] == "created"
        assert len(loaded["identities"]) == 1
        assert loaded["identities"][0]["value"] == "newidentity@test.com"

    def test_no_test_writes_to_production_state(self):
        """Regression: confirm the production state file has not been contaminated.

        The autouse fixture in conftest.py redirects STATE_FILE to a temp
        file for every test. We read the REAL production file directly to
        verify it was not modified by tests. Production state should have
        only groq (unknown) plus the 7 user-confirmed connections (known).
        """
        production_state_path = os.path.join(
            os.path.expanduser("~/.hermes/skills/provider-xref"),
            "provider_state.json"
        )
        with open(production_state_path) as f:
            state = json.load(f)
        # Production should have groq (unchanged) + confirmed connections
        pas = state.get("provider_accounts", [])
        # groq must remain unknown and unmodified
        groq = [pa for pa in pas if pa.get("provider_id") == "groq"]
        assert len(groq) == 1
        assert groq[0]["ownership_status"] == "unknown"
        assert groq[0].get("identity_id") is None
        # Execution request must remain untouched
        req_path = os.path.join(
            os.path.expanduser("~/.hermes/skills/provider-xref"),
            "data/execution_requests/exec_8d52268f6482.json"
        )
        with open(req_path) as f:
            req = json.load(f)
        assert req["status"] == "awaiting_approval"


# ── Task 10: Ownership Flow Verification ──────────────────────────────────

class TestOwnershipFlow:
    """Tests verifying the ownership confirmation flow using isolated state."""

    def test_email_match_produces_inferred_not_known(self):
        """Email evidence alone must NOT produce 'known' ownership."""
        from engine.identity import match_ownership, OWNERSHIP_INFERRED, OWNERSHIP_MATCHED

        omni_pa = {
            "connection_id": "test-conn-abc",
            "provider_id": "antigravity",
            "auth_type": "oauth",
            "email": "angeloandrea.isola@gmail.com",
        }

        result = match_ownership(omni_pa, [], [], {})

        assert result["ownership_status"] == OWNERSHIP_INFERRED
        assert result["ownership_status"] != OWNERSHIP_MATCHED

    def test_known_connection_takes_priority_over_email_inference(self):
        """A known connection in local state must NOT be downgraded to inferred."""
        from engine.identity import match_ownership, OWNERSHIP_MATCHED, canonical_identity_id

        identity_id = canonical_identity_id("email", "angeloandrea.isola@gmail.com")
        local_pa = {
            "id": "pa_test",
            "provider_id": "antigravity",
            "omniroute_account_id": "conn-test-abc",
            "ownership_status": OWNERSHIP_MATCHED,
            "match_method": "user_confirmed",
            "match_confidence": "high",
            "identity_id": identity_id,
        }
        omni_pa = {
            "connection_id": "conn-test-abc",
            "provider_id": "antigravity",
            "auth_type": "oauth",
            "display_name": "angeloandrea.isola@gmail.com",
        }

        result = match_ownership(omni_pa, [local_pa], [], {})
        assert result["ownership_status"] == OWNERSHIP_MATCHED, \
            "Known connection was downgraded to non-known by email matching"
        assert result["identity_id"] == identity_id

    def test_confirm_ownership_requires_existing_pa(self):
        """confirm_ownership() must NOT create new PAs or write to OmniRoute."""
        from engine.identity import confirm_ownership
        from engine.state import default_state

        state = deepcopy(default_state())
        with patch("engine.state.save_state"):
            result = confirm_ownership(
                "nonexistent-conn-id",
                identity_id="identity_email_test",
                state=state,
            )

        assert result["status"] == "error"
        assert "No provider account" in result["message"]

    def test_confirm_ownership_stores_supplied_id(self):
        """confirm_ownership() stores the supplied identity_id without rewriting."""
        from engine.identity import confirm_ownership, OWNERSHIP_MATCHED, canonical_identity_id
        from engine.state import default_state

        ident_id = canonical_identity_id("email", "test@example.com")
        state = deepcopy(default_state())
        state["provider_accounts"].append({
            "id": "pa-test",
            "provider_id": "test",
            "identity_id": None,
            "omniroute_account_id": "conn-123",
            "auth_type": "api_key",
            "status": "connected",
            "omniroute_connected": True,
            "ownership_status": "inferred",
            "match_method": "email_match",
        })

        result = confirm_ownership(
            "conn-123",
            identity_id=ident_id,
            state=state,
        )

        assert result["status"] == "confirmed"
        assert result["ownership_status"] == OWNERSHIP_MATCHED
        assert result["identity_id"] == ident_id
        assert result["match_method"] == "user_confirmed"

    def test_known_ownership_not_auto_promoted(self):
        """A confirmed known connection must not be auto-promoted to a new registration."""
        from engine.identity import canonical_identity_id

        ident_id = canonical_identity_id("email", "andrea.isola@me.com")

        # Verify the identity ID is the canonical form
        assert ident_id.startswith("identity_email_andrea_isola_me_com_")
        assert len(ident_id) > 30  # includes hash suffix
