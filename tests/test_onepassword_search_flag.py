"""
test_onepassword_search_flag.py — regression tests for the live-run defect.

The bug (found during the first live read-only run, invisible to every
fixture-based test):

  `search_items()` invoked `op item list --search <query>`, but the 1Password
  CLI has no `--search` flag (verified against op 2.38.1). Every call failed
  with "unknown flag: --search"; `_run_op` returned {"error": ...}; and
  `search_items` mapped that to `[]`. Result: 1Password silently appeared to
  contain zero items, and `reconcile_from_sources()` — which wraps discovery
  in `except Exception: pass` — reported a clean reconciliation built on a
  totally failed read.

These tests pin both halves of the fix:
  1. the invalid flag is never passed, and filtering happens client-side
  2. a failed read is distinguishable from a genuinely empty result
"""

import sys
from pathlib import Path

import pytest

SKILL_ROOT = Path(__file__).parent.parent
if str(SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT))

import adapters.onepassword as op


ITEMS = [
    {"id": "i1", "title": "Groq Api Key", "category": "API_CREDENTIAL",
     "vault": {"name": "Personal"}, "tags": ["provider"]},
    {"id": "i2", "title": "Groq Login", "category": "LOGIN",
     "vault": {"name": "Personal"}},
    {"id": "i3", "title": "Passaporto", "category": "DOCUMENT",
     "vault": {"name": "Andrea to share with family"}},
    {"id": "i4", "title": "OmniRoute api.cerebras.ai Api Key",
     "category": "API_CREDENTIAL", "vault": {"name": "Personal"}},
]


@pytest.fixture(autouse=True)
def _reset_error():
    op._clear_last_error()
    yield
    op._clear_last_error()


@pytest.fixture
def captured(monkeypatch):
    """Capture the argv handed to op, returning a canned item list."""
    calls = []

    def fake(args, timeout=15):
        calls.append(list(args))
        return ITEMS

    monkeypatch.setattr(op, "_run_op", fake)
    return calls


# ── The flag bug ────────────────────────────────────────────────────────────

class TestNoSearchFlag:

    def test_search_flag_never_passed(self, captured):
        op.search_items("api key")
        assert captured, "op was not invoked"
        for argv in captured:
            assert "--search" not in argv, \
                "op item list has no --search flag; filter client-side"

    def test_invocation_is_plain_item_list(self, captured):
        op.search_items("api key")
        assert captured[0][:2] == ["item", "list"]

    def test_invocation_requests_json_format(self, captured):
        op.search_items("api key")
        assert captured[0][:5] == ["item", "list", "--format", "json"]

    def test_real_cli_emits_json_with_format_flag(self):
        """Documents that --format json is what makes op return parseable data."""
        import shutil
        import subprocess
        if not shutil.which("op"):
            pytest.skip("op CLI not installed")
        try:
            r = subprocess.run(["op", "item", "list", "--format", "json"],
                               capture_output=True, text=True, timeout=20)
        except subprocess.TimeoutExpired:
            pytest.skip("op desktop approval required (headless) — cannot verify live")
        if r.returncode != 0:
            pytest.skip(f"op not available here: {r.stderr[:80]}")
        assert r.stdout.strip().startswith("["), \
            "op item list --format json must emit a JSON array"

    def test_only_supported_flags_used(self, captured):
        op.search_items("api key", vault="Personal", tags=["provider"])
        argv = captured[0]
        supported = {"--vault", "--tag", "--tags", "--categories",
                     "--favorite", "--long", "--include-archive", "--format"}
        for tok in argv:
            if tok.startswith("--"):
                assert tok in supported, f"unsupported op flag: {tok}"

    def test_vault_and_tags_still_forwarded(self, captured):
        op.search_items("x", vault="Personal", tags=["provider", "ai"])
        argv = captured[0]
        assert "--vault" in argv and "Personal" in argv
        assert argv.count("--tag") == 2

    def test_real_cli_rejects_search_flag(self):
        """Documents the actual CLI contract (skips when op is absent)."""
        import shutil
        import subprocess
        if not shutil.which("op"):
            pytest.skip("op CLI not installed")
        r = subprocess.run(["op", "item", "list", "--help"],
                           capture_output=True, text=True, timeout=20)
        help_text = (r.stdout or "") + (r.stderr or "")
        if not help_text.strip():
            pytest.skip("could not read op help")
        assert "--search" not in help_text, \
            "op grew a --search flag; revisit the client-side filter"


# ── Client-side filtering ───────────────────────────────────────────────────

class TestClientSideFilter:

    def test_query_filters_by_title(self, captured):
        got = op.search_items("Groq Api Key")
        assert [i["id"] for i in got] == ["i1"]

    def test_query_is_case_insensitive(self, captured):
        assert [i["id"] for i in op.search_items("groq api key")] == ["i1"]

    def test_token_match_across_metadata(self, captured):
        # "api key" matches both API-credential titles by token.
        ids = {i["id"] for i in op.search_items("api key")}
        assert {"i1", "i4"} <= ids
        assert "i3" not in ids

    def test_no_query_returns_everything(self, captured):
        assert len(op.search_items()) == len(ITEMS)

    def test_nonmatching_query_returns_empty(self, captured):
        assert op.search_items("nonexistent-provider-xyz") == []

    def test_empty_result_is_not_an_error(self, captured):
        op.search_items("nonexistent-provider-xyz")
        assert op.last_error() is None, \
            "an empty match must not look like a failed read"

    def test_matches_tags(self, captured):
        assert any(i["id"] == "i1" for i in op.search_items("provider"))

    def test_malformed_items_do_not_crash(self, monkeypatch):
        monkeypatch.setattr(op, "_run_op",
                            lambda a, timeout=15: [None, "junk", {}, {"title": None}])
        assert op.search_items("anything") == []


# ── Failure is distinguishable from empty ───────────────────────────────────

class TestErrorVisibility:

    def test_cli_error_recorded(self, monkeypatch):
        monkeypatch.setattr(op, "_run_op",
                            lambda a, timeout=15: {"error": "unknown flag: --search"})
        assert op.search_items("api key") == []
        assert op.last_error() is not None
        assert "unknown flag" in op.last_error()

    def test_error_distinguishes_failure_from_empty(self, monkeypatch):
        """The exact confusion that hid the bug must now be detectable."""
        monkeypatch.setattr(op, "_run_op",
                            lambda a, timeout=15: {"error": "not signed in"})
        failed = op.search_items("api key")
        failed_err = op.last_error()

        monkeypatch.setattr(op, "_run_op", lambda a, timeout=15: [])
        empty = op.search_items("api key")
        empty_err = op.last_error()

        assert failed == empty == []          # identical return values...
        assert failed_err is not None         # ...but distinguishable state
        assert empty_err is None

    def test_success_clears_previous_error(self, monkeypatch):
        monkeypatch.setattr(op, "_run_op",
                            lambda a, timeout=15: {"error": "boom"})
        op.search_items("x")
        assert op.last_error() is not None
        monkeypatch.setattr(op, "_run_op", lambda a, timeout=15: ITEMS)
        op.search_items("x")
        assert op.last_error() is None

    def test_timeout_recorded(self, monkeypatch):
        monkeypatch.setattr(op, "_run_op",
                            lambda a, timeout=15: {"error": "op command timed out"})
        op.search_items("x")
        assert "timed out" in op.last_error()

    def test_non_json_output_recorded(self, monkeypatch):
        monkeypatch.setattr(op, "_run_op", lambda a, timeout=15: "some banner text")
        assert op.search_items("x") == []
        assert op.last_error() is not None

    def test_none_output_is_success(self, monkeypatch):
        monkeypatch.setattr(op, "_run_op", lambda a, timeout=15: None)
        assert op.search_items("x") == []
        assert op.last_error() is None


# ── read_available() probe ──────────────────────────────────────────────────

class TestReadAvailable:

    def test_error_means_unavailable(self, monkeypatch):
        monkeypatch.setattr(op, "_run_op",
                            lambda a, timeout=15: {"error": "not signed in"})
        ok, detail = op.read_available()
        assert ok is False and "not signed in" in detail

    def test_items_means_available(self, monkeypatch):
        monkeypatch.setattr(op, "_run_op", lambda a, timeout=15: ITEMS)
        ok, detail = op.read_available()
        assert ok is True and "4 item" in detail

    def test_empty_is_available_but_flagged(self, monkeypatch):
        """Zero items is a real answer, but worth surfacing to the operator."""
        monkeypatch.setattr(op, "_run_op", lambda a, timeout=15: [])
        ok, detail = op.read_available()
        assert ok is True
        assert "zero items" in detail

    def test_no_secrets_in_returned_metadata(self, captured):
        for item in op.search_items():
            for k in item:
                assert str(k).lower() not in (
                    "password", "credential", "api_key", "token", "secret")
