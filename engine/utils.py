"""
utils.py — Shared helpers for the provider-xref engine.

Provides:
- SKILL_ROOT: absolute path to the skill directory
- load_json / save_json_atomic: JSON read/write with atomic save
- uuid_id: generate unique IDs
- now_iso: ISO 8601 timestamp
- validate_json_schema: validate a JSON object against a schema file
"""

from __future__ import annotations

import json
import os
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── Paths ─────────────────────────────────────────────────────────────

SKILL_ROOT: Path = Path(os.path.expanduser("~/.hermes/skills/provider-xref"))

STATE_FILE: Path = SKILL_ROOT / "provider_state.json"
CATALOG_FILE: Path = SKILL_ROOT / "provider_catalog.json"
HISTORY_FILE: Path = SKILL_ROOT / "data" / "registration_history.json"
SCHEMA_DIR: Path = SKILL_ROOT / "schemas"


def ensure_skill_dirs() -> None:
    """Ensure all required skill directories exist."""
    for d in [SKILL_ROOT / "data", SKILL_ROOT / "engine", SKILL_ROOT / "adapters",
              SKILL_ROOT / "workflows", SKILL_ROOT / "schemas", SKILL_ROOT / "tests"]:
        d.mkdir(parents=True, exist_ok=True)


# ── JSON I/O ────────────────────────────────────────────────────────────

def load_json(path: str | Path, default: Any = None) -> Any:
    """Load a JSON file. Returns *default* if the file doesn't exist."""
    p = Path(path)
    if not p.exists():
        return default
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json_atomic(path: str | Path, data: Any) -> None:
    """
    Atomically save JSON to *path*.

    Writes to a temporary file first, then renames into place.
    This ensures that an incomplete write never corrupts the
    existing state file.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)

    # Serialize with consistent formatting
    content = json.dumps(data, indent=2, sort_keys=False, ensure_ascii=False)
    content += "\n"

    # Write to temp file in the same directory (so rename is atomic)
    fd, tmp_path = tempfile.mkstemp(dir=str(p.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, str(p))
    except Exception:
        # Clean up temp file on failure
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


# ── IDs and timestamps ─────────────────────────────────────────────────

def uuid_id(prefix: str = "id") -> str:
    """Generate a unique ID with an optional prefix."""
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def now_iso() -> str:
    """Return the current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Schema validation ──────────────────────────────────────────────────

def validate_json_schema(data: dict, schema_file: str) -> tuple[bool, str]:
    """
    Validate *data* against a JSON schema file.

    Returns (True, "") on success, (False, error_message) on failure.
    Falls back gracefully if jsonschema is not installed.
    """
    try:
        import jsonschema
    except ImportError:
        # Without jsonschema, just do a basic type check
        if not isinstance(data, dict):
            return False, f"Expected dict, got {type(data).__name__}"
        return True, ""

    schema_path = SCHEMA_DIR / schema_file
    if not schema_path.exists():
        return False, f"Schema file not found: {schema_path}"

    schema = load_json(schema_path)
    try:
        jsonschema.validate(instance=data, schema=schema)
        return True, ""
    except jsonschema.ValidationError as e:
        return False, str(e)
    except jsonschema.SchemaError as e:
        return False, f"Schema error: {e}"


# ── Atomic state update helper ──────────────────────────────────────────

def atomic_state_update(modify_fn) -> dict:
    """
    Load state, apply modify_fn(state) -> state (or None to skip),
    validate, and atomically save.

    Usage:
        def add_identity(state):
            state["identities"].append({...})
            return state

        new_state = atomic_state_update(add_identity)
    """
    from . import state as state_mod
    state = state_mod.load_state()
    result = modify_fn(state)
    if result is not None:
        state = result
    state_mod.save_state(state)
    return state
