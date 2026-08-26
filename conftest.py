"""
conftest.py — pytest configuration and path setup.

Ensures all modules can be imported whether the skill is loaded as
a package (sys.path includes ~/.hermes/skills) or as a standalone
directory (sys.path includes the skill root).
"""
import sys
import os
from pathlib import Path

# Always add the skill root to sys.path so absolute imports work
# (from engine.x import ..., from adapters.x import ..., etc.)
SKILL_ROOT = str(Path(__file__).parent.resolve())
if SKILL_ROOT not in sys.path:
    sys.path.insert(0, SKILL_ROOT)

# Also add the parent so the package can be imported by directory name
SKILLS_PARENT = str(Path(__file__).parent.parent.resolve())
if SKILLS_PARENT not in sys.path:
    sys.path.insert(0, SKILLS_PARENT)


# ── Import compatibility shim ─────────────────────────────────────────────
# When loaded as a standalone package (sys.path = skill root),
# relative imports like `from ..engine.state import ...` fail because
# there is no parent package.  We patch them at import time.

def _patch_relative_imports():
    """Patch modules that use relative imports beyond top-level."""
    import importlib

    # The workflows and sync.py use `from ..engine` and `from ..adapters`
    # which only work when the skill is loaded as a proper package.
    # When loaded standalone, we convert these to absolute imports.

    # This is handled by the try/except pattern already in sync.py
    # For workflows, we'll use a helper function
    pass

_patch_relative_imports()
