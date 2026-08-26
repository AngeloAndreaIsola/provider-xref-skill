"""
provider-xref engine package.

Core modules:
- state: load/save/validate provider_state.json with atomic writes
|- catalog: load/validate provider_catalog.json
|- graph: identity/provider relationship graph traversal
|- audit: produce a structured audit report
|- planner: opportunity detection, scoring, and ranking
|- policy: policy classification and enforcement
|- registration: registration state machine + ledger
|- identity: identity discovery, ownership matching, review queue
|- utils: shared helpers (ID generation, atomic save, date helpers)
"""
