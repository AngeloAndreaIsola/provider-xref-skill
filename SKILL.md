---
name: provider-xref
description: Cross-reference OmniRoute providers with 1Password accounts — deterministic state, graph, and planning layer for provider identity management.
tags: [omniroute, accounts, 1password, automation, provider-management, state-graph]
category: productivity
---

# Provider-Xref

Provider-xref is a deterministic provider-state, identity, capability, policy, reconciliation, and planning layer for Hermes Agent.

Hermes is the natural-language orchestrator/UI. Provider-xref is the deterministic engine. Adapters are the only layer that communicates with external systems (OmniRoute, 1Password, Browser MCP).

## 1. Purpose

Provider-xref provides a deterministic bridge between:

1. **Local state** (`provider_state.json`) — identities, external accounts, provider accounts, credentials, and capabilities.
2. **OmniRoute** (`http://localhost:20128`) — live provider connections via the OmniRoute gateway.
3. **1Password** (`op` CLI) — credential metadata (metadata only, no secrets).

Provider-xref is NOT itself the autonomous account-registration authority. It produces deterministic state, plans, and recommendations that Hermes presents to the user for explicit approval.

## 2. Architecture

```
Hermes (natural-language UI / orchestrator)
   │
   ▼
provider-xref (skill root)
   │
   ├── StateManager
   │     ├── load_state()    → provider_state.json
   │     ├── save_state()     → atomic write (tempfile + os.replace)
   │     ├── validate_state() → JSON schema validation
   │     └── uuid_id() / now_iso()
   │
   ├── Catalog
   │     ├── load_catalog()  → provider_catalog.json (78 providers)
   │     ├── get_provider(catalog, id)
   │     ├── get_all_providers(catalog)
   │     ├── search_providers(query)
   │     ├── is_identity_provider(provider)
   │     ├── is_api_key_provider(provider)
   │     ├── get_downstream_providers(catalog, provider_id)
   │     ├── get_scoring_weights(catalog)
   │     └── default_catalog()  → minimal empty fallback (NOT fixture data)
   │
   ├── ProviderGraph
   │     ├── __init__(state, catalog)
   │     ├── find_identities()       → all available identities
   │     ├── find_unused_identities() → identities not linked to any account
   │     ├── find_provider_accounts() → all provider accounts
   │     ├── find_capabilities()     → all capabilities
   │     ├── find_paths(start_id, end_type) → capability cascade path
   │     └── _get_node(node_id)      → look up any node by ID
   │
   ├── PolicyEngine
   │     ├── get_policy(catalog, provider_id) → policy dict
   │     ├── can_automate_registration(catalog, provider_id) → (bool, reason)
   │     ├── is_provider_allowed(provider) → ALLOW / DENY / REQUIRES_REVIEW / UNKNOWN
   │     └── get_opportunity_policy_status(catalog, provider_id) → policy enum
   │
   ├── Auditor
   │     ├── audit() → full cross-system audit dict (read-only)
   │     ├── audit_text() → human-readable markdown report
   │     ├── reconcile_real_state() → structured reconciliation with
   │     │   catalog_coverage, policy_distribution, opportunities
   │     └── ownership classification (matched / unknown / requires_review / inferred)
   │
   ├── Planner
   │     ├── find_opportunities(state, catalog) → ranked list of opportunities
   │     ├── make_opportunity(provider_id, catalog, state, graph) → opportunity dict
   │     ├── plan_new_phone(phone_number, state, catalog) → capability cascade
   │     ├── plan_new_email(email, state, catalog) → capability cascade
   │     ├── plan_new_google_account(state, catalog) → capability cascade
   │     ├── plan_new_github_account(state, catalog) → capability cascade
   │     ├── plan_registration(provider_id, identity, ...) → registration plan
   │     └── save_plan(plan) → writes to data/plans/ (temp dir in tests)
   │
   ├── RegistrationStateMachine
   │     ├── RegistrationStateMachine(provider_id, ...)
   │     ├── transition_to(state) → validates transition, updates ledger
   │     ├── record_success(result) → finalizes registration
   │     └── record_failure(error)  → logs failure, supports retry
   │
   ├── RegistrationLedger
   │     ├── record_attempt(provider_id, workflow) → entry ID
   │     ├── record_partial(entry_id, steps, status) → update entry
   │     ├── record_success(entry_id, result) → finalize entry
   │     ├── check_phone_usage(phone_number) → entry or None
   │     ├── resume_most_recent(provider_id) → entry or None
   │     └── load_history() / save_history() → data/registration_history.json
   │
   ├── Sync
   │     ├── sync(state, catalog, dry_run=True) → change_summary
   │     ├── discover_omniroute_state() → OmniRoute connection data
   │     ├── _normalize_omniroute(discovery, catalog) → normalized list
   │     ├── _normalize_onepassword(items) → normalized list
   │     ├── _strip_sensitive_metadata() → removes secret-like keys
   │     └── _compare(state, graph, omni, op, catalog) → diff
   │
   ├── Adapters
   │     ├── OmniRoute  (adapters/omniroute.py)
   │     │     ├── _get_token() → env var OMNIR_TOKEN or ~/.omniroute/config.json
   │     │     ├── is_running() → ping /api/providers
   │     │     ├── get_connected_providers() → normalized list[dict] from /api/providers
   │     │     │   - strips prefixes, lowercases provider_id
   │     │     │   - maps auth_type (apikey → api_key)
   │     │     │   - _is_sensitive_key() filters secret-like fields
   │     │     └── discover_omniroute_state() → full discovery dict with
   │     │         uncatalogued, ownership_breakdown, observations
   │     ├── 1Password  (adapters/onepassword.py)
   │     │     ├── list_vaults() → dynamic vault discovery (no hardcoded vault names)
   │     │     ├── get_vault_by_name(name) → vault lookup
   │     │     ├── search_items() → metadata only (no secret retrieval)
   │     │     ├── get_item_metadata(item_id) → title, url, username
   │     │     └── _extract_safe_item_metadata() → strips passwords/keys/tokens
   │     └── Browser   (via MCP filesystem / playwright)
   │           ├── extract_provider_data(url) → provider metadata
   │           └── verify_provider(provider_id) → verification status
   │
   ├── Workflows
   │     ├── api_key.py  → API key registration (headless)
   │     ├── oauth.py    → OAuth flow via browser
   │     ├── google.py   → Google-specific OAuth
   │     └── github.py   → GitHub-specific OAuth
   │
   ├── Executor (engine/executor.py)
   │     ├── create_execution_request() → structured request (awaiting_approval)
   │     ├── preflight() → 6 deterministic checks (provider, policy, identity, duplicate, approval, plan_stability)
   │     ├── approve() → request-scoped approval with hard/soft block enforcement
   │     ├── execute() → validate → preflight → workflow → verify → record (supports dry_run)
   │     ├── cancel() → cancel a request
   │     ├── resume() → resume from human checkpoint
   │     ├── registration_status() → query request status
   │     └── list_execution_requests() → list all requests
   │     Enforces: DENY always blocks, UNKNOWN never auto-allows, approval is request-scoped,
   │     dry-run never mutates, planning never executes, no secrets serialized.
   │
   └── Schemas
         ├── provider_state.schema.json (includes ownership_status, source, match_method, match_confidence)
         ├── provider_catalog.schema.json
         ├── registration_plan.schema.json
         └── registration_result.schema.json (collection: {history_version, entries: [...]})
```

## 3. Identity/Capability Model

The model is **identity/capability based**, not simply:

```
email → provider
```

The graph conceptually represents a cascade:

```
Identity (email, phone, google, github)
  ↓
External Account (provider-specific account)
  ↓
Provider Account (OmniRoute connection)
  ↓
Credential (reference to 1Password item)
  ↓
Capability (access to downstream providers/services)
```

**Not every edge must exist.** An identity may exist without any provider accounts. A provider account may exist without an identity link (ownership_status = unknown). The graph only asserts relationships that have been observed or explicitly established.

Key distinction: **Provider existence ≠ identity requirement.** Some providers can be used without a persistent identity (e.g., API key providers), while others require email verification, phone verification, or OAuth identity creation.

## 4. Observation vs Ownership

**Observed OmniRoute connection ≠ confirmed user-owned account**

An OmniRoute connection record tells us that a credential exists in OmniRoute and is functional. It does NOT tell us which user identity owns that credential or whether the user has explicitly registered it.

Each OmniRoute connection is classified into one of four ownership states:

| State | Meaning | Evidence |
|---|---|---|
| **matched** | Ownership confirmed by local state | `identity_id` is set with high confidence; matched by OmniRoute UUID or provider_id with local record |
| **inferred** | Ownership plausibly inferred from strong evidence | Matched by provider_id with local ownership_status="inferred"; has supporting evidence (e.g., email domain match) |
| **requires_review** | 1Password evidence exists but no deterministic match | 1Password has a login item for this provider, but no local identity link; user must confirm |
| **unknown** | Connection observed but no ownership evidence | `identity_id = null`, `ownership_status = "unknown"` |

**A connection may have:**
- `ownership_status: "unknown"`
- `identity_id: null`
- `external_account_id: null`

This is **preferable** to inventing ownership from provider name matches.

### Ownership Semantics (Conservatism Rules)

1. **UUID match = highest confidence.** If the OmniRoute connection UUID matches a local `omniroute_account_id`, ownership is confirmed (`matched`).
2. **provider_id match = candidate, not proof.** Matching by provider_id identifies a candidate relationship but does NOT fabricate ownership if ambiguity exists.
3. **1Password metadata = evidence only.** A 1Password login for "google.com" is evidence that the user may have a Google account — it does NOT prove that a specific OmniRoute connection belongs to that identity.
4. **1Password evidence → `requires_review`**, never `matched` or `confirmed`.
5. **Provider names are never converted into identities.** "Google" in a provider name does not become a Google identity.
6. **Multiple accounts remain distinguishable.** Each OmniRoute connection UUID is tracked separately; even for multi-account providers, connections are not merged without explicit evidence.
7. **Reconciliation is deterministic.** Given identical inputs (provider_state, OmniRoute observation, 1Password metadata), the output is identical across repeated runs.

## 5. OmniRoute Reconciliation

Matching priority (highest to lowest confidence):

1. **OmniRoute connection UUID** — the connection's `id` field matched against local `omniroute_account_id`
   - `match_method: "omniroute_uuid"`
   - `match_confidence: high`
2. **provider_id** — the normalized provider ID matched against local `provider_id`
   - `match_method: "provider_id"`
   - `match_confidence: medium` (candidate only)
3. **1Password metadata** — 1Password login item title matched against provider name/ID
   - `match_method: "identity"` or `null`
   - `match_confidence: unknown` (evidence only, produces `requires_review`)

### Sensitive Field Filtering

When observing OmniRoute connections, sensitive fields are stripped:

- `apiKey` / `api_key` → `[REDACTED]`
- `accessToken` → `[REDACTED]`
- `refreshToken` → `[REDACTED]`
- `idToken` → `[REDACTED]`
- `password` → `[REDACTED]`
- `secret` → `[REDACTED]`
- `credential` → `[REDACTED]`

The `_is_sensitive_key()` function checks field names against these patterns. Fields matching are replaced with `[REDACTED]` in all observation metadata, audit output, and persisted state.

### Provider ID Normalization

`get_connected_providers()` normalizes provider IDs by:
- Stripping common prefixes (`google_`, `azure_`, `github_`, `openai_`, `anthropic_`, `groq_`, etc.)
- Lowercasing
- Replacing spaces/hyphens with underscores

Example: "Google Gmail" → `google_gmail`

## 6. 1Password Security

Provider-xref only uses **metadata** during reconciliation. The following are **NEVER** retrieved:

- Passwords
- API keys stored as secrets
- OAuth tokens (access, refresh, id)
- Recovery codes
- TOTP secrets
- Session cookies

Only safe metadata is extracted: `title`, `id`, `vault`, `category`, `tags`, `username/email` (if present).

Vault discovery is **dynamic** — `list_vaults()` queries `op vault list` at runtime. There is no hardcoded "Private" or "Work" vault assumption. If 1Password is not signed in, metadata discovery returns empty results gracefully.

`provider_state.json` stores credential references (`credential_ref` pointing to a 1Password item ID), never credential values.

## 7. Policy Model

Catalog providers are classified by policy status:

| Status | Meaning | Automation |
|---|---|---|
| `ALLOW` | Provider explicitly allows automation | May register after user approval |
| `REQUIRES_REVIEW` | Policy unclear or restricted | User must review before any action |
| `UNKNOWN` | Insufficient catalog data | Treated as REQUIRES_REVIEW; never auto-upgraded |
| `DENY` | Provider explicitly disallows automation | Never automatically registered |

The catalog uses `automation_allowed` field with values: `"allowed"`, `"disallowed"`, `"restricted"`, `"unknown"`.

**Critical invariant: UNKNOWN must NEVER become ALLOW automatically.**

New catalog entries (30 providers added during Phase 3) default to `automation_allowed: "unknown"`. This means:

- They will NOT be suggested for automated registration
- They require explicit user review before any action
- OmniRoute having a connection for a provider does NOT upgrade its policy from UNKNOWN to ALLOW

Additional policy rules:
- `free_tier` existence ≠ permission to create another account
- OAuth support ≠ permission to automate OAuth flow
- Provider presence in OmniRoute ≠ registration eligibility

## 8. Natural-Language Command Mapping

| User Says | Provider-xref Action | Mutates State? |
|---|---|---|
| "Audit my providers." | `reconcile_real_state()` + `audit_text()` | No (read-only) |
| "What's connected?" | OmniRoute observation via `get_connected_providers()` | No |
| "Who owns this account?" | Ownership classification (`_classify_ownership`) | No |
| "What providers am I missing?" | Catalog vs observed state comparison | No |
| "I got a new phone number." | `plan_new_phone()` → plan with `phone_classification` (new/existing/update) | No (plan only) |
| "I got a new email." | `plan_new_email()` → plan only | No (plan only, no registration) |
| "What's the highest-value account I can create?" | `find_opportunities()` + policy analysis | No (read-only) |
| "Create the account." | `plan_registration()` → approval-gated workflow | Only after explicit approval |
| "Who owns this connection?" | `match_ownership()` — deterministic ownership classification | No |
| "Confirm this is my account." | `confirm_ownership(connection_id, identity_id)` — requires explicit approval | Only with user confirmation |
| "Sync my provider state." | `discover → normalize → compare → report` | No (report only by default) |

**Mutation must never happen merely because a user asked for an audit or sync.** The default behavior is always read-only. State writes require an explicit, separate approval step.

## 9. OmniRoute Import Investigation

**Status: READ-ONLY investigation complete. No POST requests were sent.**

### What was investigated

1. **Routes manifest** (`/api/providers/import` route lookup):
   - Searched OmniRoute's Next.js `.next-cli-build/routes-manifest.json`
   - **OBSERVED: No `/api/providers/import` route exists in the routes manifest.**
   - General import endpoint: **NOT FOUND**

2. **`/api/providers` route** (source code inspection of `route.js`):
   - **GET handler**: Returns `{"connections": [...]}`, explicitly strips `apiKey`, `accessToken`, `refreshToken`, `idToken` from each connection
   - **POST handler**: Creates individual provider connections with body `{provider, auth: {type: "apiKey"/"oauth", apiKey, name, baseURL, ...}}`
   - **OBSERVED: POST supports individual connection creation, not bulk import**

3. **Provider-specific import routes**:
   - `/api/oauth/codex/bulk-import` (exists in routes)
   - `/api/oauth/cursor/import` (exists in routes)
   - These are **provider-specific**, not general CSV/JSON import endpoints

4. **Frontend source code**:
   - Searched Next.js static chunks for `import`, `FileReader`, `FormData`, `CSV`, `JSON.parse` patterns
   - Found "Bulk Add" button text in dashboard providers page (for codex provider specifically)
   - No generic CSV/JSON file upload component found in the providers pages

### Format Classification

| Aspect | Finding | Confidence |
|---|---|---|
| General import endpoint (`/api/providers/import`) | UNKNOWN — route does not exist in manifest | HIGH (verified via routes-manifest.json) |
| CSV format | UNKNOWN — no CSV parser found | LOW |
| JSON format | UNKNOWN — no general JSON import found | LOW |
| OAuth import capability | UNKNOWN — only provider-specific OAuth setup routes exist | MEDIUM |
| API-key import capability | UNKNOWN — POST creates individual connections, no bulk import | MEDIUM |
| Can supply account UUIDs | UNKNOWN — would require testing POST body | HIGH (cannot determine without POSTing) |
| Server-side credential writes | UNKNOWN — import endpoint not found | HIGH |
| Import performs server-side credential writes | UNKNOWN | HIGH |
| OAuth bulk import support | NOT CONFIRMED — no general OAuth bulk import found | MEDIUM |

**Conclusion: General OmniRoute CSV/JSON import format is UNKNOWN / NOT CONFIRMED.**

The investigation found no evidence of a general `/api/providers/import` endpoint that accepts CSV or JSON. The only import-like functionality consists of:
- Individual connection creation via `POST /api/providers` (one at a time, with inline credentials or OAuth)
- Provider-specific bulk routes (e.g., `codex/bulk-import`, `cursor/import`) — not general purpose

**No POST requests were sent to any endpoint.**

## 10. Current Catalog

- **78 providers** in `provider_catalog.json`
- 48 providers were in the original catalog
- **30 providers** were added during Phase 3 from real OmniRoute observations
- All 30 new entries default to conservative `automation_allowed: "unknown"` policy
- No provider was made `ALLOW` merely because it exists in OmniRoute
- All existing explicit `DENY` providers remain `DENY`
- All existing `ALLOW` providers remain unchanged
- `catalog_version` is the canonical version field (not `schema_version`)

## 11. Audit Safety

The audit/reconciliation process is **READ-ONLY** by design:

- **No registrations performed** — audit does not create accounts
- **No account creation** — no external side effects
- **No API key creation** — no credential generation
- **No OmniRoute imports** — no POST requests sent
- **No 1Password writes** — only metadata read
- **No secrets retrieved** — 1Password secret values never accessed
- **No secrets persisted** — sensitive fields stripped from all outputs

Production JSON file hashes are verified unchanged before and after audit execution.

## 12. Response Semantics

These terms describe the confidence level of each observation:

| Term | Meaning |
|---|---|
| **OBSERVED** | Directly verified from a reliable source (e.g., API response, route manifest) |
| **INFERRED** | Logically derived from observed evidence, but not directly verified |
| **UNKNOWN** | Cannot be determined without additional information or a state-changing request |
| **REQUIRES_REVIEW** | Evidence exists but is ambiguous; user decision required |
| **POSSIBLE** | May be true, but unconfirmed |
| **DENIED** | Explicitly disallowed by policy |

## 13. Limitations

- **OmniRoute connections may have unknown ownership.** The majority of connections (58 of 59 in the current real state) have `ownership_status: "unknown"` because no 1Password evidence was available to link them.
- **1Password metadata does not prove ownership.** A login item for "google.com" is evidence of a Google account but does not prove a specific OmniRoute connection belongs to it.
- **Catalog policy may remain UNKNOWN.** 44 of 78 catalog providers have `automation_allowed: "unknown"`. These require explicit user review before any registration attempt.
- **Provider existence does not imply registration eligibility.** OmniRoute may have a connection for a provider that is DENY in the catalog (e.g., `cursor`, `github`).
- **Import format is unconfirmed.** No general `/api/providers/import` endpoint was found in the OmniRoute route manifest.
- **Local state may initially contain fewer identities than real external systems.** The local `provider_state.json` starts sparsely initialized; reconciliation identifies gaps.

## 14. Phase 3 Audit Procedure

To run the Phase 3 read-only audit:

```bash
cd ~/.hermes/skills/provider-xref/

# 1. Run tests
python -m pytest -q

# 2. Check compilation
python -m compileall .

# 3. Validate schemas
python -c "
import json
from jsonschema import validate
# Validate each production JSON against its schema
"

# 4. Run real audit (read-only)
python -c "
from engine.audit import reconcile_real_state, audit_text
result = reconcile_real_state()
print(audit_text(result))
"

# 5. Verify no mutation (check file hashes before/after)
shasum provider_state.json provider_catalog.json data/registration_history.json
python -c "from engine.audit import reconcile_real_state; reconcile_real_state()"
shasum provider_state.json provider_catalog.json data/registration_history.json
```

## 15. Provider Catalog Policy Summary

| Policy | Count | Description |
|---|---|---|
| `ALLOW` | 7 | Explicitly allowed for automation after user approval |
| `REQUIRES_REVIEW` | 2 | Policy restricted or unclear; user must decide |
| `UNKNOWN` | 44 | Insufficient data; conservative default; never auto-upgraded |
| `DENY` | 6 | Explicitly disallowed; never automatically registered |

## 16. File Layout

| File | Role |
|---|---|
| `provider_state.json` | **Production state** — identities, external accounts, provider accounts, credentials, capabilities. Atomic writes via `save_json_atomic`. |
| `provider_catalog.json` | **Production catalog** — 78 providers with auth types, policies, free-tier info, cascades. |
| `data/registration_history.json` | **Production ledger** — registration attempt/completion records. |
| `data/plans/` | Plan output directory (ephemeral — plans are shown to user before execution). |
| `schemas/*.json` | JSON Schemas for each data file. |
| `tests/fixtures/` | **Test-only fixtures** — never used by production code. |
| `tests/conftest.py` | **Test-only** — patches `STATE_FILE`, `CATALOG_FILE`, `HISTORY_FILE` to `tmp_path`. |
| `engine/` | Core engine: state, catalog, graph, policy, audit, planner, registration, sync. |
| `adapters/` | External system adapters: OmniRoute, 1Password. |
| `workflows/` | Registration workflows: api_key, oauth, google, github. |
|| `tests/` | Test suite (331 tests). |
|| `tests/test_phase5.py` | Phase 5 execution engine tests (42 tests). |

### Production vs Test Isolation

- **Production** loads real files from `~/.hermes/skills/provider-xref/`.
- **Tests** patch `engine.state.STATE_FILE`, `engine.catalog.CATALOG_FILE`, and `engine.registration.HISTORY_FILE` to `tmp_path` directories.
- `default_catalog()` returns a minimal empty catalog (scoring weights only) — it is NOT fixture data and is only used as a fallback when the catalog file cannot be loaded.
- Tests cannot overwrite real `provider_state.json` — the `isolated_state` fixture patches the module-level `STATE_FILE` to a temp directory.
- Plan files are written to a temp directory in tests (via `patch("engine.planner._get_skill_path")`).

---

## Phase 4 Identity & Ownership Model

### Identity Graph

Provider-xref uses an **identity/capability-based model**, not a simple `email → provider` mapping:

```
Identity (email, phone, google, github)
  │
  ├── ExternalAccount (provider-specific account)
  │     │
  │     └── ProviderAccount (OmniRoute connection)
  │
  └── ProviderAccount (direct link, may skip ExternalAccount)

ProviderAccount ──provides──▶ Capability
ProviderAccount ──uses──▶ Credential (1Password reference)
```

**Key rule: Not every edge must exist.** An identity may exist with zero provider accounts. A provider account may exist with `identity_id = null` and `ownership_status = "unknown"`.

### Identity Types

The schema supports these identity types: `google`, `github`, `microsoft`, `email`, `phone`, `apple`, `other`.

Each identity has:
- `id`: Unique identifier (e.g., `identity_email_test1`)
- `type`: One of the supported types
- `value`: The actual identifier (email address, phone number, etc.)
- `source`: `user_declared`, `omniroute_sync`, `registration`, `1password_metadata`, `omniroute_metadata`
- `confidence`: `high` (user-declared), `low` (discovered)
- `status`: `active`, `suspended`, `consumed`, `available`, `retired`
- `verification`: `{email_verified, phone_verified, mfa_enabled}`
- `constraints`: e.g., `["phone_verification_required", "rate_limited"]`

### Identity Discovery

Identities are discovered from safe sources:
1. **Local state** (`provider_state.json`) — explicitly user-declared identities (confidence: high)
2. **1Password metadata** — login item usernames/emails (confidence: low, evidence only)
3. **OmniRoute metadata** — display names, email fields (confidence: low, evidence only)

**Never retrieved:** passwords, API keys, OAuth tokens, TOTP secrets, recovery codes.

### Ownership Matching

The `engine/identity.py` module provides deterministic ownership matching via `match_ownership()`:

**Matching priority (highest to lowest):**
1. **OmniRoute connection UUID** — `match_method: "connection_id"`, `confidence: high`
2. **Provider ID** — `match_method: "provider_id"`, `confidence: medium` (candidate only)
3. **1Password evidence** — `match_method: "1password_evidence"`, `confidence: medium` (evidence only)
4. **No match** — `match_method: null`, `confidence: "none"`

**Ownership statuses:**

| Status | Meaning |
|---|---|
| `matched` | Strong deterministic evidence (UUID match or explicit local link with identity_id) |
| `inferred` | Multiple non-authoritative signals strongly suggest ownership |
| `requires_review` | Evidence exists but is insufficient for automatic ownership (e.g., 1Password only) |
| `unknown` | No evidence; `identity_id = null`, `external_account_id = null` |

**Critical rules:**
- 1Password metadata → `requires_review`, NEVER `matched`
- Provider name alone → `unknown`, NEVER `matched`
- OmniRoute connection existence → `unknown`, NEVER `matched`
- Same inputs → same outputs (deterministic)

### Review Queue

`build_review_queue()` identifies connections where ownership cannot be safely determined:

```python
{
    "review_type": "provider_ownership",
    "provider_id": "claude",
    "connection_id": "...",
    "candidate_identities": [],
    "evidence": [{"source": "1password", "username": "user@example.com"}],
    "reason": "No authoritative ownership evidence"
}
```

Hermes can tell the user:
> "I found a Claude connection and a matching login in 1Password. This is supporting evidence but not sufficient for automatic ownership. Is this your account?"

### Explicit Ownership Confirmation

`confirm_ownership(connection_id, external_account_id, identity_id)` is the ONLY way to explicitly upgrade ownership:

- Required: explicit user confirmation
- Records: `match_method: "user_confirmed"`, `match_confidence: "high"`
- Records: `confirmed_at` timestamp
- Preserves: original observation metadata
- Does NOT retrieve credentials

After confirmation:
```python
{
    "ownership_status": "matched",
    "match_method": "user_confirmed",
    "match_confidence": "high",
    "identity_id": "identity_email_xxx",
    "confirmed_at": "2026-08-26T..."
}
```

### Phone Identity Planning

`plan_new_phone()` distinguishes three phone states:

| Classification | Condition |
|---|---|
| `new_phone_identity` | Phone not in local state |
| `existing_available_phone` | Phone exists, status = "available" |
| `update_existing_phone` | Phone exists, status = "consumed"/"retired" |

The planner:
1. Does NOT register any accounts
2. Does NOT replace existing phone identities
3. Checks if phone is already used by existing accounts
4. Produces a plan for Hermes to present
5. Marks manual verification requirements explicitly

### Identity Operations Available to Hermes

```python
# Add a user-declared identity (no registration)
from engine.identity import add_identity
result = add_identity("phone", "+15551234567")

# Match all OmniRoute connection ownerships
from engine.identity import match_all_ownerships
result = match_all_ownerships(omni_providers, local_pas, catalog=catalog)

# Build review queue for ambiguous connections
from engine.identity import build_review_queue
queue = build_release_queue(ownership_results)

# Explicitly confirm ownership (requires user approval)
from engine.identity import confirm_ownership
result = confirm_ownership("conn_1", identity_id="identity_test")

# Plan for a new phone number
from engine.planner import plan_new_phone
plan = plan_new_phone("+15551234567", state, catalog)
```


---

## Sync Pipeline

```
DISCOVER → NORMALIZE → COMPARE → REPORT
```

### Step 1: Discover

```
OmniRoute:  GET /api/providers → {"connections": [...]}
1Password:  op vault list + op item list → [{title, id, vault, ...}]  (metadata only)
```

Adapters are the ONLY layer that communicates with external systems.

### Step 2: Normalize

- `_normalize_omniroute()` maps OmniRoute connections to internal format
- `_strip_sensitive_metadata()` removes secret-like keys from metadata
- Provider IDs are normalized (prefixes stripped, lowercased)
- Auth types are normalized (`apikey` → `api_key`)

### Step 3: Compare

- `_compare()` matches OmniRoute connections to local state by UUID, then provider_id
- 1Password metadata is cross-referenced (evidence only)
- Catalog coverage is computed (observed vs unobserved)
- Policy distribution is computed per observed provider

### Step 4: Report

- Returns structured dict with observations, ownership classification, reconciliation
- No mutations unless explicitly requested via approval-gated sync

---

## 17. Phase 5 Execution Engine

### Execution Request Model

Provider-xref uses a structured **execution request** model that separates planning from execution. Every request follows this lifecycle:

```
CREATED → VALIDATED → AWAITING_APPROVAL → APPROVED → PREPARING → EXECUTING → VERIFYING → COMPLETED
                                                                                     ↓
                                                                                    FAILED
                                                                                     ↓
                                                                                CANCELLED / BLOCKED
```

**Execution states** (from `engine/executor.py`):

| State | Meaning |
|---|---|
| `created` | Request initialized |
| `validated` | Request structure verified |
| `awaiting_approval` | Waiting for user approval |
| `approved` | User has explicitly approved |
| `preparing` | Preflight passed, loading workflow |
| `executing` | Workflow is running |
| `verifying` | Verifying result state |
| `completed` | Registration finished successfully |
| `partial` | Stopped at human checkpoint |
| `failed` | Execution failed |
| `cancelled` | User cancelled |
| `blocked` | Blocked by policy or checks |

**Request structure:**

```json
{
  "request_id": "exec_...",
  "created_at": "...",
  "operation": "register_provider",
  "provider_id": "deepseek",
  "identity_id": "identity_email_test1",
  "policy_status": "unknown",
  "plan": { "provider_id": "...", "auth_type": "...", "policy_status": "..." },
  "required_approvals": ["user_approval"],
  "status": "awaiting_approval",
  "approval": null,
  "preflight_result": null,
  "workflow_result": null
}
```

**Invariants:**
- No secrets are stored in execution requests. The `plan` field contains only `provider_id`, `auth_type` (label), `policy_status`, and `can_automate` boolean.
- Execution requests are persisted to `data/execution_requests/{request_id}.json`.
- The `plan` field is a snapshot — material changes invalidate approval.

### Execution Gate (Preflight)

`preflight(request_id)` runs 6 deterministic checks:

| Check | PASS | FAIL | UNKNOWN | REQUIRES_REVIEW |
|---|---|---|---|---|
| `provider_exists` | Provider found in catalog | Provider not in catalog | — | — |
| `policy` | ALLOW | DENY | — | REQUIRES_REVIEW |
| `identity` | Identity exists and active | Identity not found | — | Identity consumed/retired |
| `duplicate` | No existing connection | Already connected | — | — |
| `approval` | Request approved | — | — | Not yet approved |
| `plan_stability` | Plan unchanged | Plan materially changed | — | — |

**Execution flow:**

```
create_execution_request()     → status = "awaiting_approval"
    ↓
preflight()                    → 6 checks, deterministic
    ↓
approve()                      → request-scoped approval
    ↓
execute()                      → validate → preflight → workflow → verify → record
```

**Policy enforcement in the gate:**

| Policy | Preflight | approve() | execute() |
|---|---|---|---|
| DENY | FAIL (hard block) | BLOCKED — user cannot override | BLOCKED |
| UNKNOWN | FAIL (soft block) | User can override via explicit approval | May proceed after approval |
| REQUIRES_REVIEW | REQUIRES_REVIEW | User can override via explicit approval | May proceed after approval |
| ALLOW | PASS | Still requires explicit approval | May proceed after approval |

### Approval Semantics

`approve(request_id)` establishes an **explicit, request-scoped** approval. The approval is bound to the exact `request_id` and captures:

- `request_id` — the exact request being approved
- `approved_at` — timestamp
- `approved_by` — approver identity (default: "user")
- `approval_scope` — scoped to `register_provider:{provider_id}`
- `policy_state_at_approval` — snapshot of policy at approval time
- `plan_snapshot` — snapshot of the plan for material-change detection

**Approval cannot be overridden for hard blocks:**
- DENY policy → approval blocked (user cannot override)
- Missing provider → approval blocked
- Missing identity → approval blocked (identity must exist)
- Duplicate registration → approval blocked (already completed)
- Plan stability failure → approval blocked

**Soft blocks (user can override via approval):**
- UNKNOWN policy → user explicitly accepts the risk
- REQUIRES_REVIEW → user explicitly accepts the risk
- Identity consumed/retired → user explicitly accepts

**Material change invalidation:** If the plan changes after approval (provider_id, identity_id, operation, policy state, or plan contents), the approval is invalidated and execution is blocked until re-approval.

**No blanket approval:** There is no "approve all" mechanism. Each `approve()` call is bound to a single `request_id`.

### Dry-Run Execution

`execute(request_id, dry_run=True)` performs:

- Validation of the request structure
- All preflight checks (provider, policy, identity, duplicate, approval)
- Workflow selection
- Workflow action description

**But performs NO external mutations:**
- No browser registration calls
- No OmniRoute POST/PUT/PATCH/DELETE requests
- No API key creation
- No OAuth writes
- No 1Password credential writes
- No account creation in state

Returns a `workflow_result` with `status: "dry_run"` and a list of `actions` that would be performed.

### Human Checkpoints

Browser-based workflows (OAuth, browser-based API key flows) may encounter situations requiring human intervention:

| Situation | Status |
|---|---|
| CAPTCHA | `human_checkpoint` — checkpoint_type: `captcha` |
| Phone verification | `human_checkpoint` — checkpoint_type: `phone_verification` |
| Email verification | `human_checkpoint` — checkpoint_type: `email_verification` |
| Security challenge | `human_checkpoint` — checkpoint_type: `security_challenge` |
| Manual OAuth interaction | `human_checkpoint` — checkpoint_type: `manual_oauth` |
| Terms/consent | `human_checkpoint` — checkpoint_type: `consent` |

Workflows **never** attempt to bypass anti-abuse systems. When a checkpoint is encountered, execution stops and returns:

```json
{
  "status": "human_checkpoint",
  "checkpoint_type": "phone_verification",
  "message": "Manual phone verification is required.",
  "resume_token": "resume_..."
}
```

### Resume Support

`resume(request_id)` continues execution from a human checkpoint:

1. Reloads the execution request
2. Verifies it has not expired or been cancelled
3. Verifies approval remains valid
4. Re-runs preflight
5. Continues from the correct workflow state
6. Never repeats completed registration steps
7. Never creates duplicate accounts

### Idempotency

`execute()` enforces idempotency:

- If the provider is already connected for the identity → returns `already_completed`
- If a previous registration exists in history with `status: "completed"` → returns `already_completed`
- If a previous attempt was `partial` → delegates to `resume_registration()`
- Repeated `execute()` calls never create duplicate accounts or OmniRoute connections

### Registration Ledger

`data/registration_history.json` is extended to record execution lifecycle entries. Each entry records:

- `request_id` — links to the execution request
- `provider_id` — provider being registered
- `identity_id` — identity used
- `operation` — what was attempted
- `auth_type` — "api_key" or "oauth" (type label, never value)
- `status` — completed, failed, partial, cancelled
- `timestamps` — created_at, started_at, completed_at
- `policy_decision` — the policy state at registration time
- `approval_info` — approval record reference
- `workflow_result` — classification (success, human_checkpoint, failed, dry_run)
- `resulting_provider_account_id` — safe identifier where available

**Never recorded:** passwords, API keys, OAuth tokens, refresh tokens, TOTP values, session cookies.

### OmniRoute API

**Read-only (allowed):**
- `GET /api/providers` — Returns `{"connections": [...], "total": N}`
- Response fields: `id`, `provider`, `authType`, `name`, `email`, `priority`, `isActive`, etc.
- Sensitive fields (`apiKey`, `accessToken`, `refreshToken`, `idToken`) are stripped by the OmniRoute server from GET responses
- `discover_omniroute_state()` normalizes connections with safe metadata only

**Mutation (PROHIBITED during Phase 5 — requires explicit execution approval):**
- `POST /api/providers/{provider_id}` — `connect_provider()` sends `{"auth": {...}, "name": "..."}`
- `POST /api/providers/{provider_id}/test` — `verify_provider()` tests a connection

**Bulk import: UNKNOWN** — No `/api/providers/import` endpoint found in the OmniRoute route manifest. Individual connection creation via POST is the only write path.

### Natural-Language Safety Mapping

| User Says | Hermes Action | Mutates? |
|---|---|---|
| "I got a new phone number." | `plan_new_phone()` | No — plan only |
| "Register the best provider using this number." | `plan_registration()` → present plan → `create_execution_request()` → request approval | No — waiting for approval |
| "Do it." | `approve(request_id)` → `execute(request_id)` | Only if approval was explicit and preflight passed |
| "Register everything." | `find_opportunities()` → present bounded plan → request explicit approval per item | No — approval required per item |
| "Use whichever account is best." | `find_opportunities()` selects by deterministic scoring | No — approval required for execution |
| "What accounts do I have?" | `audit()` / `reconcile_real_state()` | No — read-only |
|| "Verify my connections." | `verify_provider()` via GET | No — read-only |

---

## 17. Phase 7: Operational UX, Orchestration & Automation Foundation

Phase 7 turns the existing safe execution engine into a usable operational system for managing provider opportunities. The goal is to establish the smallest solid foundation for:

- **Discovering opportunities** — ranking providers by value, policy, and identity availability
- **Prioritizing them** — priority tiers (high/medium/low) based on score and automation eligibility
- **Showing the user what Hermes recommends** — a `recommendations()` layer with next-action guidance
- **Generating safe execution plans** — batch creation of execution requests (no approval)
- **Running approved work through the existing execution gate** — unchanged from Phase 5/6
- **Handling checkpoints and partial completion** — unchanged from Phase 5/6 (resume, partial status)
- **Maintaining useful operational history** — unified batch status across execution requests
- **Supporting orchestration of multiple independent tasks** — batch planning, status, and summary

Phase 7 is read-only by default. It creates execution requests in `awaiting_approval` status but **never** approves or executes them. All Phase 6 safety guarantees are preserved.

### 17.1 Recommendations Layer

`engine/audit.py` provides two new entry points:

```python
from engine.audit import recommendations, recommend_next

# Get all opportunities with priority tiers and next-action guidance
recs = recommendations()

# Get just the single highest-priority recommendation
next = recommend_next()
```

Each recommendation includes:

| Field | Type | Description |
|---|---|---|
| `provider` | str | Provider ID |
| `name` | str | Human-readable provider name |
| `auth_type` | str | `api_key` or `oauth` |
| `score` | int (0–100) | Deterministic opportunity score |
| `confidence` | float (0.0–1.0) | Confidence in the score |
| `policy_status` | str | `allowed`, `unknown`, `requires_review`, `disallowed` |
| `can_automate` | bool | Whether policy allows automation |
| `priority_tier` | str | `high`, `medium`, `low` |
| `priority_label` | str | Human-readable tier description |
| `next_action` | str | `plan_registration`, `review_policy`, `provide_identity`, `review_and_approve`, `do_not_register` |
| `downstream_count` | int | How many providers cascade from this one |
| `free_quota` | str | Free tier description |
| `signup_difficulty` | str | `easy`, `moderate`, `hard` |
| `verification_requirements` | list[str] | Identity types needed for verification |
| `omniroute_support` | bool | Whether OmniRoute supports this provider |

**Priority tiers** are purely advisory — they help Hermes surface what to show the user first but do NOT replace the execution gate:

- `high` — score ≥ 70, ready to register or review
- `medium` — score ≥ 40, review before registering
- `low` — score < 40, informational
- `none` — policy disallowed

**Next-action guidance** tells Hermes what the user needs to do:

- `plan_registration` — ALLOW + automatable + identity available → create execution request
- `review_policy` — UNKNOWN policy, no automation → user must review
- `provide_identity` — required identity not in state → user must provide
- `review_and_approve` — REQUIRES_REVIEW or UNKNOWN with explicit approval path
- `do_not_register` — policy disallowed → never suggest registration

### 17.2 Batch Planning

`engine/planner.py` provides `plan_recommended_batch()` — a thin composition over the existing `create_execution_request()` system:

```python
from engine.audit import recommendations
from engine.planner import plan_recommended_batch

# Get recommendations
recs = recommendations()

# Create execution requests for each (but do NOT approve or execute)
batch = plan_recommended_batch(recs)
print(f"Created {batch['total_created']} requests, skipped {batch['total_skipped']}")
```

Batch result:

| Field | Description |
|---|---|
| `batch_id` | Unique identifier for this batch |
| `created` | List of `{request_id, provider, status, policy_status, can_automate}` |
| `skipped` | List of `{provider, reason}` — e.g. already connected |
| `errors` | List of `{provider, error}` — for requests that couldn't be created |
| `total_requested` | Number of recommendations passed in |
| `total_created` | Number of execution requests created |
| `total_skipped` | Number skipped (already connected) |
| `total_errors` | Number that errored |
| `status` | Always `"planned"` — never `"approved"` or `"executing"` |
| `created_at` | ISO timestamp |

**Key invariant**: `plan_recommended_batch()` creates execution requests in `awaiting_approval` status only. It never calls `approve()` or `execute()`. The user must review and approve individual requests before any real work happens.

### 17.3 Batch Operational Status

`engine/executor.py` provides `get_batch_status()` and `summarize_batch()` — read-only queries over execution-request files:

```python
from engine.executor import get_batch_status, summarize_batch

# Get detailed status for each request in a batch
statuses = get_batch_status(request_ids)

# Get an aggregated operational summary
summary = summarize_batch(request_ids)
print(f"Awaiting approval: {len(summary['awaiting_approval'])}")
print(f"Ready to execute: {len(summary['ready_to_execute'])}")
print(f"Blocked: {len(summary['blocked'])}")
```

**Summarize batch output:**

| Field | Description |
|---|---|
| `batch_id` | Deterministic ID from sorted request IDs (sha256[:16]) |
| `total` | Number of requests in the batch |
| `by_status` | `{status: count}` across all execution states |
| `by_provider` | `{provider_id: count}` |
| `awaiting_approval` | List of request IDs still awaiting approval |
| `ready_to_execute` | List of approved, preflight-passing request IDs |
| `blocked` | List of blocked request IDs |
| `completed` | List of successfully completed request IDs |
| `partial` | List of request IDs paused at human checkpoints |
| `failed` | List of failed request IDs |
| `cancelled` | List of cancelled request IDs |
| `not_found` | List of request IDs that don't exist |
| `created_at` | Timestamp of the most recent request creation |

Both functions are pure read — they do not modify any request files or trigger execution.

### 17.4 Operational Command Mapping

| User Says | Hermes Action | Mutates? |
|---|---|---|
| "What should I do next?" | `recommend_next()` → present single recommendation | No — read-only |
| "Show me all opportunities." | `recommendations()` → present prioritized list | No — read-only |
| "Plan registrations for my top 3." | `plan_recommended_batch(top_3_recs)` → create execution requests | No — requests stay in `awaiting_approval` |
| "What's the status of my batch?" | `summarize_batch(request_ids)` → operational summary | No — read-only |
| "Execute this batch." | `approve(request_id)` → `execute(request_id)` per item | Only after explicit per-request approval |
| "Resume the ones that need it." | `resume(request_id)` for partial requests | Only after re-validation |

### 17.5 Safety Invariants (unchanged from Phase 6)

All Phase 6 safety guarantees are preserved and verified by `test_phase7.py`:

1. **DENY always blocks** — `recommendations()` excludes disallowed providers; `plan_recommended_batch()` creates requests but preflight will block
2. **UNKNOWN never auto-allows** — unknown-policy opportunities get `review_and_approve` next-action; batch-created requests stay in `awaiting_approval`
3. **Approval is per-request** — `plan_recommended_batch()` does not call `approve()`; each request must be individually approved
4. **No secrets in serialized data** — recommendations contain no credential values; execution requests strip secrets via `_strip_secrets()`
5. **Read-only by default** — `recommendations()`, `recommend_next()`, `get_batch_status()`, `summarize_batch()` never modify state
6. **Planning never executes** — `plan_recommended_batch()` status is `"planned"`, not `"approved"` or `"executing"`
7. **Audit remains read-only** — `recommendations()` delegates to `find_opportunities()` which calls `load_state()` (read-only)

### 17.6 Phase 7 Test Coverage

`tests/test_phase7.py` adds 57 tests across 8 test classes:

| Test Class | Tests | Coverage |
|---|---|---|
| `TestRecommendationsReadness` | 4 | Read-only, no mutation, no secrets, no external calls |
| `TestRecommendationsStructure` | 8 | Output structure, sorting, score ranges, field validation |
| `TestPriorityClassification` | 8 | `_classify_priority()` for all policy/score combinations |
| `TestNextAction` | 7 | `_next_action()` for all policy/identity combinations |
| `TestRecommendNext` | 3 | Single-recommendation selector |
| `TestBatchPlanning` | 8 | Batch creation, awaiting_approval status, no approval/execution, skip duplicates, no secrets |
| `TestBatchPlanningSafety` | 2 | DENY blocks, UNKNOWN never auto-approved |
| `TestBatchStatus` | 4 | Batch status query, field presence, not-found handling, read-only |
| `TestSummarizeBatch` | 8 | Summary structure, by_status, by_provider, batch_id, counter consistency, read-only |
| `TestBatchOperationalFlow` | 3 | Full flow integration, no secrets, no execution |

**Total: 487 tests pass** (430 Phase 1–6 + 57 Phase 7).

---

## 18. Phase 9 — Persistent Browser & Secure Credential Lifecycle

Phase 9 adds the generic browser automation layer and secure credential persistence, making the Phase 8 Cloudflare end-to-end registration path reusable for any provider.

### 18.1 Test Results

**606 tests pass** (487 Phase 1–7 + 108 new Phase 9 tests + 8 registry tests + 3 secret-redaction tests + 1 checkpoint test). 0 failures, 0 errors.

### 18.2 Persistent Local Browser (`adapters/browser.py`)

The browser adapter wraps real MCP browser tools (browser_navigate, browser_click, browser_type, browser_snapshot, browser_vision, browser_scroll, browser_press, browser_console, browser_get_images) and provides:

| Function | Purpose |
|---|---|
| `navigate(url, profile_id)` | Open a URL in the persistent browser profile |
| `click(selector, profile_id)` | Click an element |
| `type_text(selector, text, ...)` | Type text into an input |
| `fill_form(form_data, ...)` | Fill a form with field values |
| `screenshot(profile_id)` | Take a screenshot |
| `snapshot(full, profile_id)` | Get page accessibility snapshot |
| `get_text(selector, profile_id)` | Extract text from a selector |

**Persistent profile management:**
- `ensure_browser_profile_dir()` — creates `~/.hermes/browser_profiles/` directory
- `get_browser_profile_path(profile_id)` — returns the browser profile directory path
- `save_browser_profile_metadata(profile_id, ...)` — writes `browser_profile_metadata.json` with **metadata only** (profile_id, browser_provider, associated_providers, created_at). Never stores cookies, session tokens, or credentials.
- `load_browser_profile_metadata(profile_id)` — loads profile metadata
- `list_browser_profiles()` — lists all profiles by metadata

**Human checkpoint lifecycle:**
- `detect_checkpoint(page_text, page_url)` — detects CAPTCHA, MFA, passkey/webauthn, email verification, OAuth consent, phone verification, phone verification prompts. Returns checkpoint info dict or `None`.
- `detect_authenticated(page_text, page_url, snapshot)` — detects if a user is already logged in (logout buttons, dashboard content, account/profile URLs). Returns `(bool, match_type)`.
- `detect_checkpoint_completion(checkpoint_type, page_text, page_url)` — checks if a previously-detected checkpoint is now resolved. Returns `(bool, details)`.
- `create_checkpoint(...)` — builds a structured checkpoint dict for state persistence (checkpoint_id, provider, step, reason, expected_state, resume_condition). **Never includes password, api_key, token, or secret fields.**
- `checkpoint_message(checkpoint)` — generates a safe, human-readable message (no secrets).

**Compatibility API (Phase 8 backward compatibility):**
- `api_key_flow(provider_id, provider_config, identity)` — declarative action-descriptor for API key provider signup. Returns a list of `actions` (navigate, fill_form, click, checkpoint). Passwords appear as `<GENERATED_PASSWORD>` placeholders — never real values.
- `oauth_flow(provider_id, provider_config, identity, callback_url)` — declarative action-descriptor for OAuth provider registration. Includes session check, authorization navigation, OAuth consent checkpoint, and human verify checkpoint.
- `check_human_checkpoint(current_actions)` — returns checkpoint info dict using Phase 9 detection primitives.
- `generate_consent_message(provider_name, action, details)` — generates user-facing consent messages (safe for chat output).

### 18.3 1Password Authentication & Item Model (`adapters/onepassword.py`)

**Authentication backend detection (Phase 9D):**
- `detect_auth_backend()` — classifies as `service_account`, `desktop_cli`, or `unknown`. Detects when `OP_SERVICE_ACCOUNT_TOKEN` is set (may be read-only). Never prints credentials.
- `can_read()` / `can_write()` — test read/write capability. `can_write()` correctly returns `False` for service accounts (read-only by default).
- `get_desktop_account()` — retrieves the user's desktop-integrated 1Password account (has write access).
- `require_write_access()` — returns `(has_access, error_message)`. If service account is read-only, suggests switching to desktop account.

**Item title conventions:**
- `api_key_title(hostname)` → `"OmniRoute [hostname] Api Key"` (e.g., `"OmniRoute api.cloudflare.com Api Key"`)
- `account_login_title(provider_name)` → provider display name (e.g., `"Cloudflare"`)

**Item lookup & deduplication:**
- `find_login_item(provider_name, vault, account)` — finds existing LOGIN item, returns metadata only (item_id, title, vault, username, tags). Never returns password.
- `find_api_key_item(hostname, vault, account)` — finds existing API key item, returns metadata only.
- `item_exists(title, vault)` — checks if an item already exists.

**Credential storage (Phase 9E):**
- `credential_to_onepassword(credential, hostname, provider_name, vault, dry_run)` — stores a credential in 1Password (or returns reference for dry_run). Returns `{status, credential_ref, item_id, item_title, ...}`. The `credential_ref` contains metadata only (`backend`, `vault`, `item_id`, `field`, `reference`).
- `build_credential_ref(vault, item_id, item_title, field)` — builds a reference dict with `op://vault/item_id/field` format.
- `get_credential_value(item_id, field, vault, account)` — retrieves the actual secret value. **Only called by operational code that needs it.**

**Account login persistence (Phase 9G):**
- `create_account_login(title, username, password, url, vault, tags, custom_fields, account)` — creates a 1Password LOGIN item for provider account credentials. Password is set to `"<GENERATED_PASSWORD>"` placeholder in the browser flow; the real password goes directly to 1Password via the browser's form autofill. **Never stored in state or chat.**
- `Adapter` class wrapper exposes: `detect_auth_backend()`, `can_read()`, `can_write()`, `get_desktop_account()`, `require_write_access()`, `account_login_title()`, `api_key_title()`, `find_login_item()`, `find_api_key_item()`, `item_exists()`, `create_login()`, `update_login()`, `get_credential_value()`, `build_credential_ref()`, `search_items()`, `get_item()`, `search_provider_items()`, `get_login()`.

### 18.4 Generic Credential Extraction (`adapters/credential_extractor.py`)

- `ExtractionRule` — defines a regex/selector/CLIPBOARD/snippet_button/table_row extraction pattern with `provider`, `page`, `pattern`, `prefix`, `min_length`, `description`.
- `ExtractionStrategy` — enum: `REGEX`, `SELECTOR`, `CLIPBOARD`, `SNIPPET_BUTTON`, `TABLE_ROW`.
- `PageSnapshot` — text and URL context for extraction.
- `ExtractionResult` — holds extraction results. `to_debug_dict()` and `to_result()` methods **NEVER include the actual secret value** — only metadata (provider, method, prefix, masked, redacted).
- `extract_credential(snapshot, rules)` — tries each rule in order, returns first match.
- `_try_extract_rule(rule, snapshot)` — applies a single rule, handles `re.findall` returning strings or tuples.
- `redact_credential(value)` — masks all but first 4 and last 4 characters. Returns `[REDACTED]` for empty/None values.
- `credential_to_onepassword(...)` and `retrieve_credential_value(...)` — integration with 1Password storage/retrieval.

**Provider extraction rules** (`PROVIDER_EXTRACTION_RULES`):
| Provider | Strategy | Pattern |
|---|---|---|
| Cloudflare Workers AI | SNIPPET_BUTTON | API key button on `/dashllar/...` |
| OpenAI | REGEX | `sk-[a-zA-Z0-9_-]{20,}` on `platform.openai.com/api-keys` |
| Anthropic | REGEX | `sk-ant-[a-zA-Z0-9_-]+` on `console.anthropic.com/settings/keys` |
| Groq | REGEX | `gsk_[a-zA-Z0-9]+` on `console.groq.com/keys` |
| Google AI | SNIPPET_BUTTON | API key button on `aistudio.google.com/` |
| DeepSeek | REGEX | `sk-[a-zA-Z0-9_-]{48}` on `platform.deepseek.com/` |
| Gemini | SNIPPET_BUTTON | Show key button on `aistudio.google.com/` |

**Security boundary:** The extraction pipeline is `Browser/page → secret held transiently in memory → 1Password → credential reference`. The secret does NOT flow through chat, debug dictionaries, execution request JSON, registration history, provider state, browser profile metadata, or logs. `ExtractionResult.to_debug_dict()` and `to_result()` remain secret-free. `retrieve_credential_value()` may return the secret ONLY to the operational caller.

### 18.5 OmniRoute Connection Lifecycle (`adapters/omniroute.py`)

- `find_existing_connection(provider_id, omniroute_connections)` — searches existing OmniRoute connections to avoid duplicates.
- `rename_provider(provider_id, new_name, token)` — renames a provider connection. Uses `PUT /api/providers/{id}` (PATCH returns 405).
- `update_provider(provider_id, updates, token)` — generic provider update via PUT.

### 18.6 Security Model

**Browser profile:** The persistent browser profile may contain authenticated browser state/cookies internally (this is inherent to persistent browser sessions). However, `browser_profile_metadata.json` contains **metadata only** — no cookies, session tokens, or browser credentials are exported to JSON or state files.

**Human checkpoints:** The browser remains open after human checkpoints. Human authentication happens in the visible browser window — Hermes never asks the user to paste passwords, MFA codes, API keys, or OAuth tokens. Hermes detects checkpoints, tells the user to complete them in the browser, leaves the browser open, re-snapshots, and detects when authentication is complete. **Live-validated:** the Phase 9 acceptance test successfully demonstrated checkpoint detection (GitHub OAuth login), human authentication completion (password + MFA in visible browser), and automatic resume (redirect back to Groq Console detected).

**1Password account-login model:** When Hermes creates a provider account, it saves the account login to 1Password automatically using the provider's display name as the title. If a matching login item already exists, it is detected and reused. The API credential is a separate item. Passwords never appear in chat, registration history, provider state, execution requests, or logs.

### 18.7 Limitations

- Provider browser automation has been **unit-tested** (via mock browser adapters) and **live-validated** with a real headed Chrome browser performing GitHub OAuth on Groq.
- `api_key_flow` and `oauth_flow` return **declarative action descriptors** (not live browser automation). The Hermes runtime executes these descriptors as actual MCP tool calls.
- Credential extraction rules are defined per-provider in the `PROVIDER_EXTRACTION_RULES` catalog. New providers require adding a rule entry.
- The browser profile directory lives outside the repository at `~/.hermes/browser_profiles/` — it is gitignored and not tracked.

### 18.8 Phase 9 Live Acceptance Test — Groq GitHub OAuth

**Live-validated capabilities** (verified with real headed Chrome browser):

```
headed browser
→ console.groq.com/login
→ GitHub OAuth (Continue with GitHub)
→ human authentication checkpoint (GitHub password + MFA)
→ OAuth redirect back to Groq Console
→ authenticated Groq session
→ identity verification (lazymause@gmail.com confirmed via /settings/profile)
→ automatic resume after checkpoint
```

**Multi-account identity distinction** (verified):
- Groq Google account → `angeloandrea.isola@gmail.com`
- Groq email account → `lazymause@gmail.com`
- Both identities are distinguishable via the Groq Profile page (`/settings/profile` → Email field)

**Test results:**
- Browser session: PASS (headed Chrome, visible window, 1 window confirmed)
- MCP browser tools: PASS (navigate, snapshot, click all work)
- Checkpoint detection: PASS (detected GitHub login page as `oauth_signin` checkpoint)
- Human checkpoint handling: PASS (detected GitHub password/MFA requirement, reported to user)
- Automatic resume: PASS (detected redirect to console.groq.com/home, verified authenticated state)
- Identity verification: PASS (email `lazymause@gmail.com` detected on Profile page)
- No account creation: PASS (login flow only, no signup)
- No API key generation: PASS (test stopped before credential acquisition)
- No OmniRoute changes: PASS (existing connection unchanged)
- No 1Password changes: PASS (no new items created)
- Security boundary: PASS (no secrets in Hermes state/logs/checkpoints)

**Configuration:** `browser.headed: true` in `~/.hermes/config.yaml` is required for the Hermes runtime to launch `agent-browser` with `--headed` flag, producing a visible Chrome window.

### 18.9 Known Limitations — Magic-Link Authentication Isolation

**Email magic-link authentication is inherently browser-session-bound.**

When a provider (e.g., Groq) sends a magic link to the user's email, the link can only authenticate the browser session that opens it. Opening the link in a different browser (the user's normal browser vs. the Hermes-controlled browser) does NOT authenticate the Hermes session.

The Phase 9 checkpoint system handles this correctly:
1. Detects the email verification checkpoint (via `detect_checkpoint()`)
2. Reports the current URL and checkpoint state
3. The user must open the magic link **in the Hermes-controlled browser**
4. After the user completes the action, `detect_checkpoint_completion()` checks if authentication is complete
5. If the magic link was opened in a different browser, the Hermes session remains unauthenticated — this is correctly detected as `authenticated: False`

The system never:
- Extracts or copies cookies/tokens between browsers
- Pastes magic-link URLs into Hermes/chat
- Stores authentication links in state

**Recovery options** when magic-link is opened in the wrong browser:
- Retry the authentication flow
- Use an alternative auth method (Google, GitHub, OAuth) if available
- The checkpoint `retry_count` tracks attempts with bounded retries

**Email verification recovery** (e.g., expired, invalid, already-used links):
- The checkpoint system detects error states via regex patterns
- `resend` links are detected and reported in the checkpoint reason
- The checkpoint is marked as `recoverable: True` for email verification
- The `retry_count` tracks how many resend attempts have occurred
