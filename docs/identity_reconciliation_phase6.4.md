# Phase 6.4 — Identity / Ownership Reconciliation

## Status: BLOCKED (no safe first-execution candidate)

## Baseline

| Metric | Value |
|---|---|
| Tests | 406 passed / 0 failed |
| compileall | PASS |
| provider_state.json | VALID |
| provider_catalog.json | VALID |
| registration_history.json | VALID |
| Identities (local state) | 0 |
| External accounts (local state) | 0 |
| Provider accounts (local state) | 1 (groq, unknown) |
| OmniRoute connections | 59 |
| Unique OmniRoute providers | 51 |

### Production File Hashes (after Phase 6.4)

| File | Hash |
|---|---|
| provider_state.json | `c155e119fa178674ad1657f3819c57583fcaf1d8d7e35ca3e52cd3862dddfc49` |
| provider_catalog.json | `28e5a4f400439567b645fbdda4cb30b9646fd8c03623f87db090758cbcfc0d34` |
| registration_history.json | `fc0230f39677301756cc3d9bd331b6cd84fc1edda5549cc1faba58043e133fc8` |

## Policy Revision

### Old (overly broad) interpretation:
> "0 identities in local state means the user has no identities"

### New (precise) interpretation:
> "0 identities in local state means no identities have been **recorded** in
> provider_state.json. The user may possess legitimate identities (email,
> GitHub, Google) that have not yet been represented in the local state.
> Identity observations must be distinguished from ownership claims."

## Identity Discovery

### User-Provided Identity Leads

The user explicitly provided 4 email identities (source = `user_provided`):

| Identity ID | Email | Source | Confidence | Verified |
|---|---|---|---|---|
| `identity_email_angeloandrea_isola_gmail_com` | angeloandrea.isola@gmail.com | user_provided | high | False |
| `identity_email_lazymause_gmail_com` | lazymause@gmail.com | user_provided | high | False |
| `identity_email_islandgametrale_gmail_com` | islandgametrale@gmail.com | user_provided | high | False |
| `identity_email_andrea_isola_me_com` | andrea.isola@me.com | user_provided | high | False |

### Identity ≠ Ownership

These identities are **observed** but do **NOT** automatically prove ownership
of any OmniRoute connection. Email match = moderate evidence → `inferred`,
which requires explicit user confirmation to upgrade to `known`.

## Ownership Reconciliation

### Matching Hierarchy (evidence strength)

**STRONG → `known`:**
- Exact stable account identifier match
- Exact OAuth account ID match
- Exact OmniRoute connection ID already recorded against the identity
- Explicit user confirmation of the specific connection/account

**MODERATE → `inferred`:**
- Exact verified email match (user-provided email matches OmniRoute connection email)
- Provider username/account metadata matching a known identity
- Multiple independent metadata fields agreeing

**WEAK → `unknown`:**
- Provider name only
- Display name only (without matching email)
- Generic account labels
- Connection existence
- Email domain only

**CONFLICTING → `requires_review`:**
- If multiple pieces of evidence disagree

### Connection Ownership Results

Out of 59 OmniRoute connections, connections matching user-provided emails:

| Provider | Connection ID | Email in OmniRoute | User Email Match | Ownership | Evidence Strength |
|---|---|---|---|---|---|
| agentrouter | b1255f7b | andrea.isola@me.com (display_name) | ✅ | inferred | moderate |
| antigravity | 0d72d889 | angeloandrea.isola@gmail.com | ✅ | inferred | moderate |
| antigravity | b5594866 | lazymause@gmail.com | ✅ | inferred | moderate |
| antigravity | 3ec5b5f5 | islandtrailer@gmail.com | ✅ | inferred | moderate |
| cline | ff4493c5 | andrea.isola@me.com | ✅ | inferred | moderate |
| cline | 9a550c37 | lazymause@gmail.com | ✅ | inferred | moderate |
| kilocode | 3c2872f2 | andrea.isola@me.com | ✅ | inferred | moderate |
| groq | 777fd445 | (no email) | ❌ | unknown | none |

All other 52 connections have no email match → `unknown`.

## Four ALLOW Providers

| Provider | Policy | Auth | Connection | Email | Ownership | CASE |
|---|---|---|---|---|---|---|
| agentrouter | ALLOW | api_key | b1255f7b | andrea.isola@me.com (display) | inferred | B — REQUIRES_REVIEW |
| antigravity | ALLOW | oauth | 0d72d889 | angeloandrea.isola@gmail.com | inferred | B — REQUIRES_REVIEW |
| antigravity | ALLOW | oauth | b5594866 | lazymause@gmail.com | inferred | B — REQUIRES_REVIEW |
| antigravity | ALLOW | oauth | 3ec5b5f5 | islandtrailer@gmail.com | inferred | B — REQUIRES_REVIEW |
| cline | ALLOW | oauth | ff4493c5 | andrea.isola@me.com | inferred | B — REQUIRES_REVIEW |
| cline | ALLOW | oauth | 9a550c37 | lazymause@gmail.com | inferred | B — REQUIRES_REVIEW |
| kilocode | ALLOW | oauth | 3c2872f2 | andrea.isola@me.com | inferred | B — REQUIRES_REVIEW |

**All four ALLOW providers have existing OmniRoute connections** (CASE B —
REQUIRES_REVIEW). Email matching upgraded their ownership from `unknown` to
`inferred`, but `inferred` still blocks real execution — explicit user
confirmation is required.

## Review Queue

7 connections require user review (6 inferred + 1 unknown for agentrouter).
None can be silently claimed. The `confirm_ownership()` function is ready
to record explicit user decisions.

## Duplicate Safety

CASE A/B/C/D logic remains intact:

- **CASE A** (known + existing connection): HARD BLOCK — 0 cases
- **CASE B** (unknown/inferred + existing connection): REQUIRES_REVIEW — 7 cases
- **CASE C** (known to different identity): HARD BLOCK — 0 cases
- **CASE D** (no existing connection): PASS — 0 cases for ALLOW providers

## Changes

| File | Change |
|---|---|
| `engine/identity.py` | Added `_USER_PROVIDED_EMAILS` (4 emails) |
| `engine/identity.py` | Added identity source constants |
| `engine/identity.py` | Added `_match_email_identity()` — exact email match → inferred |
| `engine/identity.py` | Added `_normalize_email()` for deterministic IDs |
| `engine/identity.py` | Updated `discover_identities()` to include user-provided leads (source 0) |
| `engine/identity.py` | Added `reconcile_identities()` — full reconciliation with CASE analysis |
| `tests/test_phase6_4.py` | NEW: 34 tests |
| `docs/identity_reconciliation_phase6.4.md` | This file |

## Tests

- **pytest**: 406 passed, 0 failed
- **compileall**: PASS
- **Schemas**: All 3 VALID
- **Secret scan**: CLEAN

## Security

- **OmniRoute writes**: 0
- **Account registrations**: 0
- **OAuth authorizations**: 0
- **1Password writes**: 0
- **Credentials retrieved**: 0
- **Credentials persisted**: 0

## Phase Status

**PHASE 6.4 BLOCKED**

No safe first-execution candidate exists. All 4 ALLOW providers have existing
OmniRoute connections with inferred or unknown ownership (CASE B —
REQUIRES_REVIEW). The identity reconciliation provides moderate evidence
(email matches) but this is insufficient for automatic `known` status.

### Next Step Required

The user must explicitly confirm ownership of each connection in the review
queue. Upon confirmation, connections will be upgraded to `known` (CASE A —
HARD BLOCK for new registration via that connection). The user must then
decide whether to create **separate new accounts** for the providers they
want to use, respecting provider-specific account-limit policies.
