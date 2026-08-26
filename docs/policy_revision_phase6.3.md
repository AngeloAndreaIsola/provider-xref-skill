# Phase 6.3 — Legitimate Account Creation Policy

## Status: BLOCKED (no safe first-execution candidate)

## Policy Revision

### Old (overly broad) interpretation:
> "Bot account creation is prohibited" / "Providers requiring Google/GitHub
identities cannot be used"

This interpretation treated any provider requiring browser signup, OAuth,
email verification, or Google/GitHub identity as automatically unsuitable.

### New (precise) policy:

**Legitimate account creation is permitted when ALL of:**
1. The account is being created for the user themselves.
2. The user has explicitly authorized the registration.
3. Real user-provided identity information is used.
4. The provider permits the account.
5. The workflow does NOT circumvent anti-abuse or security controls.
6. CAPTCHA remains a **HUMAN CHECKPOINT** (never bypassed).
7. Email verification remains a **HUMAN CHECKPOINT** (unless the user
   explicitly provides an authorized mechanism to complete it).
8. Phone verification remains a **HUMAN CHECKPOINT**.
9. OAuth authorization remains a **HUMAN CHECKPOINT** when user interaction
   or consent is required.
10. Credentials are stored only through the existing secure credential
    mechanism (1Password).
11. No credentials are exposed in state, logs, plans, execution requests,
    or audit output.

### Explicitly prohibited (unchanged):
- Fabricated identity information
- Impersonation
- Unauthorized account creation
- Bypassing CAPTCHA, email verification, phone verification, or OAuth consent
- Bypassing provider account limits or rate limits
- Bypassing bans or suspensions
- Circumventing anti-abuse systems
- Creating accounts to obtain resources the provider limits per user/account
- Using disposable/fake identities to evade provider restrictions

### Key distinction:
```
"identity not recorded locally" ≠ "user does not possess this identity"
```
The user may possess real identities (email, GitHub, Google) that are simply
not yet recorded in `provider_state.json`. These must be reported as required
user input rather than assumed absent.

---

## ALLOW Provider Re-evaluation

### Catalog ALLOW providers:
| Provider | Auth | Identity Req | Verification | Signup |
|---|---|---|---|---|
| agentrouter | api_key | email | email | browser |
| antigravity | oauth | email, google, github | none | browser + OAuth |
| cline | oauth | email, github | none | browser + OAuth |
| kilocode | oauth | email, github | none | browser + OAuth |

### OmniRoute Audit (READ-ONLY GET /api/providers)

Total connections in OmniRoute: **59**
Unique providers connected: **50**

All 4 ALLOW providers have **existing OmniRoute connections** with
**unknown ownership** (no local identity evidence):

| Provider | Connection ID | Auth Type | Active | Test Status | Ownership |
|---|---|---|---|---|---|
| agentrouter | b1255f7b-36ed-413e-8a34-2627ec93deea | apikey | ✅ | active | unknown |
| antigravity | 0d72d889-c960-4756-bec1-712d525af0d4 | oauth | ✅ | active | unknown |
| cline | ff4493c5-c716-4761-9143-a7bcb612cb11 | oauth | ✅ | active | unknown |
| kilocode | 3c2872f2-4e3b-442a-b437-da602e6f4305 | oauth | ✅ | active | unknown |

### Duplicate Safety Cases (all CASE B — REQUIRES_REVIEW)

Per the Phase 6.2 safety rules, each existing connection with unknown
ownership is classified as **CASE B: REQUIRES_REVIEW**. This means:

- The connection **cannot be safely reused** as a clean first-execution candidate.
- The connection **cannot be overwritten** (Rule: do not modify, claim, or delete it).
- Creating a **separate new account** is only legitimate if the provider
  permits multiple accounts AND the existing connection is left untouched.

### Provider account policy investigation

**agentrouter** (agentrouter.io):
- Auth: API key
- Policy evidence: provider does not document multiple-accounts policy
- `agentrouter_policy_evidence`: UNKNOWN
- The provider operates as an LLM routing service; account limits are
  opaque. Creating a new account is technically possible but policy
  cannot be confirmed.
- `policy_evidence: UNKNOWN` → cannot confirm multiple accounts are permitted

**antigravity** (antigravity.ai):
- Auth: OAuth via Google/GitHub
- The Antigravity-Manager GitHub project explicitly supports **multi-account
  management** ("Add multiple Google accounts to increase your combined quota")
- However, this is a third-party tool's feature, not the provider's official
  ToS. The provider's own terms are not reviewed.
- `policy_evidence: PARTIAL` (multi-account tool exists, provider ToS not reviewed)

**cline** (cline.rodney.fm):
- Auth: OAuth via GitHub/Git
- Cline is an open-source VS Code extension; accounts are GitHub-based
- Each GitHub account can have one Cline auth
- `policy_evidence: PARTIAL`

**kilocode** (kilocode.com):
- Auth: OAuth via GitHub
- `policy_evidence: UNKNOWN` (no documentation found)

### Candidate evaluation

For a provider to be a safe first-execution candidate, it must satisfy ALL:
1. policy = ALLOW ✅ (all 4)
2. supported workflow ✅ (api_key or oauth workflow available)
3. identity available — **BLOCKED** (0 identities in local state; user must provide)
4. no known duplicate — **BLOCKED** (all 4 have existing OmniRoute connections with unknown ownership → CASE B)
5. no existing OmniRoute connection used as clean candidate — **BLOCKED**
6. no destructive modification — OK if a new separate connection is created
7. no prohibited external identity creation — OK if user performs OAuth/signup themselves
8. no CAPTCHA/security bypass — workflows include human checkpoint steps
9. explicit user approval still required — enforced by executor

### Blocking factors

1. **OmniRoute CASE B for all 4 ALLOW providers**: Each has an existing
   connection with unknown ownership. Per Phase 6.2 Rule 3, this is
   REQUIRES_REVIEW and cannot become executable merely through normal
   approval.

2. **Zero identities in local state**: The user has not yet recorded any
   identities in `provider_state.json`. The user may possess real identities
   (email, GitHub, Google) but these must be explicitly provided.

3. **No CASE D (no existing connection) ALLOW provider**: All ALLOW providers
   already have OmniRoute connections.

### Cannot promote UNKNOWN providers
Per Phase 6.2 Rule 8 and Phase 6.3 Task 2, UNKNOWN providers cannot be
promoted merely because no ALLOW provider is available.

---

## Verdict

### PHASE 6.3 — BLOCKED

**Reason**: No ALLOW provider satisfies all first-execution safety criteria.

1. All 4 ALLOW providers (agentrouter, antigravity, cline, kilocode) have
   existing OmniRoute connections with unknown ownership → CASE B →
   REQUIRES_REVIEW → cannot be safely auto-selected as a clean first-execution
   candidate.

2. Zero identities are recorded in local state. While the user may possess
   real identities, the executor requires explicit identity selection and
   must not fabricate or assume identity availability.

3. No CASE D (no existing connection) ALLOW provider exists in the catalog.

**Next step required**: The user must explicitly decide how to handle the
existing OmniRoute connections. Specifically:

> **Please confirm**: For which of the 4 ALLOW providers (agentrouter,
> antigravity, cline, kilocode) would you like to proceed with creating
> a **separate new account** (leaving the existing OmniRoute connection
> untouched), and please provide the identity information (email, GitHub,
> Google) you wish to use?

Upon receiving this explicit user decision and identity, the system can:
1. Create a new execution request for the specified provider
2. Run preflight (which will flag the existing connection as CASE B)
3. Require explicit user confirmation of the CASE B status
4. Proceed only after explicit approval with the CASE B acknowledged

No real OmniRoute mutation, account creation, OAuth authorization, or
1Password write occurred during this phase.