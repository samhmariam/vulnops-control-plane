# Day 1 security architecture review

Date: 25 October 2026. Reviewed baseline: `b0d0dbb` (Prompts 0–12), followed by
the targeted fixes below.

Status: **DONE_WITH_CONCERNS. Day 1 acceptance PASS** under the documented synthetic,
trusted-local-operator threat model. This does not authorize production mutation or
unrestricted agent/database integration.

## Scope, method, and trust boundaries

Before modifying code, reviewed the domain/application models, adapters, matching,
workflow policy, repositories, schema, Alembic/RLS/grants, CLI, lab inputs/Compose,
initialization scripts, lockfile, tests, invariants, and ADR-001 through ADR-011.
Applied the cso skill's trust-boundary, safe verification, and false-positive
methodology; targeted remediation follows the user's explicit instructions.
Unrelated onboarding, telemetry, and future product functionality were not added.

Two candidate boundaries received independent read-only review. Optional evidence
URIs were correctly rejected as a vulnerability: ADR-002 allows internal observations
without public URLs. The cross-asset issue was independently reproduced and its
fix independently verified. Blank required attribution was verified directly and is
a representation gap, not a demonstrated remote exploit.

```text
Untrusted fixture bytes -> explicit adapter -> canonical observations + Evidence
  -> application assessment/case policy -> tenant repositories/state machine
  -> PostgreSQL snapshots + append-oriented history -> inspection CLI
```

Shape validation and hashes do not prove source truth. The supported caller is a
trusted local operator; RLS does not authenticate whoever chooses tenant context.
There is no HTTP application endpoint, live-feed scheduler, agent runtime, generic
shell executor, or production tool. Lab HTTP servers are inert static stand-ins.

## Findings and disposition

| ID | Classification | Verification | Disposition |
| --- | --- | --- | --- |
| H-01 | HIGH: assessment accepted foreign asset components | 9/10 confidence; independently reproduced | FIXED |
| M-01 | MEDIUM: blank required evidence attribution accepted | 10/10 for the validation gap; local construction probe | FIXED |
| F-01 | FUTURE: source suitability, authenticity, freshness | Confirmed deferred authority boundary | Before authoritative live intelligence |
| F-02 | FUTURE: authenticated tenant/actor context and agent isolation | Confirmed trusted-caller boundary | Before agents or remote/multi-user access |
| F-03 | FUTURE: exact immutable action-bound approvals | UUID references alone do not implement this | Before production mutation |
| F-04 | FUTURE: default-deny execution gateway and global kill switch | No executor exists yet | Before production mutation |
| F-05 | FUTURE: external action idempotency and reconciliation | Current replay covers records, not external effects | Before retryable external execution |
| F-06 | FUTURE: administrator-resistant audit and recovery | Runtime append APIs/grants are not a ledger | According to retention/threat requirements |

**BLOCKER: 0. HIGH: 1 found, 1 fixed, 0 open. MEDIUM: 1 found, 1 fixed.
LOW: no additional verified finding.** FUTURE entries are explicit feature gates,
not vulnerabilities attributed to nonexistent production features.

### H-01: Foreign components could establish another asset's conclusion

Location: `src/vulnops/application/assessment.py:25`, assess_asset.

**Root cause:** Asset/Vulnerability contain mutable nested lists. Revalidating each
InstalledComponent cannot establish ownership relative to the containing Asset.
Assessment resolved evidence UUIDs without revalidating complete snapshots,
contrary to ADR-004's explicit application-boundary requirement.

**Verified sequence:** load affected web-01 and fixed web-02; replace
`web01.components[:]` with `web02.components`; assess web-01. Before the fix,
the result was NOT_AFFECTED while comparison ownership identified web-02.

**Security consequence:** a caller/future adapter with a mutated snapshot could
obtain false reassurance for the wrong asset, violating INV-10. HIGH denotes this
security-critical application invariant, not remote exploitability. No successful
persisted demo corruption was demonstrated: the demo loads validated fixtures,
and save_asset already revalidates. Those containment facts do not make the public
assessment result correct.

**Fix:** revalidate complete Asset, Vulnerability, and Evidence snapshots before
assessment. Reject conflicting contents for one evidence UUID instead of letting
list order select a claim. The original probe now raises ValidationError; the
unchanged valid baseline remains AFFECTED.

**Architectural implication:** model construction and frozen IDs are insufficient
application boundaries. [ADR-012](decisions/ADR-012-assessment-boundary-revalidation.md)
requires snapshot revalidation without changing version semantics, dropping foreign
components silently, or manufacturing safe outcomes.

**Tests added:** foreign-list replacement/append, cleared asset/component/product
provenance, and conflicting evidence identities. A PostgreSQL regression injects
the malformed inventory into the real application and verifies nonzero CLI exit,
no PASS, and rollback of source, asset, and case writes.

### M-01: Empty required attribution could be stored as evidence

Locations: `src/vulnops/domain/evidence.py:53` and the revalidation path in
`src/vulnops/persistence/repositories.py:82`.

**Root cause:** required source_name, subject_type, subject_id, claim_type, and claim
strings accepted empty/whitespace-only content. Their UUID could satisfy reference
existence checks without providing useful attribution.

**Verified sequence:** construct Evidence with blank required strings and a valid
source enum, UUID, and timestamp. Before the fix, construction succeeded and the
repository's identical validation contract would not reject its blankness. This
requires an in-process caller/faulty adapter; fixture adapters already supply actual
attribution. It is not evidence of a remote attacker crossing today's boundary.

**Security consequence:** apparently present provenance could fail INV-03. This is
distinct from optional URI/hash design, which remains valid.

**Fix:** reject blank required attribution and blank optional URI/hash values when
supplied. Allow absent internal URIs and preserve original nonblank source text,
including instruction-like claims. Assignment and repository revalidation enforce
the same contract. Nonblank content still does not establish authenticity or truth.

**Architectural implication:** require attribution without turning Evidence into a
decision or inventing sources. Malformed historical rows fail validation and require
explicit reconciliation; valid lab records and identities remain unchanged.

**Tests added:** blank required/optional fields, assignment rejection, absent
internal URI support, instruction-like text preservation, and PostgreSQL rejection
of a malformed trusted model_copy snapshot.

## Answers to the twelve questions

| # | Answer | Boundary / residual requirement |
| --- | --- | --- |
| 1. External content directly mutating authoritative state | No observed instruction/execution bypass. Supported claims intentionally influence records and assessments through application policy. | No eval, shell execution, arbitrary URL fetching, or model interpreter consumes advisory text. Structurally valid sources can still lie (F-01). |
| 2. Evidence without meaningful provenance | Blank attribution was accepted and is now rejected (M-01). | Existence/nonblank strings do not establish suitability. The generic repository checks existence, not whether an unrelated UUID proves a particular conclusion (F-01). |
| 3. UNKNOWN becoming NOT_AFFECTED | No automatic conversion found; unsupported/ambiguous versions stay UNKNOWN. | Asset negatives require complete inventory and all comparisons to exclude affectedness. H-01 was a distinct cross-asset false-negative path, now fixed. |
| 4. Lifecycle skips | Normal repository transition/append APIs deny unlisted edges. | Current-state locks, expected-state/revision checks, and prerequisites apply. Actor labels are not authentication; direct SQL credentials remain outside the Python policy boundary (F-02). |
| 5. Historical event alteration | No normal update/delete API; conflicting replay is rejected. | Runtime grants deny event UPDATE/DELETE. Database owners/admins retain authority; this is not a tamper-proof ledger (F-06). |
| 6. One case mutating another asset's case | No persisted retarget path demonstrated. | Tenant-scoped identity/uniqueness/FKs and full event equality prevent reassignment. A new PostgreSQL event-retarget regression verifies neither case/history changes. Assessment attribution H-01 is fixed. |
| 7. Malformed versions causing unsafe determinations | Unsupported ordering remains UNKNOWN in reviewed paths. | Only explicit numeric three-part SemVer ordering is supported; no generic string ordering. Opaque exact equality is an explicit ADR-008 source claim, not inferred ordering or proof of truth. |
| 8. Repeated source events duplicating actions | Exact fixtures reuse core records/events; no production operation executes. | Changed snapshots conflict explicitly. Record identity is not exactly-once external execution (F-05). |
| 9. Future agents bypassing the boundary | Yes, if given raw credentials, sessions, or trusted in-process write authority. | Immutability is not a sandbox. Expose authenticated narrow commands; do not expose raw save/append APIs as model tools (F-02). |
| 10. Difficulty introducing default-deny tools | No structural obstruction; no generic executor exists to preserve. | Require registered typed operations, bounded targets, policy, and approval outside orchestration; never fall back to shell execution (F-04). |
| 11. Exact immutable approval binding | A clear future path exists, but UUID references alone are insufficient. | Immutable action specifications/versioned plans plus approval digest binding through application services (F-03). |
| 12. Global mutation kill switch | The shared application authorization/dispatch boundary is the clear location. | Check durable global denial immediately before each side effect; fail closed if unavailable. This is planned, not implemented (F-04). |

## Future control design; no Day 2 implementation

**F-01:** live-source services must establish collector/source identity, relevant
asset/product/version evidence, observation freshness, and scoped completeness.
Retain conflicts rather than choosing convenient claims or confidence values.
Evidence existence, a hash, and nonblank attribution are not suitability policy.

**F-02:** derive tenant and actor from authenticated context independently of model
output. Agents must not receive database/tool credentials, SQLAlchemy sessions,
arbitrary host imports, or host process authority. Narrow commands must re-evaluate
permissions/evidence. RLS cannot protect against credentials allowed to choose
arbitrary tenant context; a HUMAN enum is not proof of human authority.

**F-03:** approvals should bind tenant, case, asset/target set, immutable plan/action
version, registered operation/tool version, normalized parameters, artifact/image
digests, relevant evidence/context versions, and a versioned canonical action digest.
Check authority, expiry, revocation, and digest equality at dispatch. Changed targets
or parameters require new approval. An approval UUID or plan UUID is insufficient.

**F-04:** one shared application mutation gateway should enforce tool registration,
policy, approval, and global denial. Every canary, rollout, and rollback adapter
must pass it and recheck immediately before each mutation. Global denial must
dominate tenant/tool allowances and fail closed on unreadable stop state. A UI
toggle, environment flag, or LangGraph edge alone is insufficient. Any emergency
rollback exception needs explicit narrow audited policy, not a generic bypass.
These are future responsibilities; no new executor/kill-switch module is claimed.

**F-05:** future effects need scoped idempotency keys, durable dispatch state,
transactional intent recording, and verification/reconciliation after ambiguous
timeouts. Approval/action identity must survive retries. Repeated source messages
must not map directly to repeated production effects.

**F-06:** revisit privileged-access separation, signed/immutable audit retention,
backups and tested restore for the applicable threat/regulatory requirements.
Existing runtime grants constrain normal application APIs, not database owners.
ADR-007's deferred ledger decision is not silently reversed.

## Infrastructure, secrets, and dependency checks

* No CI workflows, IaC deployment targets, incoming webhook receivers, or repository
  skill execution files were found. Missing controls on nonexistent systems are not
  reported as current vulnerabilities.
* A redacted, format-based tracked-history scan found no obvious private-key, AWS
  access-key, GitHub-token, or Slack-token patterns. This limited heuristic is not
  exhaustive secrets certification; no credential was tested against a live provider.
* Tracked `.env.example` URLs were verified as loopback/public-development defaults.
  `.env`, other `.env.*` files, and credential directories remain ignored. The public
  lab passwords are development configuration, not deployment credentials.
* PostgreSQL/web host ports bind loopback. Four stand-ins use only the internal
  network; two web stand-ins also have bridge egress. Mutable lab image tags are not
  production deployment pins. No real vulnerable service was deployed.
* The committed lockfile uses PyPI/local sources and distribution hashes. Temporary
  pip-audit evaluation of **12 locked runtime packages** returned **0 known advisories
  and 0 skipped evaluated packages** on this date. Windows-only tzdata was outside
  the Linux evaluation. Dev/build dependencies and container images were not scanned
  for advisories. This is neither a guarantee of safety nor ongoing freshness.
* Gitleaks was unavailable; the limited history scan above was used instead. Consider
  an independently maintained secret scanner when CI is introduced. Auditing added
  no runtime dependency and sent package names/versions, not repository source,
  fixture contents, credentials, or enterprise data, to advisory services.

## Validation and closing gate

Pre-fix probes reproduced both findings before edits. Independent post-fix review
confirmed the H-01 probe is rejected while the valid baseline stays AFFECTED.

* Focused security/application/evidence tests: **68 passed**.
* Full `uv run --env-file .env.example --locked pytest`: **405 passed**, including
  **22 new security unit tests**, **3 new PostgreSQL security integration tests**,
  and all **8 Day 1 acceptance scenarios**; no selected tests skipped.
* `uv build`: source distribution and wheel built. `git diff --check`: passed.
* No lifecycle edge, database schema, live feed, agent, production approval,
  executor, or Day 2 functionality was introduced.

Day 1 may close within its local/synthetic boundary: no open BLOCKER or HIGH
finding remains. Day 2 adapter development may proceed while preserving acceptance.
Satisfy F-01 before authoritative live conclusions, F-02 before agents/remote callers,
and F-03–F-05 before production changes. Future controls are not asserted to pass
tests before they exist.

This AI-assisted repository review is not a substitute for an independent professional
security audit. It is not comprehensive or guaranteed to find every vulnerability
and does not certify production readiness.
