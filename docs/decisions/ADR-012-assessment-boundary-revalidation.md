# ADR-012: Revalidate assessment snapshots and reject blank attribution

Status: Accepted

Date: 2026-10-25

Refines: ADR-002's attribution validation and implements ADR-004's requirement to
revalidate mutable nested snapshots at application boundaries. No lifecycle edge,
matching semantics, source-trust policy, or production capability is added.

## Evidence and decision

The Day 1 security review reproduced an affected asset being assessed as
NOT_AFFECTED after its mutable component list was replaced with another asset's
fixed components. InstalledComponent validation alone cannot verify the containing
asset relationship. The current demo loads valid source snapshots and repository
saves already revalidate Asset, so no remote exploit or persisted demo corruption
was demonstrated. The public assessment boundary nonetheless violated INV-10 and
ADR-004's explicit ownership rule.

Revalidate complete Vulnerability, Asset, and Evidence snapshots at assess_asset
entry using JSON round trips, consistent with the existing matcher/repository
boundaries. This catches cross-asset list replacement, nested provenance removal,
and invalid trusted-copy snapshots before a conclusion is returned. Conflicting
content for one evidence UUID is rejected rather than resolved by list order.

Required evidence source, subject, claim-type, and claim strings must contain
non-whitespace content. Optional source_uri and raw_payload_hash remain optional;
when supplied, they cannot be blank. Preserve nonblank source strings verbatim,
including instruction-like text, without executing or rewriting them. Confidence
remains advisory. We do not invent provenance, mandate public URLs for internal
observations, or pretend that nonblank attribution proves authenticity/suitability.

## Alternatives and trade-offs

Reject relying on earlier model construction, validating only individual
components, silently dropping foreign components, and treating whitespace as
attributable provenance. Deep-freezing every source model would be a wider
compatibility change; database-only validation is too late for callers of the
assessment service. Accept additional serialization work for the small Day 1 batch
and fail-closed validation of previously malformed snapshots.

Existing stored evidence with blank required fields now fails validation when
read. No invalid records are rewritten or assigned fabricated sources; operators
must reconcile such records explicitly. Reviewed lab evidence is already valid,
so fixture identities, histories, and exact replay remain unchanged.

## Revisit conditions and invariants

Revisit immutable source snapshot types or versioned finding/input digests when
volume or concurrent consumers justify them. Source authentication, freshness,
claim suitability, authenticated actors, immutable action-bound approvals, and a
global mutation kill switch remain future boundaries documented in the security
review; string validation is not a substitute.

Preserve INV-01 through INV-05 and INV-10: source content remains data; findings
remain attributable; ambiguity stays UNKNOWN; and one asset's components cannot
establish another asset's status. Regression tests exercise actual foreign-list
replacement, nested provenance clearing, conflicting evidence identities, and
blank attribution without inspecting private implementation structure.
