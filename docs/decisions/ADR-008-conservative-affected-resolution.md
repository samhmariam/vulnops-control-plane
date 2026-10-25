# ADR-008: Conservative deterministic affected resolution

- Status: accepted
- Date: 25 October 2026
- Builds on: ADR-001 through ADR-007 and [system invariants](../invariants.md)
- Refines: ADR-003's deferred comparison boundary with a tested, limited subset

## Context and decision

A false negative can tell operators that an asset is safe when it still needs
investigation or remediation. The consequence is more serious than sending an
uncertain candidate for manual review. Introduce deterministic product/version
matching returning AFFECTED, NOT_AFFECTED, or UNKNOWN with reasons and evidence.
Incomplete input, contradictory claims, and unsupported semantics remain UNKNOWN.
This intentionally accepts more investigation work and some conservative positives.

`resolve_affected` evaluates one InstalledComponent/AffectedProduct pair. It returns
candidate component/asset IDs, the matched product and component when identity
matches, identity status, reason, evidence UUIDs, matching method, version method,
and a certainty explanation. Evidence is deduplicated from both input records.
Inputs are revalidated as domain snapshots, and resolution has no side effects.
It does not compute risk, write cases, transition state, or claim an entire asset
is unaffected because one candidate pair is excluded. Asset-wide resolution needs
complete candidate/component coverage and handling of every unresolved pair later.

## Structured identity first

The priority is PURL, CPE, ecosystem/package identifier, then complete normalised
vendor/product names. Structured identifiers constrain package namespace, ecosystem,
or platform identity more precisely than display names. Priority selects the best
available comparable method; it must not erase a contradiction in another supplied
structured identifier.

- PURLs use the [reference Python parser](https://github.com/package-url/packageurl-python),
  with supported types pypi, npm, maven, cargo, nuget, golang, deb, rpm, and generic.
  Compare type, namespace, name, qualifiers, and subpath. Version is evaluated
  separately, never used to classify a different release as a different product.
  Qualifier/subpath disagreement, one-sided qualifier scope, malformed syntax,
  unsupported types, and wildcard identities remain UNKNOWN.
- CPE support is a restricted subset of literal formatted CPE 2.3 names, not a
  complete implementation of [NIST's CPE specifications](https://csrc.nist.gov/projects/security-content-automation-protocol/specifications/cpe).
  Require a known part (a/o/h), lowercase literal vendor and product, an optional
  literal version, and wildcard remaining attributes. Escaping, wildcard vendor or
  product, editions, target-specific attributes, and other bindings are unsupported.
  Do not silently discard such restrictions to obtain a broader match.
- Package fallback supports PyPI and npm, including scoped npm identifiers.
  PyPI names follow [PyPA's normalisation rules](https://packaging.python.org/en/latest/specifications/name-normalization/);
  npm identifiers use the supported lowercase literal subset. A simple unqualified
  PURL can supply the equivalent package key when the other source has only
  ecosystem/package fields. PURL/package or declared-ecosystem contradictions
  remain UNKNOWN. Other bare-package schemes require later explicit semantics.
- Vendor/product fallback requires both complete ASCII fields to agree after
  whitespace and case normalisation. It does not strip punctuation or editions,
  perform substring matching, or infer alias equivalence. Display-name mismatch
  and vendor-less names remain UNKNOWN. Name-based candidates can support an
  affected observation, but cannot justify a definitive version-based exclusion:
  a would-be NOT_AFFECTED result from this fallback remains UNKNOWN.

Different supported structured identities exclude only the supplied candidate
pair. Comparable identifiers that disagree about equality produce UNKNOWN even
if the higher-priority identifier matches. Concrete PURL/CPE version hints must
agree with the installed version; otherwise resolution is UNKNOWN. Cross-source
identifier translation, repackaging, forks, and alias registries are not inferred.
If a version-specific affected-product identifier names the installed release but
its affected range excludes that release, the scope conflict also remains UNKNOWN.
An explicit matching NOT_AFFECTED exemption does not create that contradiction.

## Supported version semantics

The [SemVer specification](https://semver.org/) defines normal releases as numeric
major/minor/patch components. The initial ordered subset requires the explicit
`version_scheme="semver"` and plain X.Y.Z releases with no leading zeroes.
Compare integer tuples, never arbitrary version strings. Prereleases, build
metadata, vendor suffixes, distribution epochs, abbreviated releases, and unknown
schemes remain unsupported for ordering. No scheme is guessed from the ecosystem
or the appearance of a version number.

Support exact versions; inclusive introduced and last-affected boundaries;
exclusive fixed boundaries; introduced-to-fixed ranges; introduced-only ranges;
and less-than-fixed ranges. Missing fixed version does not clear an affected
claim. A constraint with no boundaries is incomplete, not a claim about every
possible version. Mixed exact/range fields and contradictory/empty bounds remain
UNKNOWN. Unknown source status also remains UNKNOWN.

Without a declared scheme, identical non-placeholder opaque exact-version strings
can support an explicit source claim: equality needs no invented ordering.
Unequal opaque strings do not establish non-affectedness. A declared unsupported
scheme remains UNKNOWN even if an exact string happens to agree.

Multiple affected ranges form a union. Being outside one range does not cancel a
positive match in another. An unsupported or incomplete range prevents a negative
conclusion; a supported positive can still establish conservative affectedness.
An explicit NOT_AFFECTED claim overlapping a positive claim yields UNKNOWN rather
than choosing the more convenient source. Outside an exemption is UNKNOWN, not
proof of affectedness. NOT_AFFECTED requires every supplied constraint to support
that conclusion and sufficiently structured identity.

These results are conditional on the supplied source claims and boundaries. They
do not prove source truth, freshness, authenticity, or completeness. Application
policy and persistence must still resolve and assess the referenced Evidence.
No numerical confidence score is used to resolve uncertainty.

## Why LLM matching is deferred

Embeddings, fuzzy similarity, and model judgement can propose plausible links that
are wrong in hard-to-reproduce ways. They do not establish product equivalence,
version ordering, or safe exclusions. They are unnecessary for the supported
fixtures and are not dependencies of authoritative matching or state.

Later, probabilistic tools might rank UNKNOWN candidates, suggest aliases, find
vendor documentation, or explain evidence to a human. Those suggestions must
remain advisory. A human or deterministic adapter must establish an attributable
mapping; a high model confidence must never turn UNKNOWN into AFFECTED or
NOT_AFFECTED by itself (INV-05).

## Alternatives, trade-offs, and revisit conditions

Reject universal string ordering, inferred ecosystem semantics, dropping qualifiers,
fuzzy names as proof, highest-confidence conflict resolution, and treating one
excluded pair as an asset-wide safety decision. Accept narrow coverage, one small
PURL parsing dependency, and more UNKNOWN results for reviewable decisions.

Tests cover identifier priority and conflict, package/name fallbacks, numeric
boundaries, known fixes, unknown versions, unsupported schemes, disjoint ranges,
explicit contradictions, and evidence traceability. Existing ADR decisions remain
unchanged beyond introducing this explicit tested comparison subset.

Revisit CPE/PURL coverage and ecosystem version rules only with concrete fixtures
and source semantics; alias translation with reviewed mapping evidence; and
asset-wide aggregation with inventory completeness rules. Revisit probabilistic
assistance only with a human review boundary and evaluation evidence. Preserve
UNKNOWN, evidence traceability, and deterministic enforcement through any change.
