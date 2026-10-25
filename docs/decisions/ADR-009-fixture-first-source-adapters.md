# ADR-009: Fixture-first source adapters and a six-asset laboratory

Status: Accepted

Date: 2026-10-25

## Context

ADRs 001–008 establish independent domain models, attributable evidence,
tenant-scoped storage, and conservative matching. Day 1 needs reproducible inputs
before feed availability, authentication, rate limits, schema drift, and changing
vulnerability records complicate diagnosis.

## Decision

`VulnerabilitySource.fetch()` returns canonical Vulnerabilities together with their
Evidence. The protocol owns no database session or lifecycle state. The fixture
implementation adapts an explicitly versioned OSV-like subset and separate
KEV-, EPSS-, and vendor-like records. These are illustrative source formats, not
complete implementations of upstream specifications. Inventory has a separate
adapter returning Assets, InstalledComponents, and Evidence.

Five fictional CVE-shaped identifiers and fictional PyPI package identities cover
fixed, affected, unknown, shared components, and unavailable fixes. Six inventory
assets vary environment, exposure, criticality, technology category, and version
completeness. Their Docker containers serve inert static pages; simulated component
versions exist in inventory, not in the images. No vulnerable software is deployed.

Live feeds are deliberately postponed. Fixture loading performs no network calls,
follows no advisory URLs, executes no source instructions, and makes no lifecycle
changes. An absent observation is not a negative finding. Unsupported version
semantics remain explicit and resolve UNKNOWN through the existing matcher.

Canonical identities use deterministic UUIDs. Evidence identifies the source
snapshot, subject, and claim, and hashes the exact retained file bytes with SHA-256
(`sha256:<hex>`). A fixed, timezone-aware observation time makes replay stable
across processes and checkout locations. Enrichment records retain their own
provenance instead of inheriting the base vulnerability's evidence. The Evidence
claim is parsed JSON text; the hash is of the original file, not that serialization.
Several observations may share a source-file hash. Changed bytes create new
evidence; hashes establish content identity, not trust or authenticity. Raw fixture
files remain in the repository. This refines ADR-002's retention intent without
introducing a production raw-payload store.

The adapter validates the whole batch before returning it. Duplicate identities,
orphan/duplicate enrichment, malformed records, and conflicting vendor fixes raise
SourceError. Additive raw fields remain in evidence without changing domain logic.
Unknown range-event fields are rejected to prevent silently dropping a
security-relevant boundary. No probabilistic matching or risk score is introduced.

## Alternatives considered

* Live feeds immediately: current records, but network and upstream changes would
  obscure failures in matching and provenance.
* Canonical-model JSON fixtures: simpler, but bypasses the translation boundary
  future integrations need to exercise.
* Real vulnerable images: useful later for remediation validation, but unnecessary
  exposure and maintenance for Day 1 domain contracts.
* Domain logic coupled to source DTOs: less adapter code, but source schema changes
  would propagate into matching, persistence, and policy.

## Trade-offs and consequences

This small lab validates architecture, not ecosystem coverage or real remediation.
Schemas, supported versions, and observation time are deliberately narrow and static.
The adapter materializes a small batch; no pagination, scheduling, retries, or
streaming guarantees exist. Container tags can change; the first Docker run may
download an image. Fixture ingestion needs neither Docker nor network access.
Only web stand-ins bind host ports, on loopback; all six share an internal Docker
network and use unprivileged read-only containers. The two web stand-ins also join
a bridge network for published-port connectivity; this permits their outbound
traffic. The four remaining stand-ins have only the internal network. Docker's
internal-only network did not publish the web port bindings during validation.

Exact replay uses existing repository idempotency. Changed snapshots require
explicit reconciliation; adapters cannot overwrite earlier authoritative records.
Batch validation does not replace a tenant transaction when persisting records.
Pair resolution does not declare an entire asset safe, create cases, or advance
lifecycle state. Lab data remains outside the production wheel.

## Day 2 and reconsideration

A live adapter can implement the same protocol, translate its external schema, and
return canonical observations plus Evidence. Downstream matching and repositories
continue consuming the same domain types. Day 2 must add source-specific validation,
raw-payload retention, observation clocks, refresh reconciliation, authentication,
timeouts, and rate-limit handling at the source/application boundaries.

Revisit batching for feed volume; identity for cross-source deduplication; retention
for legal/privacy requirements; and fixture coverage for new ecosystems or version
schemes. Add real remediation targets when sandbox execution and isolation controls
exist. Preserve INV-01–INV-05 and INV-10: external content stays data, observations
remain attributable, missing knowledge stays UNKNOWN, and authoritative conclusions
remain deterministic and asset-specific.
