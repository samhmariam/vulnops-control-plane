# ADR-002: Evidence as a first-class domain model

- Status: accepted
- Date: 25 October 2026
- Builds on: [ADR-001](ADR-001-core-architecture.md)
- Relevant constraints: [INV-01 through INV-05 and INV-08](../invariants.md)

## Context

VulnOps must distinguish what a source reported from what the system concluded.
External intelligence may be wrong, stale, incomplete, contradictory, or contain
malicious instructions. Model assistance makes attribution especially important:
plausible text cannot substitute for evidence. Evidence is an attributable
observation, not truth, a finding, an affectedness decision, or a risk score.

## Decision: first-class evidence

Introduce an independent `Evidence` domain object before scoring or AI reasoning.
Each observation has a UUID, source category and name, retrieval time, subject,
claim type, and claim text. Callers may supply a UUID to preserve identity across
serialization or replay; otherwise a new UUID is generated. Callers must supply
the actual retrieval time rather than silently substituting the current clock.
Publication time, source URI, raw payload hash, and confidence may be absent.

Source categories initially cover CVE, CISA KEV, EPSS, vendors, asset inventory,
SBOM, vulnerability scanners, humans, and the system. Subject and claim types stay
strings until later domain models establish their vocabulary. Internal observations
need not have a public URI. URI presence is optional for all categories; adapters
will later define source-specific provenance requirements. A URI is stored as data
and is never automatically fetched or treated as an instruction.

Evidence remains independent of orchestration, persistence, and external services.
Later findings and decisions should reference evidence IDs so multiple consumers
can use the same observation without duplicating it inside every asset or
vulnerability. Multiple records may disagree; this model preserves the disagreement
instead of silently choosing the most confident source.

## Why evidence, findings, and decisions are separate

The progression is **Evidence → Finding → Decision**. "Inventory reports version
1.2" records an observation. Interpreting that version against an advisory produces
a finding. Applying deterministic policy or authorised human judgement produces a
decision. These stages have different responsibilities and must remain traceable.

Embedding conclusions into source records would obscure which reasoning produced
an outcome, complicate conflict resolution, and make later reassessment harder.
Findings, decisions, risk evaluation, and affectedness are not implemented here.
Optional confidence records an observation's stated confidence in the inclusive
range 0–1. Even confidence 1.0 does not establish correctness, source trust, or risk.

## Validation boundary

Use Pydantic v2 with strict Python input types, forbidden extra top-level fields,
and assignment validation. UUIDs and enum instances must be supplied as their
Python types. JSON validation supports UUID, enum, and timestamp strings because
JSON has no native equivalents; invalid values still fail validation. Both
timestamps must be timezone-aware when supplied. Non-UTC offsets are allowed and
preserved. Confidence must be finite and within bounds.

Source-specific metadata is an extensible `dict[str, Any]` with an independent
empty default per record. Typed top-level fields carry the core contract; metadata
does not gain authority merely by being present. Source names and claims remain
strings without semantic interpretation or rewriting. This model validates shape,
not factual accuracy, evidence sufficiency, or whether a source exists.

Assignment validation does not provide deep immutability: callers can modify
nested metadata. This in-memory model is not an append-only audit store. Future
persistence must define evidence retention and correction semantics rather than
claiming that a mutable Python object establishes tamper resistance.

## Why retain or hash raw source material later

Normalisation can omit details needed to investigate a disagreement or reproduce
an assessment. Retaining source bytes would allow later inspection and replay.
A content hash can identify the exact bytes and detect changes when those bytes
are available, while allowing multiple records to refer to the same source material.

`raw_payload_hash` is an optional supplied string for now. This model neither
computes nor verifies hashes and does not impose an algorithm or payload
canonicalisation scheme. A hash alone cannot reconstruct a source or establish its
truth, and a URI alone may change or disappear. Before ingestion persists payloads,
decide the digest format and algorithm, byte representation, retention policy,
access controls, and sensitive-data handling. No payload store is introduced here.

## Alternatives considered

- Embed evidence directly inside vulnerabilities and assets: rejected because it
  duplicates observations and complicates references across sources and decisions.
- Put evidence in orchestrator state or model responses: rejected because it couples
  business provenance to execution context and probabilistic output.
- Build findings, risk scoring, RAG, embeddings, or vector storage now: deferred
  because this prompt needs only the provenance contract.

## Trade-offs accepted

Independent records introduce more IDs, references, and eventual joins. Future
persistence must enforce referential integrity, source retention, and deduplication;
generating a UUID is not deduplication. Strict validation requires adapters to
explicitly parse Python inputs. Open metadata and free-form subject/claim types
permit source evolution but require later source-specific validation. Optional
payload hashes and URIs mean this foundation does not yet guarantee full replay.

In return, independently attributable observations support auditability, shared
references, later replay, conflict detection, and future AI evaluation without
granting model output authority.

## When to reconsider

Revisit metadata and claim vocabularies when real sources show recurring structure
or ambiguity. Define raw-material retention and hashing when ingestion arrives.
Review correction, deduplication, referential integrity, and tenant isolation when
persistence is introduced. Reassess storage boundaries if measured volume makes
independent records impractical; preserve attribution and evidence/conclusion
separation. Any material reversal requires a new ADR rather than silently changing
ADR-001 or the system invariants.
