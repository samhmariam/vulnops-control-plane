# VulnOps V1 scope

Status: accepted boundary, 25 October 2026. This document defines the full V1 target;
it is not a claim that these capabilities have already been implemented.

## What V1 does

V1 will:

- Ingest vulnerability intelligence from explicitly supported sources.
- Normalise vulnerability information into validated, evidence-linked records.
- Correlate vulnerabilities to enterprise assets and their components.
- Determine **Affected / Not Affected / Unknown**, retaining supporting evidence;
  insufficient evidence must remain Unknown.
- Prioritise remediation using deterministic, explainable policy.
- Produce remediation plans for explicitly supported remediation operations.
- Validate remediation in a controlled sandbox before production mutation.
- Obtain human-in-the-loop (HITL) approval for production changes.
- Perform bounded remediation through constrained tools with explicit targets
  and operation limits.
- Verify remediation against recorded evidence and expected outcomes.
- Support rollback for the supported remediation paths.
- Audit the entire lifecycle, including evidence, decisions, approvals, execution,
  verification, and rollback.

Every material security conclusion must ultimately be traceable to evidence.
Models may assist analysis or drafting; deterministic policy and authorised human
decisions govern authoritative outcomes.

## What V1 does not do

- Exploit generation.
- Penetration testing.
- Arbitrary shell execution.
- LLM-generated production commands.
- Autonomous approval of production changes.
- Universal patching support.
- Social-media threat intelligence.
- Multi-agent swarms.
- Learned risk-scoring models.

Bounded remediation means implementing a small, explicitly supported set of
operations with validation, human approval, verification, and rollback. Unsupported
assets or operations cannot silently gain execution privileges. The initial target
platforms and operation catalogue require later decisions before implementation.

## Day 1 and Prompt 0 boundary

Day 1 targets only:

```text
Vulnerability -> normalisation -> enterprise asset -> component matching
              -> Affected / Not Affected / Unknown -> VulnerabilityCase
              -> controlled lifecycle -> audit trail
```

Prompt 0 establishes only the Python 3.12+, uv, Pydantic v2, pytest, and `src/`
foundation and its documentation. Subsequent prompts introduce the Day 1 domain.
Ingestion, orchestration, database infrastructure, deployment, and remediation
execution are not implemented by Prompt 0. LangGraph is not a dependency.

## Change control

Prefer the smallest implementation preserving the architecture. Do not introduce
infrastructure needed only by later days. Read ADRs before changes; record any
material reversal in a new ADR, including evidence, alternatives, trade-offs,
revisit conditions, and invariants to preserve. Acceptance gates must pass before
committing a prompt and starting the next one.
