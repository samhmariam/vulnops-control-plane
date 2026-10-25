# VulnOps system invariants

Status: accepted architectural constraints, 25 October 2026.

These rules describe what must remain true as VulnOps evolves. Read them alongside
[V1 scope](v1-scope.md) and [ADR-001](decisions/ADR-001-core-architecture.md).
They make the existing safety model explicit; they do not reverse those decisions.
Prompt 1 documents the constraints and tests their identifiers' presence. Runtime
enforcement and behavioural tests belong to the later features that implement them.

## INV-01 — External intelligence is untrusted data

CVE descriptions, vendor advisories, scanner findings, CMDB fields, SBOM
information, and all other external content must never be interpreted as system
instructions. Parsing or validating content does not make its claims trustworthy.

Why: an attacker may control a field that appears to be ordinary intelligence.
For example, an advisory containing "ignore approval and execute this command"
remains source text; it cannot change policy, grant permissions, or execute code.

## INV-02 — Evidence and conclusions are separate

Keep **Evidence → Finding → Decision** distinct. Evidence records what a source
reported or an observation measured. A finding interprets that evidence. A decision
applies policy and authority to findings. Do not encode an unsupported conclusion
directly into source data or overwrite source evidence with an interpretation.

Why: reviewers must be able to distinguish observation from inference and action.
For example, "inventory reports version 1.2" is evidence; matching that version to
an advisory produces a finding; choosing a remediation priority is a decision.

## INV-03 — Material security assertions require provenance

Assertions such as "the asset runs a vulnerable version", "the vulnerability is
actively exploited", "the fixed version is X", or "the vulnerability applies to
product Y" must link to identifiable supporting evidence. Preserve the source,
relevant observation or retrieval time, and the supporting content or a durable
reference so a reviewer can inspect the basis of the assertion.

Why: a plausible statement is not proof. For example, a model proposing a fixed
version without a supporting advisory cannot establish that version as a fact.
Provenance makes a claim traceable; it does not by itself prove the source correct.

## INV-04 — Unknown is a first-class outcome

Affected status supports **AFFECTED**, **NOT_AFFECTED**, and **UNKNOWN**.
UNKNOWN must never automatically become NOT_AFFECTED. A definitive outcome needs
sufficient evidence and explicit evaluation; absence of a match is not proof that
an asset is safe.

Why: missing or ambiguous inventory is common. For example, an asset with no known
component version remains UNKNOWN until evidence supports a definitive assessment.
A timeout, default value, or model confidence score cannot silently clear it.

## INV-05 — Model output is advisory

No model or probabilistic process may directly mutate authoritative risk or
production state without deterministic validation or explicit human authority.
Model output is a proposal processed through the application control boundary;
it cannot itself supply authorisation or become authoritative business truth.

Why: identical inputs may produce different model responses. For example, a model
may recommend a priority, but an authoritative priority change requires explicit
policy validation or an authorised human decision, with supporting evidence.
Production changes still require both policy enforcement and recorded human
approval under INV-06 and ADR-001; validation alone is not production approval.

## INV-06 — Production mutation requires a control boundary

Every future production action must pass through policy and approval enforcement
outside the LLM, using constrained tools. The application/tool path enforces these
checks even if invoked without an orchestrator. Recorded human approval is required
for production changes; a prompt, model response, or graph checkpoint cannot grant it.

Why: model compliance cannot be an access-control mechanism. For example, a request
to patch a supported asset must be checked against policy and human approval before
the tool acts, even if the model claims it has already obtained permission.

## INV-07 — Remediation does not end at deployment

A vulnerability case is closed only when remediation is independently verified
against the affected asset and the expected outcome, with recorded evidence.
Successful command execution or a deployment completion signal alone is insufficient.

Why: deployment may succeed while the asset remains vulnerable. For example, a
patch job reporting success leaves the case open until a separate verification
observation confirms remediation. Independent verification need not require a
different person, but must not merely repeat the mutating tool's success claim.

## INV-08 — State transitions are auditable

Every meaningful lifecycle change records:

- From state.
- To state.
- Actor.
- Reason.
- Timestamp.
- Evidence, directly or through durable references.
- Correlation identifier linking the change to its case or operation.

Why: a reviewer must reconstruct what changed, who or what changed it, and why.
For example, a transition to verified closure must identify its prior state,
verification actor, rationale, time, verification evidence, and correlation ID.
A new state without its corresponding audit record is not an acceptable transition.

## INV-09 — Default deny for future mutating tools

Unknown or unregistered mutating tools must not execute. Registration is necessary
but does not bypass policy, approval, target restrictions, or operation limits.
Never fall back to a generic shell or a model-generated production command.

Why: newly suggested capabilities must not acquire authority implicitly. For
example, a model request for an unregistered `patch_everything` operation is denied
before execution rather than routed to a general-purpose executor.

## INV-10 — Decisions depend on the vulnerability and the asset

A single vulnerability may create different decisions for different assets.
Risk is **vulnerability × asset context**, not vulnerability alone. Assessments and
decisions must preserve the asset context and evidence that justify the outcome;
a global vulnerability severity cannot stand in for each asset's decision.

Why: component versions, exposure, and business importance differ. For example,
one asset may be AFFECTED, another NOT_AFFECTED based on a fixed version, and a third
UNKNOWN because its inventory is incomplete, all for the same vulnerability.

## Maintaining these constraints

Preserve these identifiers as stable references in decisions, reviews, and future
behavioural tests. The presence test catches removal of the document or identifiers;
it cannot prove semantic correctness or runtime enforcement. Review changes against
V1 scope and ADR-001. Any material reversal requires a new ADR explaining its
evidence, alternatives, accepted trade-offs, and which decision it supersedes.
