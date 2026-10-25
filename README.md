# VulnOps control plane

VulnOps will connect vulnerability evidence to controlled, auditable remediation.
This repository currently contains the Python foundation, documented system
invariants, and validated Evidence, Vulnerability, ProductIdentity, and
VersionConstraint domain models, minimal Asset and InstalledComponent context,
and evidence-backed VulnerabilityCase snapshots, with tests. It does not yet ingest
vulnerabilities, run agents, persist business state, or remediate assets.

Use Python 3.12+ and uv. The default local interpreter is Python 3.12.

```bash
uv sync --locked
uv run --locked python -c "import vulnops; print('VulnOps imports successfully')"
uv run --locked pytest
uv build
```

Pydantic v2 is the only runtime dependency and validates the domain contracts.
pytest is a development dependency. Commit `uv.lock` to
keep installations reproducible; update it deliberately when changing dependencies.

## Layout

- `src/vulnops/`: framework-independent domain/application package.
- `tests/`: automated behaviour and packaging tests.
- `lab/`: isolated future experiments; excluded from the production package.
- `docs/`: scope, evidence, and architecture.
- `docs/decisions/`: architectural decision records (ADRs).

Read [V1 scope](docs/v1-scope.md), [system invariants](docs/invariants.md),
[ADR-001](docs/decisions/ADR-001-core-architecture.md), and
[reference inspection notes](docs/reference-notes.md) before extending the system.
The [Evidence design](docs/decisions/ADR-002-evidence-first-domain-model.md) explains
the first domain object and the distinction between observations and conclusions.
The [canonical vulnerability design](docs/decisions/ADR-003-canonical-vulnerability-model.md)
explains product identity, descriptive version constraints, and separate source
observations without an aggregate risk score.
The [enterprise asset design](docs/decisions/ADR-004-minimal-enterprise-asset-model.md)
defines the boundary with upstream inventory and separates components from asset
exposure and business context.
The [case granularity design](docs/decisions/ADR-005-vulnerability-case-granularity.md)
defines one operational case per vulnerability/asset pair and its evidence boundary.

## Implementation workflow

Execute prompts sequentially: inspect current code, ADRs and invariants; implement;
test; explain architectural choices; pass the acceptance gate; commit; then proceed
to the next supplied prompt. Fix a failed gate before continuing. A material change
to an accepted decision requires a new ADR explaining why it supersedes that decision.
