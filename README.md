# VulnOps control plane

VulnOps will connect vulnerability evidence to controlled, auditable remediation.
This repository currently contains the Prompt 0 foundation: an installable Python
package, a packaging smoke test, and the V1 architectural boundary. It does not
yet ingest vulnerabilities, run agents, persist business state, or remediate assets.

Use Python 3.12+ and uv. The default local interpreter is Python 3.12.

```bash
uv sync --locked
uv run --locked python -c "import vulnops; print('VulnOps imports successfully')"
uv run --locked pytest
uv build
```

Pydantic v2 is the only runtime dependency, reserved for explicit data contracts
in subsequent prompts. pytest is a development dependency. Commit `uv.lock` to
keep installations reproducible; update it deliberately when changing dependencies.

## Layout

- `src/vulnops/`: framework-independent domain/application package.
- `tests/`: automated behaviour and packaging tests.
- `lab/`: isolated future experiments; excluded from the production package.
- `docs/`: scope, evidence, and architecture.
- `docs/decisions/`: architectural decision records (ADRs).

Read [V1 scope](docs/v1-scope.md), [ADR-001](docs/decisions/ADR-001-core-architecture.md),
and [reference inspection notes](docs/reference-notes.md) before extending the system.

## Implementation workflow

Execute prompts sequentially: inspect current code, ADRs and invariants; implement;
test; explain architectural choices; pass the acceptance gate; commit; then proceed
to the next supplied prompt. Fix a failed gate before continuing. A material change
to an accepted decision requires a new ADR explaining why it supersedes that decision.
