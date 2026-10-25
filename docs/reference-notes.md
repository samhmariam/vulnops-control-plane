# Architectural reference inspection

Inspected on 25 October 2026 through the GitHub connector. No repository was merged,
and no reference code or runtime dependencies were copied. These are selected
architectural examples, not a security audit of the reference repositories.

## Agentic AI Ops Engineer

Snapshot: `136730b1c8d2052f76169db0042b00a1298feb6c`.

The root README was empty. Inspected the repository tree and the
[RealThor HITL README](https://github.com/samhmariam/agentic-ai-ops-engineer/blob/136730b1c8d2052f76169db0042b00a1298feb6c/module-03-agentops-deploy-guard-monitor-agents/exercises/06-HITL/README.md)
and [tools module](https://github.com/samhmariam/agentic-ai-ops-engineer/blob/136730b1c8d2052f76169db0042b00a1298feb6c/module-03-agentops-deploy-guard-monitor-agents/exercises/06-HITL/src/realthor/tools.py).

The README separates pure Python policy from middleware and actions. VulnOps adopts
that separation of concerns. Its eventual application/tool boundary must enforce
approval even when invoked without an orchestrator. We do not adopt the example's
agent substructure, in-memory checkpoint authority, JSONL business persistence, or
dynamic Python execution tool. Those mechanisms do not meet this V1 boundary.

## Udacity AI Security Engineer

Snapshot: `a745dc0f9cf5574f772799919ac3def39d75078e`.

Inspected the repository tree, root README, the
[Northstar Assist project README](https://github.com/samhmariam/udacity-ai-security-engineer/blob/a745dc0f9cf5574f772799919ac3def39d75078e/01-ai-threat-modeling/project/README.md),
and the [named guardrail example](https://github.com/samhmariam/udacity-ai-security-engineer/blob/a745dc0f9cf5574f772799919ac3def39d75078e/03-adversarial-robustness/exercises/11-aria-named-guardrails/demo/aria_fixed.py).

Northstar's documentation links controls to evaluation evidence, residual risks,
and rollback procedures. VulnOps carries forward evidence traceability and explicit
trust boundaries. The guardrail example illustrates clearly named restrictions;
VulnOps documents named invariants but requires deterministic enforcement rather
than relying on a model obeying prompts. No Bedrock, RAG, red-team workflow, or
cloud deployment machinery is imported into the foundation.

## Result

These observations inform ADR-001. Later implementation must add its own tests and
evidence; reference claims or course test results cannot establish VulnOps safety.
