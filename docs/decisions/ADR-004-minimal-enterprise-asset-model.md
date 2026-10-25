# ADR-004: Minimal enterprise assets and installed components

- Status: accepted
- Date: 25 October 2026
- Builds on: ADR-001, ADR-002, and ADR-003
- Preserves: [system invariants](../invariants.md), especially INV-01 through
  INV-04 and INV-10

## Context and decision

Vulnerability sources describe products and version claims. Enterprise risk also
needs the context of the resources an organisation actually runs. Introduce a
small `Asset` model and separate `InstalledComponent` observations, reusing
`ProductIdentity`. This is a domain contract, not an inventory connector, component
matcher, CMDB, risk engine, or persistence implementation. Earlier ADRs remain
unchanged.

## Why VulnOps is not a CMDB

VulnOps consumes the attributes needed for affectedness, exposure, business impact,
and remediation. Assets carry an internal UUID, optional upstream external ID and
hostname, type, environment, service, criticality, exposure flags, classification,
owner, components, and evidence references. A repository or managed service need
not have a hostname. External IDs are opaque upstream identifiers, not globally
unique enterprise identities; future integrations must namespace them appropriately.

Procurement, hardware specifications, billing, full relationship graphs, location,
and other general inventory fields remain upstream. Rejecting extra fields prevents
upstream schemas from silently growing the domain. We accept adapter mapping and
some duplicated context snapshots in return for a smaller schema and a clear
responsibility boundary.

## Why installed components are separate

One asset may run multiple products, versions, or installations of the same product.
Each component therefore has its own UUID and links to one asset UUID. It retains
product identity, optional installed version, timezone-aware discovery time, source
system name, and nonempty UUID evidence references. `source` identifies the collector
or upstream system; its Evidence records carry the source category and full
provenance. Version strings remain descriptive under ADR-003.

This separation supports the future join from AffectedProduct through component
identity and version to asset context without duplicating the whole asset on every
component. Missing versions remain `None`, not a safe or patched version. An empty
component list is not proof of complete inventory or an unaffected asset.

Assets reject nested components referencing a different asset during construction
and component-list assignment. Asset UUIDs, component UUIDs, and component asset
references are fixed after construction to avoid silently reparenting observations.
As in earlier models, mutable nested lists are not deeply protected: in-place list
edits bypass assignment validation. Later application boundaries must revalidate
snapshots and enforce audit and persistence integrity before authoritative decisions.

## Why business criticality belongs on the asset

Criticality describes the business consequence of losing this resource or service,
not a vulnerability's intrinsic severity. A production payroll system and a test
instance can run the same component but have different impact. Business owners or
the upstream inventory provide this context; the domain does not infer it from
CVSS, hostnames, environment, or model judgement.

The initial vocabulary is CRITICAL, HIGH, MEDIUM, LOW, and UNKNOWN. It is categorical,
not a numeric risk score or priority. Unmapped or absent criticality must remain
UNKNOWN until an adapter has an explicit supported mapping. Owner, service, and
data-classification fields remain upstream strings because enterprise taxonomies
and team identifiers differ. Owner is a reference or label, not approval authority.

## Why exposure belongs to asset context

The same CVE may affect both public and isolated resources. Exposure therefore
belongs to an asset/context snapshot, not the vulnerability. `internet_exposed`
records reported public Internet exposure. `externally_reachable` records reported
reachability from outside the organisation's trusted internal boundary, which may
include partner or private external connectivity. Adapters must document which
boundary and evidence support their mapping; these fields do not describe every
network path or every component's exposure.

Both flags are strict booleans or `None`. None means unknown and must never be
treated as False. They are independent reported claims; this model does not infer
one from the other, resolve disagreements, scan networks, or declare an asset safe.
Environment explicitly supports PRODUCTION, STAGING, DEVELOPMENT, TEST, and UNKNOWN
and defaults to UNKNOWN. Asset types initially cover VM, CONTAINER, APPLICATION,
REPOSITORY, and MANAGED_SERVICE.

## Upstream authority and evidence

CMDB/inventory systems remain authoritative for their inventory identifiers and
managed context; business/service owners remain authoritative for criticality and
classification; supported scanners, SBOM sources, and discovery tools supply
component observations and exposure evidence. They can be stale or disagree, and
their content remains untrusted input. Being a designated source of record does not
turn a claim into proven truth or permit source text to become instructions.

Nonempty evidence UUID lists are required for assets and components. They attribute
claims but do not prove the referenced records exist or support those claims. Future
adapters and application policy must resolve provenance, establish freshness, and
handle conflicts. VulnOps will own its cases, decisions, approvals, and audit state
in PostgreSQL per ADR-001; it will not silently rewrite upstream inventory truth.

## Alternatives, trade-offs, and review triggers

Reject building a replacement CMDB, attaching enterprise exposure to a global CVE,
flattening installed products into display names, or defaulting missing context
to low impact or no exposure. Accept a limited context snapshot, additional UUID
references, and later reconciliation work. Strict types and forbidden extra fields
require explicit adapter conversion. No storage, network discovery, auth system,
tenant-scoped database table, or connector is introduced here.

Revisit context freshness and per-field provenance when integrating real upstream
systems; source namespacing and tenant isolation when introducing persistence;
criticality mappings when supported enterprise taxonomies are known; and exposure
granularity when remediation requires component- or path-specific reachability.
Add fields only for a demonstrated affectedness or remediation need. Preserve the
UNKNOWN outcome, evidence traceability, and separation of vulnerability and asset
context; record any material reversal in a new ADR.
