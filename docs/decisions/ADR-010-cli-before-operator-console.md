# ADR-010: CLI before an operator console

Status: Accepted

Date: 2026-10-25

## Context and decision

The Day 1 walking skeleton needs a repeatable way to inspect canonical records,
installed components, affected assessments, and lifecycle history. A web frontend
would add hosting, browser state, authentication flows, API design, and visual work
before those workflows are established. Use a Python console entry point,
`vulnops`, implemented with standard-library argparse. No frontend, FastAPI, agent
framework, or new dependency is needed. ADRs 001–009 remain in force.

## Application boundary

CLI handlers parse arguments, dispatch to application operations, serialize JSON,
and translate failures to exit codes. InspectionService validates pagination and
CVE identifiers, distinguishes a missing case from an empty history, and reads
domain snapshots through an InspectionRepository protocol. SQLAlchemy stays in
persistence and the composition module; business use cases import no ORM types.
Another interface can call the same service without copying rules from commands.

Repository queries explicitly filter tenant IDs as well as using existing forced
RLS. Asset listing batches installed components into one additional query rather
than issuing a query per asset. Asset and case lists use deterministic UUID order
with bounded limit/offset pagination (default 100, maximum 1000). History preserves
the repository's event sequence order. Commands expose full domain JSON, retaining
component evidence IDs, case status evidence IDs, and every transition's actor,
reason, evidence, correlation ID, and timestamp. UUID input is required for asset
and case lookup; vulnerability lookup uses the canonical CVE syntax.

Database commands require an explicit tenant UUID, from `--tenant-id` or
`VULNOPS_TENANT_ID`. DATABASE_URL supplies the restricted runtime connection;
credentials are not command-line arguments. Each invocation opens one tenant
transaction and disposes its engine. No schema migration, state transition, record
creation, approval, execution, or fixture seeding occurs implicitly on inspection.

This is a local trusted-operator interface. Tenant selection is not authentication
or proof of membership. Existing application credentials can select tenant context,
as documented in ADR-007. Do not expose this executable as a shared remote service
until tenant context comes from authenticated authority. Cross-tenant tests cover
the new reads, including identical missing-record responses for hidden records.

## Offline demo and presentation

`vulnops demo --lab-dir <path>` invokes an application use case that loads the Day 1
snapshots and evaluates component/product pairs. It returns the six assets, five
vulnerabilities, twelve candidate assessments, and their Evidence. Its report is
explicitly synthetic and not persisted. Different structured products are omitted
from the candidate display, not interpreted as proof that an asset is safe.
No asset-wide aggregation or authoritative case write is introduced; those need
the inventory-completeness policy deferred in ADR-008. Database inspection commands
display existing stored cases and history; running the demo does not seed them.
The older lab demo now uses this same application operation.

JSON is sufficient for both human inspection and shell pipelines. It escapes
terminal controls in untrusted source strings and preserves UNKNOWN and null
values. Connection exceptions and validation failures produce concise messages
without printing credentials, SQL, raw source payloads, or tracebacks. Exit codes:
0 success, 1 database/source failure, 2 usage/configuration/input error, 3 record
not found in the selected tenant. Successful empty lists or histories return 0.

## Alternatives and accepted trade-offs

* A web console now: deferred because read-only inspection needs no browser UI;
  access control, deployment, and frontend state would expand Day 1 scope.
* Direct SQL in CLI handlers: rejected because it couples presentation to storage
  and encourages tenant or validation rules to diverge between interfaces.
* Click/Typer: useful later, but argparse covers this small command tree without
  another dependency.
* Implicit demo seeding: rejected because a demonstration should not silently
  change authoritative data or choose a tenant. An explicit ingestion command can
  later use a tenant transaction and reviewed reconciliation/assessment policies.

Accept verbose JSON, per-command connection setup, offset pagination, manual tenant
configuration, and fixtures available only from an explicitly selected checkout.
The production wheel includes services and CLI but not lab data. Fresh databases
have empty lists until an explicit application integration saves records. The CLI
is not a production identity, approval, ingestion, or mutation service.

## Revisit conditions and invariants

Build an operator console when humans need multi-user assignment, frequent filtering
and comparison, evidence drill-down, approval queues, or a coordinated incident
view that CLI workflows cannot support. First establish authenticated tenant scope,
roles, and audited application commands. Revisit JSON output versioning for external
consumers, keyset pagination for measured scale, richer evidence inspection for
operator needs, and connection reuse for a long-running interface.

Preserve evidence references and UNKNOWN in every presentation; never grant source
text or model output instruction authority. New mutation commands must enforce
deterministic lifecycle policy, human production approval, and atomic state/audit
writes outside the interface. CLI convenience cannot bypass INV-01–INV-10.
