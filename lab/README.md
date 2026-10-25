# Day 1 laboratory

All vulnerability and inventory records are synthetic. `CVE-2099-900001` through
`CVE-2099-900005` are fictional identifiers, not assigned CVEs. Package names,
advisories, ownership labels, and `.invalid` URLs are fictional. No external
vulnerability APIs are called. Do not add secrets or enterprise inventory here.

Run the offline adapter and component/product matcher from the repository root:

```bash
uv run --locked python lab/demo.py
uv run --locked pytest tests/sources tests/integration/test_fixture_ingestion.py -m 'not integration'
```

The demo prints deterministic pair assessments. It does not persist cases, change
lifecycle state, or infer an asset-wide conclusion from an unrelated component.
For the persisted walking skeleton, configure PostgreSQL as documented in the
root README and run `uv run --env-file .env vulnops demo`. That command selects
CVE-2099-900001, persists evidence, all six assets, four relevant cases, and twelve
legal transitions. It proves the affected, unaffected, and UNKNOWN →
MANUAL_INVESTIGATION scenarios and the blocked approval shortcut before printing
`DAY-1 ACCEPTANCE: PASS`. Exact replay preserves IDs and history. The inventory's
explicit completeness claim permits the fixed web asset's negative conclusion;
missing legacy versions still yield UNKNOWN. See
[ADR-011](../docs/decisions/ADR-011-persisted-day1-walking-skeleton.md).

| Asset | Context | Example assessment |
| --- | --- | --- |
| asset-web-01 | Production, public, critical | Lab Web 1.4.0: AFFECTED |
| asset-web-02 | Production, public, critical | Lab Web 2.0.0: NOT_AFFECTED |
| asset-api-01 | Production, internal | Lab API 3.2.0: AFFECTED; no known fix |
| asset-dev-01 | Development, internal | Web/API/Common components: AFFECTED |
| asset-db-01 | Production, internal, restricted | Lab Store 5.0.0: NOT_AFFECTED |
| asset-legacy-01 | Incomplete context and versions | Web/Legacy components: UNKNOWN |

Lab Common is shared by four assets with differing installed versions. Five
OSV-like files supply package identities, ranges or exact versions, and CVSS
observations. Separate KEV/EPSS/vendor files provide additional observations;
missing observations remain absent. The manifest fixes observation time for replay.
Inventory is a CMDB-like export, not a container scanner output. Adapters return
canonical domain objects and evidence with SHA-256 hashes of retained source files.
See [ADR-009](../docs/decisions/ADR-009-fixture-first-source-adapters.md).

The optional Docker lab runs six inert static HTTP stand-ins. Their logical VM,
container, application, repository, and managed-service types are inventory context;
these containers do not install those products or run vulnerable services.
Docker is not required for fixture loading or matching. The first run may download
the Python image. All containers run unprivileged and share an internal network.
The two web stand-ins additionally join a bridge network so Docker can publish
their loopback-only host ports. That bridge permits outbound traffic; the other
four stand-ins have only the internal network.

```bash
docker compose -f lab/docker-compose.yml config --quiet
docker compose -f lab/docker-compose.yml up -d --wait
curl http://127.0.0.1:18081
curl http://127.0.0.1:18082
docker compose -f lab/docker-compose.yml stop
```

This uses a separate `vulnops-lab` Compose project. PostgreSQL continues to use the
root `compose.yaml`; see the root README to start it and run the full database
integration suite. Fixture persistence tests save snapshots twice under a random
tenant and verify canonical round trips without duplicate assets or CVEs. Changed
snapshots require reconciliation rather than silently overwriting records.

Lab data and container definitions are excluded from the production wheel. The
production adapter loads an explicitly supplied directory; it does not import lab
scripts or implicitly ingest lab data.
