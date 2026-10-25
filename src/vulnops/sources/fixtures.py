"""Offline adapters for the explicitly versioned synthetic Day 1 snapshots.

These are source-schema subsets, not complete OSV/CISA/FIRST implementations.
Source text and references are data; no URL or source instruction is executed.
"""

from datetime import date
from hashlib import sha256
import json
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid5

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, ValidationError, model_validator

from vulnops.domain.asset import Asset, AssetType, BusinessCriticality, Environment, InstalledComponent
from vulnops.domain.evidence import Evidence, EvidenceSource
from vulnops.domain.product import AffectedProduct, ProductIdentity
from vulnops.domain.version import VersionConstraint, VersionStatus
from vulnops.domain.vulnerability import CvssObservation, EpssObservation, KevObservation, Vulnerability
from vulnops.sources.base import SourceError, SourcedAsset, SourcedVulnerability


_NAMESPACE = UUID("052fd28b-b916-4b78-bc8d-df64439542de")


class _Input(BaseModel):
    model_config = ConfigDict(extra="ignore")


class _Manifest(_Input):
    schema_version: Literal["vulnops-lab/1"]
    synthetic: Literal[True]
    observed_at: AwareDatetime


class _Package(_Input):
    name: str
    ecosystem: Literal["PyPI"]
    purl: str
    vendor: str
    display_name: str

    def identity(self):
        return ProductIdentity(
            product=self.display_name, vendor=self.vendor, ecosystem="pypi",
            package_name=self.name, purl=self.purl,
        )


class _RangeEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None

    @model_validator(mode="after")
    def one_boundary(self):
        if sum(value is not None for value in (self.introduced, self.fixed, self.last_affected)) != 1:
            raise ValueError("A range event must declare exactly one supported boundary")
        return self


class _Range(_Input):
    type: str
    events: list[_RangeEvent]


class _Affected(_Input):
    package: _Package
    ranges: list[_Range] = Field(default_factory=list)
    versions: list[str] = Field(default_factory=list)


class _Severity(_Input):
    version: str
    base_score: float
    vector: str | None = None


class _Reference(_Input):
    url: str


class _Vulnerability(_Input):
    schema_version: Literal["osv-like/1"]
    id: str
    summary: str
    details: str
    published: AwareDatetime
    modified: AwareDatetime
    affected: list[_Affected]
    severity: list[_Severity] = Field(default_factory=list)
    references: list[_Reference] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)


def _read(root: Path, path: Path):
    try:
        path.resolve().relative_to(root.resolve())
        content = path.read_bytes()
        return json.loads(content), "sha256:" + sha256(content).hexdigest()
    except (OSError, ValueError) as error:
        raise SourceError("Fixture must be valid JSON inside its selected snapshot directory") from error


def _evidence(root, path, raw, digest, manifest, source_type, subject_type, subject_id, claim_type, published=None):
    relative = path.relative_to(root).as_posix()
    return Evidence(
        evidence_id=uuid5(_NAMESPACE, f"{relative}:{digest}:{subject_type}:{subject_id}:{claim_type}"),
        source_type=source_type, source_name=f"VulnOps synthetic {source_type.value} fixture",
        source_uri=f"fixture://vulnops-day1/{relative}", retrieved_at=manifest.observed_at,
        source_published_at=published, subject_type=subject_type, subject_id=subject_id,
        claim_type=claim_type, claim=json.dumps(raw, sort_keys=True), raw_payload_hash=digest,
        metadata={"synthetic": True, "fixture_path": relative},
    )


def _constraints(affected: _Affected):
    constraints = [VersionConstraint(exact_version=value, status=VersionStatus.AFFECTED) for value in affected.versions]
    for source_range in affected.ranges:
        scheme = "semver" if source_range.type == "SEMVER" else f"unsupported:{source_range.type}"
        start = None
        for event in source_range.events:
            if event.introduced is not None:
                if start is not None:
                    raise SourceError("Range has overlapping introduced events")
                start = event.introduced
            else:
                if start is None:
                    raise SourceError("Range closes without an introduced event")
                constraints.append(VersionConstraint(
                    introduced_version=start, fixed_version=event.fixed,
                    last_affected_version=event.last_affected, version_scheme=scheme,
                    status=VersionStatus.AFFECTED,
                ))
                start = None
        if start is not None:
            constraints.append(VersionConstraint(
                introduced_version=start, version_scheme=scheme, status=VersionStatus.AFFECTED,
            ))
        if not source_range.events:
            constraints.append(VersionConstraint(version_scheme=scheme))
    return constraints


class FixtureVulnerabilitySource:
    def __init__(self, fixture_root: Path):
        self.root = Path(fixture_root)

    def fetch(self) -> tuple[SourcedVulnerability, ...]:
        try:
            raw_manifest, _ = _read(self.root, self.root / "manifest.json")
            manifest = _Manifest.model_validate(raw_manifest)
            results = {}
            for path in sorted((self.root / "vulnerabilities").glob("*.json")):
                raw, digest = _read(self.root, path)
                record = _Vulnerability.model_validate(raw)
                cve_id = Vulnerability.validate_cve_id(record.id)
                if cve_id in results:
                    raise SourceError("Duplicate vulnerability identity in fixture snapshot")
                evidence = _evidence(self.root, path, raw, digest, manifest, EvidenceSource.CVE,
                                     "vulnerability", cve_id, "vulnerability_record", record.published)
                vulnerability = Vulnerability(
                    vulnerability_id=uuid5(_NAMESPACE, f"vulnerability:{cve_id}"), cve_id=cve_id,
                    title=record.summary, description=record.details, published_at=record.published,
                    updated_at=record.modified, cwe_ids=record.cwe_ids,
                    affected_products=[AffectedProduct(
                        product=item.package.identity(), version_constraints=_constraints(item),
                        evidence_ids=[evidence.evidence_id],
                    ) for item in record.affected],
                    cvss_observations=[CvssObservation(
                        version=item.version, base_score=item.base_score, vector=item.vector,
                        observed_at=manifest.observed_at, evidence_ids=[evidence.evidence_id],
                    ) for item in record.severity],
                    references=[reference.url for reference in record.references],
                    evidence_ids=[evidence.evidence_id], source_schema_version=record.schema_version,
                )
                results[cve_id] = (vulnerability, [evidence])
            if not results:
                raise SourceError("Snapshot contains no vulnerability fixtures")
            seen = set()
            for source_type, directory, key, cve_key in (
                (EvidenceSource.CISA_KEV, "kev", "vulnerabilities", "cveID"),
                (EvidenceSource.EPSS, "epss", "data", "cve"),
                (EvidenceSource.VENDOR, "vendor", "advisories", "cve_id"),
            ):
                for path in sorted((self.root / directory).glob("*.json")):
                    raw, digest = _read(self.root, path)
                    for item in raw[key]:
                        cve_id = Vulnerability.validate_cve_id(item[cve_key])
                        if cve_id not in results or (source_type, cve_id) in seen:
                            raise SourceError("Orphan or duplicate enrichment observation in snapshot")
                        seen.add((source_type, cve_id))
                        vulnerability, records = results[cve_id]
                        evidence = _evidence(self.root, path, item, digest, manifest, source_type,
                                             "vulnerability", cve_id, f"{directory}_observation")
                        if source_type is EvidenceSource.CISA_KEV:
                            vulnerability.kev_observation = KevObservation(
                                listed=True, date_added=date.fromisoformat(item["dateAdded"]),
                                observed_at=manifest.observed_at, evidence_ids=[evidence.evidence_id],
                            )
                        elif source_type is EvidenceSource.EPSS:
                            vulnerability.epss_observation = EpssObservation(
                                probability=float(item["epss"]), percentile=float(item["percentile"]),
                                score_date=date.fromisoformat(item["date"]), model_version=raw.get("model_version"),
                                observed_at=manifest.observed_at, evidence_ids=[evidence.evidence_id],
                            )
                        elif item["fixed_version"] is not None:
                            fixes = {constraint.fixed_version for product in vulnerability.affected_products for constraint in product.version_constraints}
                            if item["fixed_version"] not in fixes:
                                raise SourceError("Vendor fix conflicts with or is unrepresented by the vulnerability snapshot")
                        records.append(evidence)
                        vulnerability.evidence_ids.append(evidence.evidence_id)
            # Validate the complete batch before returning any canonical records.
            return tuple(SourcedVulnerability(
                Vulnerability.model_validate_json(vulnerability.model_dump_json()), tuple(evidence)
            ) for vulnerability, evidence in results.values())
        except (ValidationError, KeyError, TypeError, ValueError) as error:
            if isinstance(error, SourceError):
                raise
            raise SourceError("Fixture schema or canonical validation failed") from error


def load_fixture_inventory(inventory_root: Path) -> tuple[SourcedAsset, ...]:
    root = Path(inventory_root)
    path = root / "assets.json"
    raw, digest = _read(root, path)
    try:
        manifest = _Manifest.model_validate(raw)
        result = []
        identities = set()
        for record in raw["assets"]:
            external_id = record["external_id"]
            if external_id in identities:
                raise SourceError("Duplicate inventory identity in snapshot")
            identities.add(external_id)
            asset_id = uuid5(_NAMESPACE, f"asset:{external_id}")
            evidence = _evidence(root, path, record, digest, manifest, EvidenceSource.ASSET_INVENTORY,
                                 "asset", str(asset_id), "inventory_record")
            components = []
            installations = set()
            for component in record["components"]:
                installation = component["installation_id"]
                if installation in installations:
                    raise SourceError("Duplicate component installation identity")
                installations.add(installation)
                components.append(InstalledComponent(
                    component_id=uuid5(_NAMESPACE, f"component:{asset_id}:{installation}"),
                    asset_id=asset_id, identity=_Package.model_validate(component["package"]).identity(),
                    installed_version=component["version"], discovered_at=manifest.observed_at,
                    source="vulnops-lab-inventory", evidence_ids=[evidence.evidence_id],
                ))
            asset = Asset(
                asset_id=asset_id, external_id=external_id, hostname=record.get("hostname"),
                asset_type=AssetType(record["asset_type"]), environment=Environment(record["environment"]),
                business_service=record.get("business_service"), business_criticality=BusinessCriticality(record["business_criticality"]),
                internet_exposed=record.get("internet_exposed"), externally_reachable=record.get("externally_reachable"),
                data_classification=record.get("data_classification"), owner=record.get("owner"),
                components=components, evidence_ids=[evidence.evidence_id],
            )
            result.append(SourcedAsset(asset, (evidence,)))
        return tuple(result)
    except (ValidationError, KeyError, TypeError, ValueError) as error:
        if isinstance(error, SourceError):
            raise
        raise SourceError("Inventory fixture schema or canonical validation failed") from error
