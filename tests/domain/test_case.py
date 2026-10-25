"""Cases isolate one vulnerability's assessments across enterprise assets."""

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from vulnops.domain.asset import Asset, AssetType, Environment
from vulnops.domain.case import AffectedStatus, CaseExposure, CaseState, VulnerabilityCase
from vulnops.domain.evidence import Evidence, EvidenceSource
from vulnops.domain.vulnerability import Vulnerability


CREATED_AT = datetime(2026, 10, 25, 11, 0, tzinfo=timezone.utc)


@pytest.fixture
def case_fields():
    return {
        "vulnerability_id": uuid4(),
        "cve_id": "CVE-2026-12345",
        "asset_id": uuid4(),
        "created_at": CREATED_AT,
        "updated_at": CREATED_AT,
    }


def test_same_cve_has_four_independent_enterprise_cases():
    vulnerability = Vulnerability(
        cve_id="CVE-2026-12345",
        title="Example product vulnerability",
        description="A source reports vulnerable versions.",
        evidence_ids=[uuid4()],
    )
    scenarios = [
        (Environment.PRODUCTION, True, AffectedStatus.AFFECTED),
        (Environment.DEVELOPMENT, False, AffectedStatus.AFFECTED),
        (Environment.PRODUCTION, False, AffectedStatus.NOT_AFFECTED),
        (Environment.UNKNOWN, None, AffectedStatus.UNKNOWN),
    ]
    cases = []
    assets = []
    assessments = []
    for environment, exposed, status in scenarios:
        asset = Asset(
            asset_type=AssetType.APPLICATION,
            environment=environment,
            internet_exposed=exposed,
            evidence_ids=[uuid4()],
        )
        assessment = Evidence(
            source_type=EvidenceSource.SYSTEM,
            source_name="deterministic-assessment-fixture",
            retrieved_at=CREATED_AT,
            subject_type="vulnerability_asset_pair",
            subject_id=f"{vulnerability.vulnerability_id}/{asset.asset_id}",
            claim_type="affectedness_assessment",
            claim=f"Test assessment reports {status.value} for this pair.",
        )
        evidence_ids = [] if status is AffectedStatus.UNKNOWN else [assessment.evidence_id]
        # Exposure and assessment references are explicit; no assessment is inferred here.
        if exposed is not None:
            evidence_ids.extend(asset.evidence_ids)
        cases.append(
            VulnerabilityCase(
                vulnerability_id=vulnerability.vulnerability_id,
                cve_id=vulnerability.cve_id,
                asset_id=asset.asset_id,
                affected_status=status,
                exposure=CaseExposure(internet_exposed=asset.internet_exposed),
                evidence_ids=evidence_ids,
                created_at=CREATED_AT,
                updated_at=CREATED_AT,
            )
        )
        assets.append(asset)
        assessments.append(assessment)

    case_a, case_b, case_c, case_d = cases
    assert len({case.case_id for case in cases}) == 4
    assert len({case.asset_id for case in cases}) == 4
    assert {case.vulnerability_id for case in cases} == {vulnerability.vulnerability_id}
    assert {case.cve_id for case in cases} == {"CVE-2026-12345"}
    assert assets[0].environment is Environment.PRODUCTION
    assert case_a.exposure.internet_exposed is True
    assert case_a.affected_status is AffectedStatus.AFFECTED
    assert assets[1].environment is Environment.DEVELOPMENT
    assert case_b.affected_status is AffectedStatus.AFFECTED
    assert case_a.evidence_ids != case_b.evidence_ids
    assert case_c.affected_status is AffectedStatus.NOT_AFFECTED
    assert case_c.evidence_ids[0] == assessments[2].evidence_id
    assert case_d.affected_status is AffectedStatus.UNKNOWN
    assert case_d.evidence_ids == ()
    assert all(case.priority is None and case.state is CaseState.NEW for case in cases)


@pytest.mark.parametrize("status", [AffectedStatus.AFFECTED, AffectedStatus.NOT_AFFECTED])
@pytest.mark.parametrize("supply_empty_list", [False, True])
def test_definitive_status_requires_evidence(case_fields, status, supply_empty_list):
    fields = {**case_fields, "affected_status": status}
    if supply_empty_list:
        fields["evidence_ids"] = []

    with pytest.raises(ValidationError, match="require evidence_ids"):
        VulnerabilityCase(**fields)


@pytest.mark.parametrize("status", list(AffectedStatus))
def test_all_statuses_are_representable_with_evidence(case_fields, status):
    evidence_id = uuid4()
    case = VulnerabilityCase(**case_fields, affected_status=status, evidence_ids=[evidence_id])

    assert case.affected_status is status
    assert case.evidence_ids == (evidence_id,)


def test_unknown_can_exist_with_incomplete_evidence(case_fields):
    case = VulnerabilityCase(**case_fields)

    assert isinstance(case.case_id, UUID)
    assert case.affected_status is AffectedStatus.UNKNOWN
    assert case.evidence_ids == ()
    assert case.exposure.internet_exposed is None
    assert case.exposure.externally_reachable is None
    assert case.priority is None
    assert case.remediation_plan_id is None
    assert case.approval_id is None
    assert case.verification_id is None


def test_mutating_input_evidence_list_cannot_invalidate_a_definitive_case(case_fields):
    evidence_id = uuid4()
    references = [evidence_id]
    case = VulnerabilityCase(
        **case_fields, affected_status=AffectedStatus.AFFECTED, evidence_ids=references
    )
    references.clear()

    assert case.evidence_ids == (evidence_id,)
    assert isinstance(case.evidence_ids, tuple)
    with pytest.raises(ValidationError):
        case.evidence_ids = ()
    assert case.evidence_ids == (evidence_id,)


def test_case_snapshots_cannot_be_silently_reassigned(case_fields):
    case = VulnerabilityCase(**case_fields)
    for field, value in (
        ("asset_id", uuid4()),
        ("vulnerability_id", uuid4()),
        ("affected_status", AffectedStatus.NOT_AFFECTED),
    ):
        original = getattr(case, field)
        with pytest.raises(ValidationError):
            setattr(case, field, value)
        assert getattr(case, field) == original


def test_exposure_snapshot_is_immutable(case_fields):
    case = VulnerabilityCase(**case_fields, exposure=CaseExposure(internet_exposed=True))

    with pytest.raises(ValidationError):
        case.exposure.internet_exposed = False
    assert case.exposure.internet_exposed is True


def test_json_round_trip_preserves_references_and_evidence(case_fields):
    case = VulnerabilityCase(
        **case_fields,
        affected_status=AffectedStatus.AFFECTED,
        exposure=CaseExposure(internet_exposed=True, externally_reachable=True),
        evidence_ids=[uuid4()],
        priority="policy-label",
        remediation_plan_id=uuid4(),
        approval_id=uuid4(),
        verification_id=uuid4(),
    )

    assert VulnerabilityCase.model_validate_json(case.model_dump_json()) == case


def test_case_can_link_a_canonical_vulnerability_without_a_cve(case_fields):
    case = VulnerabilityCase(**{**case_fields, "cve_id": None})

    assert case.cve_id is None
    assert case.vulnerability_id == case_fields["vulnerability_id"]


@pytest.mark.parametrize("cve_id", ["CVE-2026-123", "cve-2026-12345", "CVE-2026-12345\n"])
def test_case_uses_the_canonical_cve_identifier_rules(case_fields, cve_id):
    with pytest.raises(ValidationError):
        VulnerabilityCase(**{**case_fields, "cve_id": cve_id})


@pytest.mark.parametrize("field", ["created_at", "updated_at"])
def test_case_timestamps_require_timezones(case_fields, field):
    with pytest.raises(ValidationError) as error:
        VulnerabilityCase(**{**case_fields, field: datetime(2026, 10, 25)})

    assert error.value.errors()[0]["type"] == "timezone_aware"


def test_update_cannot_precede_creation(case_fields):
    with pytest.raises(ValidationError, match="updated_at must not precede"):
        VulnerabilityCase(**{**case_fields, "updated_at": CREATED_AT - timedelta(seconds=1)})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("asset_id", "not-a-uuid"),
        ("affected_status", "AFFECTED"),
        ("evidence_ids", ["not-a-uuid"]),
        ("evidence_ids", [str(uuid4())]),
        ("approval_id", "approved"),
        ("priority", 1),
    ],
)
def test_case_python_values_are_strictly_typed(case_fields, field, value):
    with pytest.raises(ValidationError):
        VulnerabilityCase(**{**case_fields, field: value})


def test_unknown_case_and_exposure_fields_are_rejected(case_fields):
    with pytest.raises(ValidationError):
        VulnerabilityCase(**case_fields, risk_score=9.8)
    with pytest.raises(ValidationError):
        CaseExposure(safe=True)


def test_case_cannot_claim_a_closed_state_before_lifecycle_controls_exist(case_fields):
    payload = VulnerabilityCase(**case_fields).model_dump_json().replace('"NEW"', '"CLOSED"')

    with pytest.raises(ValidationError):
        VulnerabilityCase.model_validate_json(payload)
