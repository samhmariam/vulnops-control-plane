from pathlib import Path

from vulnops.application.demo import preview_demo


def test_demo_resolves_synthetic_candidates_with_complete_evidence():
    report = preview_demo(Path(__file__).resolve().parents[2] / "lab")
    assert report.synthetic and not report.persisted
    assert len(report.assets) == 6
    assert len(report.vulnerabilities) == 5
    assert len(report.assessments) == 12
    assert {item.result.status.value for item in report.assessments} == {"AFFECTED", "NOT_AFFECTED", "UNKNOWN"}
    known = {item.evidence_id for item in report.evidence}
    for assessment in report.assessments:
        assert set(assessment.result.evidence_ids) <= known
        assert assessment.result.reason
