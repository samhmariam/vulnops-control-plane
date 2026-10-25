from pathlib import Path

from vulnops.application.assessment import assess_asset
from vulnops.application.walking_skeleton import prepare_demo


LAB = Path(__file__).resolve().parents[2] / "lab"


def test_all_required_asset_assessments_and_planned_histories_are_deterministic():
    plan = prepare_demo(LAB)
    assert plan == prepare_demo(LAB)
    outcomes = {item.final.affected_status.value: item.final.state.value for item in plan.cases}
    assert outcomes == {"AFFECTED": "AFFECTED_CONFIRMED", "NOT_AFFECTED": "NOT_AFFECTED", "UNKNOWN": "MANUAL_INVESTIGATION"}
    assert len(plan.cases) == 4
    assert all(len(item.history) == 3 for item in plan.cases)


def test_missing_completeness_never_turns_exclusion_into_unaffected():
    plan = prepare_demo(LAB)
    fixed = next(item for item in plan.assets if item.external_id.endswith("asset-web-02"))
    evidence = [item.model_copy(deep=True) for item in plan.evidence]
    for item in evidence:
        if item.evidence_id in fixed.evidence_ids:
            item.metadata.pop("component_inventory_complete", None)
    assessment = assess_asset(plan.vulnerability, fixed, evidence)
    assert assessment.status.value == "UNKNOWN"
    assert not assessment.inventory_complete


def test_missing_versions_are_unknown_even_with_complete_component_inventory():
    plan = prepare_demo(LAB)
    legacy = next(item for item in plan.assets if item.external_id.endswith("asset-legacy-01"))
    result = assess_asset(plan.vulnerability, legacy, list(plan.evidence))
    assert result.inventory_complete and result.status.value == "UNKNOWN"
