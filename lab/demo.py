"""Print component/product assessments from the offline synthetic snapshot."""

from pathlib import Path

from vulnops.application.demo import preview_demo


def main():
    root = Path(__file__).resolve().parent
    report = preview_demo(root)
    assets = {asset.asset_id: asset for asset in report.assets}
    print("SYNTHETIC LAB — component/product pairs; no asset-wide safety conclusion")
    for assessment in report.assessments:
        result = assessment.result
        asset = assets[result.asset_id]
        component = next(item for item in asset.components if item.component_id == result.component_id)
        print(f"{assessment.cve_id}  {asset.external_id}  "
              f"{component.identity.package_name}  {result.status.value}")


if __name__ == "__main__":
    main()
