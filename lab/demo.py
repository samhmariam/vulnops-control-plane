"""Print component/product assessments from the offline synthetic snapshot."""

from pathlib import Path

from vulnops.matching.affected_resolver import resolve_affected
from vulnops.matching.product_matcher import ProductMatchStatus
from vulnops.sources.fixtures import FixtureVulnerabilitySource, load_fixture_inventory


def main():
    root = Path(__file__).resolve().parent
    vulnerabilities = FixtureVulnerabilitySource(root / "fixtures").fetch()
    assets = load_fixture_inventory(root / "inventory")
    print("SYNTHETIC LAB — component/product pairs; no asset-wide safety conclusion")
    for source in vulnerabilities:
        for inventory in assets:
            for component in inventory.asset.components:
                for product in source.vulnerability.affected_products:
                    result = resolve_affected(component, product)
                    if result.identity_status is not ProductMatchStatus.DIFFERENT:
                        print(f"{source.vulnerability.cve_id}  {inventory.asset.external_id}  "
                              f"{component.identity.package_name}  {result.status.value}")


if __name__ == "__main__":
    main()
