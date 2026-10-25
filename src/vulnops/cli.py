"""Argument parsing and JSON presentation; use cases live in application services."""

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any
from uuid import UUID

from pydantic import TypeAdapter
from sqlalchemy.exc import SQLAlchemyError

from vulnops.application.bootstrap import open_inspection
from vulnops.application.demo import run_demo
from vulnops.application.inspection import RecordNotFound
from vulnops.sources.base import SourceError


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="vulnops", description="Inspect tenant-scoped VulnOps records as JSON.")
    root.add_argument("--tenant-id", help="Tenant UUID (or VULNOPS_TENANT_ID); required for database commands")
    commands = root.add_subparsers(dest="resource", required=True)
    vulnerability = commands.add_parser("vulnerability").add_subparsers(dest="action", required=True)
    vulnerability.add_parser("show").add_argument("identifier", metavar="CVE")
    for resource in ("asset", "case"):
        actions = commands.add_parser(resource).add_subparsers(dest="action", required=True)
        listing = actions.add_parser("list")
        listing.add_argument("--limit", type=int, default=100)
        listing.add_argument("--offset", type=int, default=0)
        actions.add_parser("show").add_argument("identifier", type=UUID, metavar=f"{resource}-id")
        if resource == "case":
            actions.add_parser("history").add_argument("identifier", type=UUID, metavar="case-id")
    demo = commands.add_parser("demo", help="Run the offline synthetic lab; writes no database state")
    demo.add_argument("--lab-dir", type=Path, default=Path("lab"), help="Lab snapshot directory (default: ./lab)")
    return root


def _inspect(service, args):
    if args.action == "list":
        operation = service.list_assets if args.resource == "asset" else service.list_cases
        return operation(limit=args.limit, offset=args.offset)
    operations = {
        ("vulnerability", "show"): service.show_vulnerability,
        ("asset", "show"): service.show_asset,
        ("case", "show"): service.show_case,
        ("case", "history"): service.case_history,
    }
    return operations[(args.resource, args.action)](args.identifier)


def main(argv: list[str] | None = None) -> int:
    arguments = parser()
    args = arguments.parse_args(argv)
    try:
        if args.resource == "demo":
            result = run_demo(args.lab_dir)
        else:
            raw_tenant = args.tenant_id or os.environ.get("VULNOPS_TENANT_ID")
            if not raw_tenant:
                arguments.error("Database commands require --tenant-id or VULNOPS_TENANT_ID")
            tenant_id = UUID(raw_tenant)
            with open_inspection(tenant_id) as service:
                result = _inspect(service, args)
        # JSON escapes terminal controls in untrusted advisory/inventory text.
        print(json.dumps(TypeAdapter(Any).dump_python(result, mode="json"), indent=2, ensure_ascii=True))
        return 0
    except RecordNotFound:
        print("Record not found in this tenant.", file=sys.stderr)
        return 3
    except SourceError:
        print("Unable to load lab snapshot; check --lab-dir and fixture schemas.", file=sys.stderr)
        return 1
    except SQLAlchemyError:
        print("Database operation failed; check connectivity, migrations, and runtime-role configuration.", file=sys.stderr)
        return 1
    except ValueError:
        print("Invalid input or configuration; check identifiers, pagination, and DATABASE_URL.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
