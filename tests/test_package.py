"""Smoke coverage for the installed src-layout package."""

import subprocess
import sys


def test_installed_package_imports_outside_repository(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            "import vulnops; "
            "from importlib.metadata import version; "
            "print(version('vulnops-control-plane'))",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )

    assert result.stdout.strip() == "0.1.0"
