"""Acceptance must fail, rather than report a skipped database as readiness."""

import os

import pytest


@pytest.fixture(scope="session", autouse=True)
def acceptance_database(request):
    if not all(os.environ.get(name) for name in (
        "VULNOPS_TEST_DATABASE_URL", "VULNOPS_TEST_ADMIN_DATABASE_URL",
    )):
        pytest.fail("Day 1 acceptance requires both PostgreSQL test URLs; skipped database checks cannot pass the gate")
    return request.getfixturevalue("database")
