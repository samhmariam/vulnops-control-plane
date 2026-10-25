"""Keep the architectural invariant document and its stable identifiers present."""

from pathlib import Path
import re


def test_invariants_document_exists_and_contains_all_identifiers():
    document = Path(__file__).resolve().parents[2] / "docs" / "invariants.md"
    assert document.is_file(), "docs/invariants.md must exist"

    contents = document.read_text(encoding="utf-8")
    present = set(re.findall(r"\bINV-\d{2}\b", contents))
    expected = {f"INV-{number:02d}" for number in range(1, 11)}

    assert expected <= present, f"Missing invariant identifiers: {sorted(expected - present)}"
