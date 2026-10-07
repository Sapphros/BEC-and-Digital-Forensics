import csv
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

EVIDENCE = ROOT / "evidence" / "scenario-001"
ANALYSIS = ROOT / "analysis" / "scenario-001"


def sha256(path):
    h = hashlib.sha256()

    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)

    return h.hexdigest()


def test_email_hash():
    path = EVIDENCE / "Invoice_10482_Bank_Change.eml"

    assert sha256(path) == (
        "77b36abf4527e0e5e535d07c17f12293"
        "f2a219eff0da6ff3f54e27c0e8c20514"
    )


def test_attachment_hash():
    path = EVIDENCE / "Northstar_ACH_Update.txt"

    assert sha256(path) == (
        "73873d91b244fb7d26edfa36bcbe9e623"
        "7311df5d995fec546ec31bf8333678c"
    )


def test_email_analysis_contains_bec_indicators():
    path = ANALYSIS / "email_analysis.json"

    result = json.loads(path.read_text(encoding="utf-8"))

    indicator_types = {
        item["type"]
        for item in result["indicators"]
    }

    assert "reply-to mismatch" in indicator_types
    assert "financial urgency" in indicator_types
    assert "bank-change request" in indicator_types
    assert "confirmation request" in indicator_types


def test_investigator_timeline_contains_user_interaction():
    path = ANALYSIS / "investigator_timeline.csv"

    with path.open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    actions = {row["action"] for row in rows}

    assert "User opened suspicious email artifact" in actions
    assert "User opened ACH-update attachment" in actions


def test_investigator_timeline_has_six_events():
    path = ANALYSIS / "investigator_timeline.csv"

    with path.open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    assert len(rows) == 6
