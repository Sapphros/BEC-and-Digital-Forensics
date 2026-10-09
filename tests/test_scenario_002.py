import csv
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence" / "scenario-002"
ANALYSIS = ROOT / "analysis" / "scenario-002"


def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_analysis():
    path = ANALYSIS / "compromise_analysis.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_analysis_script_runs():
    result = subprocess.run(
        [sys.executable, str(ANALYSIS / "analyze_compromise.py")],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_suspicious_session_detected():
    result = load_analysis()
    assert result["summary"]["suspicious_sessions"] == ["sess-attack-001"]


def test_expected_timeline_size():
    result = load_analysis()
    assert result["summary"]["timeline_event_count"] == 10


def test_expected_findings():
    result = load_analysis()

    titles = {item["title"] for item in result["findings"]}

    assert "Suspicious successful authentication" in titles
    assert "Suspicious inbox rule created" in titles
    assert "External mailbox forwarding enabled" in titles
    assert "Fraudulent email sent from compromised mailbox" in titles
    assert "Fraudulent sent message deleted" in titles


def test_critical_findings_present():
    result = load_analysis()

    critical = {
        item["title"]
        for item in result["findings"]
        if item["severity"] == "Critical"
    }

    assert "Suspicious successful authentication" in critical
    assert "External mailbox forwarding enabled" in critical
    assert "Fraudulent email sent from compromised mailbox" in critical


def test_known_good_baseline():
    result = load_analysis()

    assert result["summary"]["known_good_ips"] == ["198.51.100.25"]
    assert result["summary"]["known_good_devices"] == ["FIN-WS01"]


def test_manifest_integrity():
    manifest = EVIDENCE / "sha256_manifest.csv"

    with manifest.open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    assert rows

    for row in rows:
        path = EVIDENCE / row["file"]
        assert path.exists()
        assert sha256(path) == row["sha256"]


def test_documentation_ip_ranges_only():
    allowed_prefixes = ("198.51.100.", "203.0.113.")

    with (EVIDENCE / "authentication_events.csv").open(
        newline="",
        encoding="utf-8",
    ) as f:
        rows = list(csv.DictReader(f))

    for row in rows:
        assert row["ip_address"].startswith(allowed_prefixes)
