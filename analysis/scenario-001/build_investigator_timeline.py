import csv
from pathlib import Path

BASE = Path.home() / "BEC-and-Digital-Forensics"
SOURCE = BASE / "analysis/scenario-001/scenario_timeline.csv"
OUTPUT = BASE / "analysis/scenario-001/investigator_timeline.csv"

events = []

with SOURCE.open(newline="", encoding="utf-8") as f:
    rows = list(csv.DictReader(f))

for row in rows:
    event_id = row["event_id"]
    command = row["command_line"]
    target = row["target_filename"]
    image = row["image"]

    # Ignore modern Notepad's internal session child process.
    if "/SESSION:" in command:
        continue

    # Keep SearchProtocolHost activity but explicitly classify it as noise/context.
    if "SearchProtocolHost.exe" in image:
        events.append({
            "timestamp": row["timestamp"],
            "category": "System activity",
            "action": "Windows Search indexed the email artifact",
            "evidence": target,
            "assessment": "Background indexing activity; not evidence of user execution."
        })
        continue

    if event_id == "11" and target.endswith("BEC-Scenario-001"):
        events.append({
            "timestamp": row["timestamp"],
            "category": "Artifact placement",
            "action": "Scenario directory created",
            "evidence": target,
            "assessment": "Controlled lab preparation/activity."
        })

    elif event_id == "11" and "Invoice_10482_Bank_Change.eml" in target:
        events.append({
            "timestamp": row["timestamp"],
            "category": "Artifact placement",
            "action": "Suspicious email artifact placed in Downloads",
            "evidence": target,
            "assessment": "Email artifact became available to the simulated user."
        })

    elif event_id == "11" and "Northstar_ACH_Update.txt" in target:
        events.append({
            "timestamp": row["timestamp"],
            "category": "Artifact placement",
            "action": "ACH-update attachment placed in Downloads",
            "evidence": target,
            "assessment": "Controlled BEC attachment staged for user interaction."
        })

    elif event_id == "1" and "Invoice_10482_Bank_Change.eml" in command:
        events.append({
            "timestamp": row["timestamp"],
            "category": "User interaction",
            "action": "User opened suspicious email artifact",
            "evidence": command,
            "assessment": "Confirmed by Sysmon process creation telemetry."
        })

    elif event_id == "1" and "Northstar_ACH_Update.txt" in command:
        events.append({
            "timestamp": row["timestamp"],
            "category": "User interaction",
            "action": "User opened ACH-update attachment",
            "evidence": command,
            "assessment": "Confirmed attachment interaction; no malicious code execution occurred."
        })

fields = [
    "timestamp",
    "category",
    "action",
    "evidence",
    "assessment",
]

with OUTPUT.open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    writer.writerows(events)

print(f"Investigator timeline events: {len(events)}")
print()

for event in events:
    print(
        f'{event["timestamp"]} | '
        f'{event["category"]} | '
        f'{event["action"]}'
    )

print()
print(f"Written to: {OUTPUT}")
