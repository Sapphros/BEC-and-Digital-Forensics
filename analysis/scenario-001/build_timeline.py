import csv
from pathlib import Path

BASE = Path.home() / "BEC-and-Digital-Forensics"
SOURCE = BASE / "analysis/scenario-001/sysmon_scenario_events.csv"
OUTPUT = BASE / "analysis/scenario-001/scenario_timeline.csv"

needles = (
    "bec-scenario-001",
    "invoice_10482",
    "northstar_ach_update",
)

rows = []

with SOURCE.open(newline="", encoding="utf-8") as f:
    reader = csv.DictReader(f)

    for row in reader:
        searchable = " ".join(
            str(value or "")
            for value in row.values()
        ).lower()

        if any(needle in searchable for needle in needles):
            rows.append(row)

rows.sort(key=lambda r: r["timestamp"])

fields = [
    "timestamp",
    "event_id",
    "rule_name",
    "user",
    "image",
    "command_line",
    "target_filename",
    "target_object",
    "parent_image",
    "parent_command_line",
]

with OUTPUT.open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()

    for row in rows:
        writer.writerow({
            field: row.get(field, "")
            for field in fields
        })

print(f"Scenario events: {len(rows)}")
print(f"Timeline: {OUTPUT}")

for row in rows:
    detail = (
        row["target_filename"]
        or row["command_line"]
        or row["target_object"]
        or row["image"]
    )

    print(
        f'{row["timestamp"]}  '
        f'Event {row["event_id"]:>2}  '
        f'{detail}'
    )
