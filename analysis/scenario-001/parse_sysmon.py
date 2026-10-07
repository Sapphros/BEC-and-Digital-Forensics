import csv
import json
from datetime import datetime, timezone
from pathlib import Path

from evtx import PyEvtxParser

EVIDENCE = (
    Path.home()
    / "BEC-and-Digital-Forensics"
    / "evidence"
    / "scenario-001"
)

EVTX_FILE = EVIDENCE / "Sysmon.evtx"

OUT_DIR = (
    Path.home()
    / "BEC-and-Digital-Forensics"
    / "analysis"
    / "scenario-001"
)

OUT_DIR.mkdir(parents=True, exist_ok=True)

JSON_OUT = OUT_DIR / "sysmon_scenario_events.json"
CSV_OUT = OUT_DIR / "sysmon_scenario_events.csv"

# Scenario activity observed between approximately
# 04:23:54 and 04:24:47 UTC.
# Add padding for surrounding forensic context.
START = datetime(2026, 10, 7, 4, 22, 0, tzinfo=timezone.utc)
END = datetime(2026, 10, 7, 4, 27, 0, tzinfo=timezone.utc)


def parse_time(value):
    value = str(value).strip()

    # evtx may return timestamps like:
    # 2026-09-18T21:53:25.1275099Z UTC
    if value.endswith(" UTC"):
        value = value[:-4]

    if value.endswith("Z"):
        value = value[:-1] + "+00:00"

    # Python datetime supports microseconds; trim longer fractional seconds.
    if "." in value:
        prefix, rest = value.split(".", 1)

        if "+" in rest:
            fraction, offset = rest.split("+", 1)
            fraction = fraction[:6]
            value = f"{prefix}.{fraction}+{offset}"
        elif "-" in rest:
            fraction, offset = rest.split("-", 1)
            fraction = fraction[:6]
            value = f"{prefix}.{fraction}-{offset}"

    dt = datetime.fromisoformat(value)

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(timezone.utc)


def get_text(value):
    if isinstance(value, dict):
        return value.get("#text", "")
    return value if value is not None else ""


def event_data_to_dict(event):
    event_data = event.get("Event", {}).get("EventData", {})

    if not isinstance(event_data, dict):
        return {}

    # Rust evtx JSON normally flattens EventData directly:
    # {"Image": "...", "CommandLine": "...", ...}
    if "Data" not in event_data:
        return {
            key: get_text(value)
            for key, value in event_data.items()
            if key != "#attributes"
        }

    # Compatibility with XML-like Data/Name representations.
    data = {}
    items = event_data.get("Data", [])

    if isinstance(items, dict):
        items = [items]

    for item in items:
        if not isinstance(item, dict):
            continue

        attrs = item.get("#attributes", {})
        name = attrs.get("Name", "")

        if name:
            data[name] = get_text(item)

    return data


events = []
total = 0
matched = 0

parser = PyEvtxParser(str(EVTX_FILE))

for record in parser.records_json():
    total += 1

    if total % 10000 == 0:
        print(f"Scanned {total:,} records...")

    record_time = parse_time(record["timestamp"])

    if not START <= record_time <= END:
        continue

    payload = json.loads(record["data"])

    system = payload.get("Event", {}).get("System", {})

    event_id = get_text(system.get("EventID", ""))
    provider_info = system.get("Provider", {})
    provider = ""

    if isinstance(provider_info, dict):
        provider = provider_info.get("#attributes", {}).get("Name", "")

    time_info = system.get("TimeCreated", {})
    timestamp = record["timestamp"]

    if isinstance(time_info, dict):
        timestamp = (
            time_info.get("#attributes", {}).get("SystemTime")
            or timestamp
        )

    computer = get_text(system.get("Computer", ""))

    data = event_data_to_dict(payload)

    event = {
        "timestamp": timestamp,
        "event_id": int(event_id) if str(event_id).isdigit() else event_id,
        "provider": provider,
        "computer": computer,
        "data": data,
    }

    events.append(event)
    matched += 1

events.sort(key=lambda event: event["timestamp"])

JSON_OUT.write_text(
    json.dumps(events, indent=2),
    encoding="utf-8",
)

fields = [
    "timestamp",
    "event_id",
    "computer",
    "rule_name",
    "user",
    "image",
    "command_line",
    "target_filename",
    "target_object",
    "parent_image",
    "parent_command_line",
]

with CSV_OUT.open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()

    for event in events:
        data = event["data"]

        writer.writerow(
            {
                "timestamp": event["timestamp"],
                "event_id": event["event_id"],
                "computer": event["computer"],
                "rule_name": data.get("RuleName", ""),
                "user": data.get("User", ""),
                "image": data.get("Image", ""),
                "command_line": data.get("CommandLine", ""),
                "target_filename": data.get("TargetFilename", ""),
                "target_object": data.get("TargetObject", ""),
                "parent_image": data.get("ParentImage", ""),
                "parent_command_line": data.get("ParentCommandLine", ""),
            }
        )

print()
print(f"Total Sysmon records scanned: {total:,}")
print(f"Scenario-window records:      {matched:,}")
print(f"JSON: {JSON_OUT}")
print(f"CSV:  {CSV_OUT}")
