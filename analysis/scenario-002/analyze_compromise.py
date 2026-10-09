import csv
import json
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "evidence" / "scenario-002"
OUTPUT = ROOT / "analysis" / "scenario-002"

AUTH_FILE = EVIDENCE / "authentication_events.csv"
MAILBOX_FILE = EVIDENCE / "mailbox_audit_events.csv"

TARGET_USER = "finance@sapphros.test"


def read_csv(path):
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


auth_events = read_csv(AUTH_FILE)
mailbox_events = read_csv(MAILBOX_FILE)

timeline = []
findings = []

# Establish the known-good profile from successful compliant sessions.
known_good_ips = {
    row["ip_address"]
    for row in auth_events
    if row["user"] == TARGET_USER
    and row["status"] == "success"
    and row["device_compliant"].lower() == "true"
    and row["device_id"]
}

known_good_devices = {
    row["device_id"]
    for row in auth_events
    if row["user"] == TARGET_USER
    and row["status"] == "success"
    and row["device_compliant"].lower() == "true"
    and row["device_id"]
}

suspicious_sessions = set()

for row in auth_events:
    if row["user"] != TARGET_USER:
        continue

    suspicious_reasons = []

    if row["ip_address"] not in known_good_ips:
        suspicious_reasons.append("IP not observed in known-good compliant activity")

    if row["device_compliant"].lower() != "true":
        suspicious_reasons.append("Non-compliant or unidentified device")

    if row["device_id"] and row["device_id"] not in known_good_devices:
        suspicious_reasons.append("Unknown device")

    if row["risk_detail"] not in ("", "none"):
        suspicious_reasons.append(f'Risk detail: {row["risk_detail"]}')

    if row["location"] != "Denver, US":
        suspicious_reasons.append(f'Unusual location: {row["location"]}')

    if suspicious_reasons:
        if row["session_id"]:
            suspicious_sessions.add(row["session_id"])

        timeline.append({
            "timestamp": row["timestamp"],
            "source": "authentication",
            "category": "Suspicious authentication",
            "operation": row["status"],
            "user": row["user"],
            "ip_address": row["ip_address"],
            "session_id": row["session_id"],
            "details": "; ".join(suspicious_reasons),
        })


# Analyze mailbox events tied to suspicious sessions.
for row in mailbox_events:
    if row["user"] != TARGET_USER:
        continue

    if row["session_id"] not in suspicious_sessions:
        continue

    operation = row["operation"]

    if operation == "MailItemsAccessed":
        category = "Mailbox access"
        assessment = "Mailbox content accessed from suspicious session."

    elif operation == "New-InboxRule":
        category = "Mailbox persistence / concealment"
        assessment = (
            "Inbox rule created from suspicious session. "
            "Rule targets invoice/payment messages and moves them while marking them read."
        )

        findings.append({
            "severity": "High",
            "title": "Suspicious inbox rule created",
            "evidence": row["parameters"],
            "assessment": assessment,
        })

    elif operation == "Set-Mailbox":
        category = "Mailbox persistence / forwarding"
        assessment = (
            "External forwarding configured from suspicious session, "
            "allowing mailbox content to be copied to an external address."
        )

        findings.append({
            "severity": "Critical",
            "title": "External mailbox forwarding enabled",
            "evidence": row["parameters"],
            "assessment": assessment,
        })

    elif operation == "Send":
        category = "Fraudulent outbound activity"
        assessment = (
            "Message sent from legitimate mailbox during suspicious session."
        )

        findings.append({
            "severity": "Critical",
            "title": "Fraudulent email sent from compromised mailbox",
            "evidence": row["parameters"],
            "assessment": assessment,
        })

    elif operation == "SoftDelete":
        category = "Anti-forensics / concealment"
        assessment = (
            "Sent message deleted during suspicious session, "
            "consistent with an attempt to conceal outbound activity."
        )

        findings.append({
            "severity": "High",
            "title": "Fraudulent sent message deleted",
            "evidence": row["parameters"],
            "assessment": assessment,
        })

    else:
        category = "Mailbox activity"
        assessment = "Activity associated with suspicious session."

    timeline.append({
        "timestamp": row["timestamp"],
        "source": "mailbox_audit",
        "category": category,
        "operation": operation,
        "user": row["user"],
        "ip_address": row["client_ip"],
        "session_id": row["session_id"],
        "details": f'{row["object"]} | {row["parameters"]} | {assessment}',
    })


# Add a specific authentication finding for the suspicious successful sign-in.
for row in auth_events:
    if (
        row["user"] == TARGET_USER
        and row["session_id"] in suspicious_sessions
        and row["status"] == "success"
        and row["client_app"] == "Browser"
    ):
        findings.insert(0, {
            "severity": "Critical",
            "title": "Suspicious successful authentication",
            "evidence": (
                f'{row["ip_address"]} | {row["location"]} | '
                f'MFA={row["mfa_result"]} | '
                f'DeviceCompliant={row["device_compliant"]}'
            ),
            "assessment": (
                "Successful authentication originated from an unusual location "
                "and non-compliant unidentified device. MFA was recorded as "
                "'satisfied_by_token_claim'; this is consistent with session/token "
                "reuse but does not by itself prove how the token was obtained."
            ),
        })
        break


timeline.sort(key=lambda row: parse_time(row["timestamp"]))

summary = {
    "target_user": TARGET_USER,
    "known_good_ips": sorted(known_good_ips),
    "known_good_devices": sorted(known_good_devices),
    "suspicious_sessions": sorted(suspicious_sessions),
    "timeline_event_count": len(timeline),
    "finding_count": len(findings),
    "assessment": (
        "Evidence supports mailbox account compromise. A suspicious successful "
        "authentication session was followed by mailbox access, creation of an "
        "invoice-hiding inbox rule, external forwarding configuration, a fraudulent "
        "outbound payment-change message, and deletion of that sent message. "
        "The available evidence establishes malicious mailbox activity but does not "
        "establish the original mechanism by which the attacker obtained the valid "
        "session or token."
    ),
}


with (OUTPUT / "compromise_analysis.json").open("w", encoding="utf-8") as f:
    json.dump(
        {
            "summary": summary,
            "findings": findings,
            "timeline": timeline,
        },
        f,
        indent=2,
    )


timeline_fields = [
    "timestamp",
    "source",
    "category",
    "operation",
    "user",
    "ip_address",
    "session_id",
    "details",
]

with (OUTPUT / "investigator_timeline.csv").open(
    "w",
    newline="",
    encoding="utf-8",
) as f:
    writer = csv.DictWriter(f, fieldnames=timeline_fields)
    writer.writeheader()
    writer.writerows(timeline)


print("=== Scenario 002 Analysis ===")
print(f"Target user: {TARGET_USER}")
print(f"Known-good IPs: {', '.join(sorted(known_good_ips))}")
print(f"Suspicious sessions: {', '.join(sorted(suspicious_sessions))}")
print(f"Timeline events: {len(timeline)}")
print(f"Findings: {len(findings)}")

print()
print("=== Findings ===")

for finding in findings:
    print(
        f'[{finding["severity"]}] '
        f'{finding["title"]}: '
        f'{finding["evidence"]}'
    )

print()
print("=== Investigator Timeline ===")

for row in timeline:
    print(
        f'{row["timestamp"]} | '
        f'{row["category"]} | '
        f'{row["operation"]} | '
        f'{row["ip_address"]}'
    )

print()
print("Written:")
print(OUTPUT / "compromise_analysis.json")
print(OUTPUT / "investigator_timeline.csv")
