import email
import hashlib
import json
from email import policy
from pathlib import Path

BASE = Path.home() / "BEC-and-Digital-Forensics"
EML = BASE / "evidence/scenario-001/Invoice_10482_Bank_Change.eml"
OUT = BASE / "analysis/scenario-001/email_analysis.json"

raw = EML.read_bytes()
msg = email.message_from_bytes(raw, policy=policy.default)

result = {
    "file": EML.name,
    "sha256": hashlib.sha256(raw).hexdigest(),
    "headers": {
        "from": msg.get("From"),
        "to": msg.get("To"),
        "reply_to": msg.get("Reply-To"),
        "subject": msg.get("Subject"),
        "date": msg.get("Date"),
        "message_id": msg.get("Message-ID"),
    },
    "body": "",
    "attachments": [],
    "indicators": [],
}

for part in msg.walk():
    content_disposition = part.get_content_disposition()

    if part.get_content_type() == "text/plain" and content_disposition != "attachment":
        try:
            result["body"] += part.get_content()
        except Exception:
            pass

    if content_disposition == "attachment":
        payload = part.get_payload(decode=True) or b""

        result["attachments"].append({
            "filename": part.get_filename(),
            "content_type": part.get_content_type(),
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        })

from_header = msg.get("From", "")
reply_to = msg.get("Reply-To", "")

if reply_to and reply_to.lower() not in from_header.lower():
    result["indicators"].append({
        "type": "reply-to mismatch",
        "value": reply_to,
        "assessment": "Reply-To differs from the apparent sender identity."
    })

subject = msg.get("Subject", "") or ""

if any(term in subject.lower() for term in ["action required", "urgent", "payment", "invoice"]):
    result["indicators"].append({
        "type": "financial urgency",
        "value": subject,
        "assessment": "Subject uses payment-related urgency commonly seen in BEC/payment-diversion attempts."
    })

body_lower = result["body"].lower()

if "banking information has changed" in body_lower:
    result["indicators"].append({
        "type": "bank-change request",
        "value": "Banking information changed",
        "assessment": "Message requests modification of existing payment instructions."
    })

if "reply once" in body_lower:
    result["indicators"].append({
        "type": "confirmation request",
        "value": "Reply once banking information has been updated",
        "assessment": "Sender requests confirmation after the payment change is completed."
    })

OUT.write_text(json.dumps(result, indent=2), encoding="utf-8")

print(json.dumps(result, indent=2))
print()
print(f"Written to: {OUT}")
