import csv
import hashlib
from email.message import EmailMessage
from email.policy import SMTP
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "evidence" / "scenario-002"
EVIDENCE.mkdir(parents=True, exist_ok=True)

auth_events = [
    {
        "timestamp": "2026-10-07T13:41:08Z",
        "user": "finance@sapphros.test",
        "ip_address": "198.51.100.25",
        "location": "Denver, US",
        "client_app": "Browser",
        "user_agent": "Chrome 154 / Windows 11",
        "status": "success",
        "mfa_result": "success",
        "device_id": "FIN-WS01",
        "device_compliant": "true",
        "risk_detail": "none",
        "session_id": "sess-legit-001",
    },
    {
        "timestamp": "2026-10-07T13:55:17Z",
        "user": "finance@sapphros.test",
        "ip_address": "198.51.100.25",
        "location": "Denver, US",
        "client_app": "Exchange Online",
        "user_agent": "Microsoft Outlook / Windows 11",
        "status": "success",
        "mfa_result": "previously_satisfied",
        "device_id": "FIN-WS01",
        "device_compliant": "true",
        "risk_detail": "none",
        "session_id": "sess-legit-001",
    },
    {
        "timestamp": "2026-10-07T14:02:41Z",
        "user": "finance@sapphros.test",
        "ip_address": "203.0.113.77",
        "location": "Frankfurt, DE",
        "client_app": "Browser",
        "user_agent": "Chrome 154 / Linux",
        "status": "failure",
        "mfa_result": "not_attempted",
        "device_id": "",
        "device_compliant": "false",
        "risk_detail": "invalid_password",
        "session_id": "",
    },
    {
        "timestamp": "2026-10-07T14:03:12Z",
        "user": "finance@sapphros.test",
        "ip_address": "203.0.113.77",
        "location": "Frankfurt, DE",
        "client_app": "Browser",
        "user_agent": "Chrome 154 / Linux",
        "status": "success",
        "mfa_result": "satisfied_by_token_claim",
        "device_id": "",
        "device_compliant": "false",
        "risk_detail": "unfamiliar_signin_properties",
        "session_id": "sess-attack-001",
    },
    {
        "timestamp": "2026-10-07T14:04:05Z",
        "user": "finance@sapphros.test",
        "ip_address": "203.0.113.77",
        "location": "Frankfurt, DE",
        "client_app": "Exchange Online",
        "user_agent": "Chrome 154 / Linux",
        "status": "success",
        "mfa_result": "previously_satisfied",
        "device_id": "",
        "device_compliant": "false",
        "risk_detail": "unfamiliar_signin_properties",
        "session_id": "sess-attack-001",
    },
    {
        "timestamp": "2026-10-07T14:11:47Z",
        "user": "finance@sapphros.test",
        "ip_address": "203.0.113.77",
        "location": "Frankfurt, DE",
        "client_app": "Exchange Online",
        "user_agent": "Chrome 154 / Linux",
        "status": "success",
        "mfa_result": "previously_satisfied",
        "device_id": "",
        "device_compliant": "false",
        "risk_detail": "unfamiliar_signin_properties",
        "session_id": "sess-attack-001",
    },
    {
        "timestamp": "2026-10-07T14:19:03Z",
        "user": "finance@sapphros.test",
        "ip_address": "198.51.100.25",
        "location": "Denver, US",
        "client_app": "Exchange Online",
        "user_agent": "Microsoft Outlook / Windows 11",
        "status": "success",
        "mfa_result": "previously_satisfied",
        "device_id": "FIN-WS01",
        "device_compliant": "true",
        "risk_detail": "none",
        "session_id": "sess-legit-001",
    },
    {
        "timestamp": "2026-10-07T14:06:14Z",
        "user": "support@sapphros.test",
        "ip_address": "198.51.100.44",
        "location": "Denver, US",
        "client_app": "Browser",
        "user_agent": "Edge 154 / Windows 11",
        "status": "success",
        "mfa_result": "success",
        "device_id": "SUPPORT-WS02",
        "device_compliant": "true",
        "risk_detail": "none",
        "session_id": "sess-support-001",
    },
]

mailbox_events = [
    {
        "timestamp": "2026-10-07T13:56:02Z",
        "user": "finance@sapphros.test",
        "operation": "MailItemsAccessed",
        "client_ip": "198.51.100.25",
        "user_agent": "Microsoft Outlook / Windows 11",
        "object": "Inbox",
        "parameters": "Normal mailbox access",
        "result": "success",
        "session_id": "sess-legit-001",
    },
    {
        "timestamp": "2026-10-07T14:04:38Z",
        "user": "finance@sapphros.test",
        "operation": "MailItemsAccessed",
        "client_ip": "203.0.113.77",
        "user_agent": "Chrome 154 / Linux",
        "object": "Inbox",
        "parameters": "Accessed recent invoice and vendor conversations",
        "result": "success",
        "session_id": "sess-attack-001",
    },
    {
        "timestamp": "2026-10-07T14:05:21Z",
        "user": "finance@sapphros.test",
        "operation": "New-InboxRule",
        "client_ip": "203.0.113.77",
        "user_agent": "Chrome 154 / Linux",
        "object": "Invoice Archive",
        "parameters": "SubjectContainsWords=invoice,payment;MoveToFolder=RSS Feeds;MarkAsRead=True",
        "result": "success",
        "session_id": "sess-attack-001",
    },
    {
        "timestamp": "2026-10-07T14:06:03Z",
        "user": "finance@sapphros.test",
        "operation": "Set-Mailbox",
        "client_ip": "203.0.113.77",
        "user_agent": "Chrome 154 / Linux",
        "object": "finance@sapphros.test",
        "parameters": "ForwardingSmtpAddress=payments-review@external-mail.test;DeliverToMailboxAndForward=True",
        "result": "success",
        "session_id": "sess-attack-001",
    },
    {
        "timestamp": "2026-10-07T14:09:44Z",
        "user": "finance@sapphros.test",
        "operation": "MailItemsAccessed",
        "client_ip": "203.0.113.77",
        "user_agent": "Chrome 154 / Linux",
        "object": "Vendor conversation: Northstar Supply",
        "parameters": "Read existing Invoice 10482 conversation",
        "result": "success",
        "session_id": "sess-attack-001",
    },
    {
        "timestamp": "2026-10-07T14:12:16Z",
        "user": "finance@sapphros.test",
        "operation": "Send",
        "client_ip": "203.0.113.77",
        "user_agent": "Chrome 154 / Linux",
        "object": "<scenario002-payment-change@sapphros.test>",
        "parameters": "To=billing@northstar-supply.test;Subject=Updated ACH Details - Invoice 10482",
        "result": "success",
        "session_id": "sess-attack-001",
    },
    {
        "timestamp": "2026-10-07T14:15:31Z",
        "user": "finance@sapphros.test",
        "operation": "SoftDelete",
        "client_ip": "203.0.113.77",
        "user_agent": "Chrome 154 / Linux",
        "object": "<scenario002-payment-change@sapphros.test>",
        "parameters": "Deleted fraudulent message from Sent Items",
        "result": "success",
        "session_id": "sess-attack-001",
    },
    {
        "timestamp": "2026-10-07T14:19:29Z",
        "user": "finance@sapphros.test",
        "operation": "MailItemsAccessed",
        "client_ip": "198.51.100.25",
        "user_agent": "Microsoft Outlook / Windows 11",
        "object": "Inbox",
        "parameters": "Normal mailbox access",
        "result": "success",
        "session_id": "sess-legit-001",
    },
]

def write_csv(path, rows):
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

write_csv(EVIDENCE / "authentication_events.csv", auth_events)
write_csv(EVIDENCE / "mailbox_audit_events.csv", mailbox_events)

msg = EmailMessage()
msg["From"] = "Finance Department <finance@sapphros.test>"
msg["To"] = "Northstar Supply Billing <billing@northstar-supply.test>"
msg["Subject"] = "Updated ACH Details - Invoice 10482"
msg["Date"] = "Wed, 07 Oct 2026 14:12:16 +0000"
msg["Message-ID"] = "<scenario002-payment-change@sapphros.test>"

msg.set_content(
    """Hello,

Please update the payment instructions for Invoice 10482 before processing payment.

Our ACH details have changed:

Bank: Sapphros Lab Bank
Routing Number: 000000000
Account Number: 0000000000

Please confirm once the payment profile has been updated.

Regards,
Finance Department

LAB ARTIFACT ONLY - synthetic data for defensive training.
"""
)

eml_path = EVIDENCE / "fraudulent_outbound_message.eml"
eml_path.write_bytes(msg.as_bytes(policy=SMTP))

notes = """Scenario 002 - Mailbox Account Compromise

All evidence in this directory is synthetic.

Reserved documentation IP ranges are used:
- 198.51.100.0/24
- 203.0.113.0/24

All email domains use .test or other synthetic training identifiers.

No real credentials, organizations, victims, bank accounts, or infrastructure
are represented.
"""

(EVIDENCE / "evidence_notes.txt").write_text(notes, encoding="utf-8")

manifest_path = EVIDENCE / "sha256_manifest.csv"
rows = []

for path in sorted(EVIDENCE.iterdir()):
    if not path.is_file() or path.name == manifest_path.name:
        continue

    rows.append({
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "file": path.name,
    })

with manifest_path.open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=["sha256", "file"])
    writer.writeheader()
    writer.writerows(rows)

print("Scenario 002 evidence created:")
for row in rows:
    print(f'{row["sha256"]}  {row["file"]}')
