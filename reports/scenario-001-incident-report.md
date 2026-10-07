# Incident Report — Vendor Payment Diversion Scenario

## Executive Summary

A controlled business email compromise (BEC) / payment-diversion scenario was investigated using preserved email artifacts and Windows Sysmon telemetry.

The simulated message claimed that a vendor's banking information had changed and instructed the recipient to use new ACH payment details for an outstanding invoice. Analysis identified multiple indicators consistent with payment-diversion fraud, including a mismatched Reply-To address, financial urgency, a request to modify banking information, and a request to confirm completion of the change.

Endpoint telemetry confirmed that the email artifact and its ACH-update attachment were placed in the user's Downloads directory and subsequently opened by the simulated user.

No evidence was identified in this scenario of malware execution, persistence, credential theft, command-and-control activity, or exploitation. The observed behavior is therefore assessed as a social-engineering/payment-diversion scenario rather than a malware-based compromise.

## Environment

- Endpoint: `WIN-TARGET-01`
- Operating system: Windows
- Telemetry source: Sysmon
- Analysis system: Linux-based Sapphros Controller
- Scenario type: Synthetic BEC / vendor payment diversion
- Evidence handling: SHA-256 integrity verification before analysis

## Evidence Reviewed

### Suspicious Email

File:

`Invoice_10482_Bank_Change.eml`

SHA-256:

`77b36abf4527e0e5e535d07c17f12293f2a219eff0da6ff3f54e27c0e8c20514`

Relevant headers:

- From: `Northstar Supply Accounts Receivable <billing@northstar-supply.test>`
- Reply-To: `northstar-payments@payment-update.test`
- Subject: `ACTION REQUIRED: Updated ACH Details - Invoice 10482`

### Attachment

File:

`Northstar_ACH_Update.txt`

SHA-256:

`73873d91b244fb7d26edfa36bcbe9e6237311df5d995fec546ec31bf8333678c`

The attachment contained synthetic replacement ACH payment instructions and no executable content.

## Email Indicators

The following indicators were identified:

1. **Reply-To mismatch**
   - The apparent sender used `northstar-supply.test`.
   - Replies were redirected to `payment-update.test`.

2. **Financial urgency**
   - The subject used `ACTION REQUIRED`.
   - The request referenced a specific outstanding invoice.

3. **Banking-information change**
   - The sender instructed the recipient to replace existing payment information.

4. **Confirmation request**
   - The recipient was asked to reply after updating the banking information.

Taken together, these characteristics are consistent with common vendor impersonation and payment-diversion BEC techniques.

## Endpoint Timeline

All timestamps below are UTC.

| Timestamp | Category | Activity |
|---|---|---|
| 2026-10-07 04:23:54.330 | Artifact placement | Scenario directory created in the user's Downloads folder |
| 2026-10-07 04:23:54.343 | Artifact placement | Suspicious email artifact placed in Downloads |
| 2026-10-07 04:23:54.343 | Artifact placement | ACH-update attachment placed in Downloads |
| 2026-10-07 04:23:55.598 | System activity | Windows Search indexed the email artifact |
| 2026-10-07 04:24:12.119 | User interaction | User opened the suspicious email artifact |
| 2026-10-07 04:24:36.386 | User interaction | User opened the ACH-update attachment |

## Telemetry Interpretation

Sysmon Event ID 11 records confirmed creation of the scenario directory and associated files.

Sysmon Event ID 1 records confirmed that the email artifact and ACH-update attachment were opened by the simulated user.

Windows `SearchProtocolHost.exe` also accessed the email artifact shortly after creation. This activity was classified as normal Windows Search indexing and was not treated as evidence of user execution.

Modern Notepad generated additional `/SESSION:` child-process activity when opening the files. These events were retained in the raw parsed telemetry but collapsed in the investigator-facing timeline to avoid representing application implementation details as separate user actions.

Several Sysmon registry events were labeled by the active rule set as `persistence-services`. Review of the underlying registry targets showed Windows Background Activity Moderator (BAM) state data rather than evidence that persistence had been established. The rule label alone was therefore not treated as proof of persistence.

## Findings

### Finding 1 — Suspicious Vendor Payment-Change Request

**Severity:** High

The message requested an immediate change to vendor banking information associated with an invoice. The combination of financial urgency, bank-detail modification, and a mismatched Reply-To address is consistent with payment-diversion BEC activity.

### Finding 2 — User Interaction Confirmed

**Severity:** Medium

Sysmon process-creation telemetry confirmed that the simulated user opened both the suspicious email artifact and the attached ACH instructions.

### Finding 3 — No Malware Execution Observed

**Severity:** Informational

The attachment was plain text and no evidence was identified of executable payloads, script execution, persistence, command-and-control traffic, or exploitation during the reviewed scenario.

### Finding 4 — Detection Labels Require Analyst Validation

**Severity:** Informational

A Sysmon rule categorized BAM registry activity under a persistence-oriented rule name. Inspection of the underlying telemetry showed that the activity did not establish persistence.

This demonstrates the need to validate alert context and underlying evidence rather than relying solely on rule names or automated classifications.

## Incident Assessment

The available evidence supports a simulated vendor payment-diversion attempt in which a user reviewed a suspicious payment-change request and its attachment.

The evidence does **not** support a conclusion that the endpoint was technically compromised.

The primary risk represented by the scenario is fraudulent modification of payment information through social engineering.

## Recommended Response Actions

If this were a real incident, recommended actions would include:

1. Suspend any pending payment associated with the requested banking change.
2. Verify the vendor's banking information using a previously established out-of-band contact method.
3. Preserve the original email, complete headers, attachments, and relevant mailbox audit data.
4. Review the affected mailbox for forwarding rules, suspicious sign-ins, OAuth grants, and additional related messages.
5. Search the organization for messages containing the same sender, Reply-To address, subject, or payment instructions.
6. Determine whether payment details were modified in accounting or ERP systems.
7. If funds were transferred, immediately engage the financial institution and applicable fraud-response processes.
8. If account compromise is identified, reset credentials, revoke sessions and tokens, review MFA state, and remove unauthorized mailbox changes.

## Evidence Limitations

This scenario used synthetic `.test` domains, fake banking data, and a controlled Windows lab environment.

The scenario did not include:

- a real Microsoft 365 tenant compromise,
- malicious OAuth activity,
- credential theft,
- real mailbox forwarding rules,
- real financial transactions,
- malware execution.

Those data sources would be required before making conclusions about mailbox compromise or financial loss in a real investigation.

## Conclusion

The investigation successfully reconstructed a controlled BEC/payment-diversion scenario using preserved email evidence, cryptographic hashes, Sysmon telemetry, automated EVTX parsing, and a normalized incident timeline.

The analysis demonstrates the distinction between suspicious social-engineering activity, normal operating-system behavior, misleading detection labels, and evidence of actual endpoint compromise.
