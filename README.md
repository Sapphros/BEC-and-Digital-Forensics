# BEC and Digital Forensics

[![Python Tests](https://github.com/Sapphros/BEC-and-Digital-Forensics/actions/workflows/python-tests.yml/badge.svg)](https://github.com/Sapphros/BEC-and-Digital-Forensics/actions/workflows/python-tests.yml)

A hands-on incident-response project investigating a controlled business email compromise (BEC) and vendor payment-diversion scenario using email analysis, Windows Sysmon telemetry, evidence hashing, Python automation, and forensic timeline reconstruction.

The project demonstrates an end-to-end investigation workflow:

**preserve evidence -> verify integrity -> analyze email -> parse endpoint telemetry -> reconstruct activity -> distinguish signal from noise -> document findings**

## Project Highlights

- **61,607** Sysmon records processed from preserved endpoint evidence
- **128** events isolated to the incident window
- **6** high-value events retained in the normalized investigator timeline
- **4** BEC indicators identified through automated email analysis
- SHA-256 integrity verification performed before forensic analysis
- False-positive context identified in persistence-labeled BAM telemetry
- Consultant-style incident report produced with findings, limitations, and response recommendations
- **13 automated tests** enforced through GitHub Actions CI

### Review the Investigation

- [Scenario 001 Incident Report](reports/scenario-001-incident-report.md)
- [Scenario 002 Incident Report](reports/scenario-002-incident-report.md)
- [Investigator Timeline](analysis/scenario-001/investigator_timeline.csv)
- [Email Analysis](analysis/scenario-001/email_analysis.json)
- [Analysis Code](analysis/scenario-001/)
- [Automated Tests](tests/test_scenario_001.py)

## Skills Demonstrated

- Business Email Compromise investigation
- Digital forensics and evidence handling
- Incident response
- Email header and attachment analysis
- Windows Sysmon analysis
- Windows event-log parsing
- Python automation
- Forensic timeline reconstruction
- SHA-256 integrity verification
- Detection validation
- Analyst-driven false-positive assessment
- Technical incident reporting

## Scenario 001 - Vendor Payment Diversion

A finance user receives a message appearing to come from a vendor's accounts-receivable department.

The message states that the vendor's banking information has changed and directs the recipient to use new ACH information for an outstanding invoice.

The scenario contains several payment-diversion indicators:

- mismatched `From` and `Reply-To` domains
- financial urgency
- request to change existing banking information
- request for confirmation after the change
- attachment containing replacement payment instructions

All domains, identities, banking information, and artifacts used in this scenario are synthetic.

## Scenario 002 - Mailbox Account Compromise

Scenario 002 extends the investigation into cloud identity and mailbox compromise.

A finance account experiences suspicious authentication from an unfamiliar source and non-compliant device. The same session is then correlated with malicious mailbox activity.

### Key Results

- suspicious authentication identified from `203.0.113.77`
- unfamiliar and non-compliant device activity identified
- malicious inbox rule targeting invoice/payment messages identified
- external forwarding to a synthetic external address identified
- existing vendor correspondence accessed
- fraudulent payment-change email sent from the legitimate mailbox
- fraudulent message deleted from Sent Items
- **10 correlated investigator-timeline events**
- **5 documented incident findings**

The evidence supports mailbox compromise with high confidence.

The evidence does **not** establish how the attacker obtained the valid session or token. The MFA value `satisfied_by_token_claim` is therefore treated as an observation rather than proof of token theft or MFA bypass.

### Scenario 002 Deliverables

- [Investigation Plan](analysis/scenario-002/SCENARIO.md)
- [Compromise Analysis](analysis/scenario-002/compromise_analysis.json)
- [Investigator Timeline](analysis/scenario-002/investigator_timeline.csv)
- [Incident Report](reports/scenario-002-incident-report.md)
- [Scenario 002 Tests](tests/test_scenario_002.py)

## Key Findings

### Suspicious payment-change request

The email requested modification of existing vendor payment information and redirected replies to a different domain than the apparent sender.

The combination of payment urgency, bank-detail modification, and Reply-To mismatch was assessed as consistent with vendor impersonation and payment-diversion BEC activity.

### User interaction confirmed

Sysmon telemetry confirmed that the simulated user opened:

- `Invoice_10482_Bank_Change.eml`
- `Northstar_ACH_Update.txt`

This provided endpoint evidence supporting the reconstructed incident timeline.

### No malware execution observed

The attachment contained plain text.

The reviewed telemetry did not show evidence of:

- executable payloads
- malicious script execution
- persistence
- exploitation
- command-and-control activity

The scenario therefore represents a social-engineering/payment-diversion incident rather than a malware-based endpoint compromise.

### Background activity separated from user activity

Windows Search accessed the email artifact shortly after it appeared in the user's Downloads directory.

The associated `SearchProtocolHost.exe` activity was classified as background indexing rather than evidence of user execution.

### Detection labels independently validated

Some Sysmon registry events were tagged by the active rule configuration with a persistence-oriented rule name.

Review of the underlying registry targets showed Windows Background Activity Moderator (BAM) state data rather than evidence that persistence had actually been established.

This reinforced an important investigative principle:

> Detection labels provide context, but investigative conclusions should be based on the underlying evidence.

## Investigator Timeline

| UTC Timestamp | Category | Activity |
|---|---|---|
| 04:23:54.330 | Artifact placement | Scenario directory created |
| 04:23:54.343 | Artifact placement | Suspicious email artifact placed in Downloads |
| 04:23:54.343 | Artifact placement | ACH-update attachment placed in Downloads |
| 04:23:55.598 | System activity | Windows Search indexed the email artifact |
| 04:24:12.119 | User interaction | User opened the suspicious email |
| 04:24:36.386 | User interaction | User opened the ACH-update attachment |

The investigator-facing timeline is generated from raw Sysmon telemetry with Python.

Application-generated noise, including modern Notepad `/SESSION:` child processes, is retained in parsed telemetry but collapsed from the normalized timeline when it does not represent a distinct user action.

## Architecture

    Controlled Email Environment
              |
              | synthetic BEC artifacts
              v
    Windows Target
    WIN-TARGET-01
              |
              | Sysmon / Windows telemetry
              v
    Evidence Collection
              |
              | SHA-256 integrity verification
              v
    Linux Analysis Controller
              |
              +--> EVTX parsing
              +--> Email analysis
              +--> Timeline reconstruction
              +--> Analyst interpretation
              |
              v
    Incident Report

## Evidence Integrity

Evidence was hashed with SHA-256 before analysis.

The evidence package was transferred to the analysis system and independently verified against the acquisition manifest before parsing began.

Original synthetic email SHA-256:

    77b36abf4527e0e5e535d07c17f12293f2a219eff0da6ff3f54e27c0e8c20514

ACH attachment SHA-256:

    73873d91b244fb7d26edfa36bcbe9e6237311df5d995fec546ec31bf8333678c

Raw Windows event logs are intentionally excluded from the public repository.

Sanitized derived artifacts are used for demonstration while original forensic evidence is retained separately.

## Automated Analysis

### Email analysis

`analyze_email.py` extracts and evaluates:

- sender
- recipient
- Reply-To
- subject
- Message-ID
- message body
- attachments
- SHA-256 hashes
- BEC-related indicators

The analysis identifies:

- Reply-To mismatch
- financial urgency
- banking-information change
- request for confirmation after the payment change

### Sysmon parsing

`parse_sysmon.py`:

1. reads preserved Sysmon EVTX evidence
2. restricts processing to the relevant incident window
3. parses relevant Sysmon fields
4. produces structured JSON and CSV telemetry

The original Sysmon export contained more than 61,000 records.

Automated analysis reduced this to 128 events within the incident window before scenario-specific filtering.

### Timeline reconstruction

`build_timeline.py` identifies scenario-related telemetry.

`build_investigator_timeline.py` converts technical events into an investigator-facing timeline while distinguishing:

- artifact placement
- user interaction
- background operating-system activity
- application implementation noise

## Repository Structure

    BEC-and-Digital-Forensics/
    |
    +-- README.md
    +-- analysis/
    |   +-- scenario-001/
    |       +-- analyze_email.py
    |       +-- parse_sysmon.py
    |       +-- build_timeline.py
    |       +-- build_investigator_timeline.py
    |       +-- email_analysis.json
    |       +-- sysmon_scenario_events.csv
    |       +-- sysmon_scenario_events.json
    |       +-- scenario_timeline.csv
    |       +-- investigator_timeline.csv
    |
    +-- evidence/
    |   +-- scenario-001/
    |       +-- Invoice_10482_Bank_Change.eml
    |       +-- Northstar_ACH_Update.txt
    |       +-- incident_start.txt
    |       +-- collection_notes.txt
    |       +-- sha256_manifest.csv
    |
    +-- reports/
    |   +-- scenario-001-incident-report.md
    |
    +-- tests/
    |   +-- test_scenario_001.py
    |
    +-- .gitignore

## Incident Response Recommendations

For a real vendor payment-diversion incident, response actions would include:

1. Suspend pending payments associated with the request.
2. Verify vendor payment details using a previously established out-of-band contact method.
3. Preserve the original email, complete headers, and attachments.
4. Review mailbox sign-in activity.
5. Inspect forwarding and inbox rules.
6. Review OAuth grants and active sessions.
7. Search the organization for related messages and indicators.
8. Determine whether accounting or ERP records were modified.
9. Contact financial institutions immediately if funds were transferred.

If mailbox compromise were confirmed, additional response actions would include credential reset, token and session revocation, MFA review, and removal of unauthorized mailbox changes.

## What I Learned

This project reinforced several practical incident-response lessons:

- establish evidence integrity before analysis
- distinguish what the evidence proves from what remains unknown
- validate detection logic against underlying telemetry
- separate operating-system background activity from user actions
- recognize that user interaction does not automatically imply malware execution
- understand that BEC may primarily be a financial-fraud and identity investigation rather than a malware investigation
- normalize noisy endpoint telemetry into a concise investigator-facing timeline
- preserve original evidence separately from public portfolio artifacts

## Testing

The project includes automated tests covering:

- synthetic email integrity
- attachment integrity
- expected BEC indicators
- investigator-timeline user actions
- expected normalized event count

Run the tests with:

    pytest -q

## Limitations

This is a controlled laboratory scenario.

It does not represent a real organization, vendor, bank account, or actual compromise.

Scenario 001 intentionally does not include:

- real Microsoft 365 authentication data
- mailbox forwarding-rule abuse
- OAuth compromise
- credential theft
- real financial transactions
- malware execution

Future scenarios can extend the project with additional identity, mailbox, endpoint, and forensic evidence sources.

## Disclaimer

This repository contains synthetic artifacts created for defensive cybersecurity training, incident-response practice, and portfolio demonstration.

No real credentials, financial information, organizations, or victims are represented.
