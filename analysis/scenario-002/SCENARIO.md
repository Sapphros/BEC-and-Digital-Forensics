# Scenario 002 - Mailbox Account Compromise

## Objective

Investigate a simulated cloud-email account compromise using synthetic authentication,
mailbox-audit, and message evidence.

The investigation will determine:

- whether an account was accessed suspiciously
- whether mailbox settings were modified
- whether persistence was established through inbox or forwarding rules
- whether the compromised account was used to send fraudulent messages
- what evidence supports or does not support account compromise
- what containment and eradication actions should be recommended

## Scenario Summary

A finance user's mailbox is accessed from an unusual source.

Shortly afterward:

1. a suspicious authentication event occurs
2. a new mailbox rule is created
3. messages related to invoices are redirected or hidden
4. a fraudulent payment-change email is sent from the legitimate mailbox
5. normal endpoint telemetry does not show corresponding local compromise

The investigation must correlate identity, mailbox, and message evidence to determine
the likely attack sequence.

## Evidence Sources

Synthetic evidence will include:

- authentication events
- mailbox audit events
- inbox/forwarding rule changes
- outbound email metadata
- IP-address indicators
- user-agent information
- timestamps
- message identifiers

All identities, addresses, IP addresses, and organizations will be synthetic.

## Investigation Questions

1. What was the first suspicious event?
2. Was authentication successful?
3. Was MFA involved?
4. What mailbox changes occurred after authentication?
5. Did the attacker establish mailbox persistence?
6. Were messages hidden, redirected, or forwarded?
7. Was the legitimate account used to send fraudulent email?
8. Is there evidence of endpoint compromise?
9. What evidence gaps remain?
10. What containment actions should be performed?

## Planned Analysis

Python tooling will:

- parse authentication evidence
- parse mailbox audit evidence
- normalize timestamps
- identify suspicious authentication characteristics
- identify mailbox-rule changes
- correlate events by account and time
- produce a normalized investigator timeline
- assign findings based on observed evidence

## Expected Deliverables

- synthetic authentication dataset
- synthetic mailbox-audit dataset
- suspicious-email artifact
- SHA-256 evidence manifest
- Python parsers and correlation tooling
- investigator-facing timeline
- automated tests
- consultant-style incident report
