# Incident Report - Mailbox Account Compromise

## Executive Summary

A simulated cloud-email account compromise affecting `finance@sapphros.test` was investigated using synthetic authentication and mailbox-audit evidence.

Analysis identified a successful authentication from an unusual source at `203.0.113.77` associated with Frankfurt, Germany. The session originated from an unidentified, non-compliant Linux device and was marked with unfamiliar sign-in properties.

The same session subsequently accessed mailbox content, created an inbox rule targeting invoice and payment messages, enabled external mailbox forwarding, reviewed an existing vendor conversation, sent a fraudulent payment-change message from the legitimate mailbox, and deleted the message from Sent Items.

The available evidence supports the conclusion that the mailbox was compromised.

The evidence does not establish how the attacker obtained the valid authentication session or token.

## Scope

Target account:

`finance@sapphros.test`

Evidence reviewed:

- authentication events
- mailbox audit events
- synthetic outbound email
- evidence integrity manifest
- correlated investigator timeline

All identities, domains, IP addresses, and financial data used in this scenario are synthetic.

## Known-Good Baseline

Legitimate activity was associated with:

- IP address: `198.51.100.25`
- location: Denver, US
- device: `FIN-WS01`
- compliant device: true
- client: Windows / Microsoft Outlook

This baseline was used to distinguish expected activity from suspicious authentication and mailbox behavior.

## Incident Timeline

All timestamps are UTC.

| Timestamp | Activity |
|---|---|
| 14:02:41 | Failed authentication from `203.0.113.77` |
| 14:03:12 | Successful authentication from same unusual source |
| 14:04:05 | Exchange Online accessed through suspicious session |
| 14:04:38 | Recent invoice and vendor messages accessed |
| 14:05:21 | Inbox rule created targeting invoice/payment messages |
| 14:06:03 | External mailbox forwarding enabled |
| 14:09:44 | Existing vendor conversation reviewed |
| 14:11:47 | Suspicious Exchange Online session remained active |
| 14:12:16 | Fraudulent payment-change email sent |
| 14:15:31 | Fraudulent message deleted from Sent Items |

## Findings

### Finding 1 - Suspicious Successful Authentication

**Severity:** Critical

A successful authentication occurred from `203.0.113.77`, an address not present in the known-good activity baseline.

The authentication differed from legitimate activity in several ways:

- unusual geographic location
- unidentified device
- device marked non-compliant
- Linux browser rather than expected Windows activity
- unfamiliar sign-in properties

MFA was recorded as `satisfied_by_token_claim`.

This demonstrates that MFA requirements were represented as satisfied for the session. It does not establish how the valid token or session was obtained.

### Finding 2 - Suspicious Inbox Rule

**Severity:** High

The suspicious session created an inbox rule named `Invoice Archive`.

The rule targeted messages containing:

- `invoice`
- `payment`

and configured them to:

- move to `RSS Feeds`
- be marked as read

This behavior is consistent with mailbox concealment intended to reduce the likelihood that the legitimate user notices financial correspondence.

### Finding 3 - External Mailbox Forwarding

**Severity:** Critical

The suspicious session enabled forwarding to:

`payments-review@external-mail.test`

with delivery configured to both the original mailbox and the forwarding destination.

This provided an external mechanism for continued access to incoming mailbox content.

### Finding 4 - Fraudulent Outbound Email

**Severity:** Critical

The suspicious session accessed an existing vendor conversation and subsequently sent a payment-change message from the legitimate finance mailbox.

This represents abuse of a trusted identity and would significantly increase the credibility of a payment-diversion attempt.

### Finding 5 - Evidence Concealment

**Severity:** High

The fraudulent outbound message was subsequently deleted from Sent Items by the same suspicious session.

This activity is consistent with an effort to conceal the attacker's outbound activity from the legitimate mailbox owner.

## Incident Assessment

The evidence supports mailbox compromise with high confidence.

The following actions were correlated to a single suspicious session:

1. suspicious successful authentication
2. mailbox reconnaissance
3. inbox-rule creation
4. external forwarding configuration
5. vendor conversation access
6. fraudulent outbound email
7. deletion of the fraudulent sent message

The activity occurred from the same source IP address and session identifier.

## MFA Interpretation

The authentication record contains:

`satisfied_by_token_claim`

This should not be interpreted as proof of MFA bypass or token theft.

It establishes only that the authentication system treated the MFA requirement as already satisfied based on the token presented.

Additional identity-provider telemetry would be required to determine whether the attacker obtained the session through:

- token theft
- adversary-in-the-middle phishing
- stolen browser/session data
- previously authenticated session abuse
- another mechanism

## Endpoint Assessment

The evidence set does not contain corresponding endpoint compromise indicators.

Therefore, this investigation supports a conclusion of **mailbox/account compromise**, but does not establish that the user's Windows workstation was compromised.

Additional EDR, browser, network, and endpoint forensic evidence would be needed to make that determination.

## Recommended Containment Actions

For a real incident:

1. Disable or temporarily block the affected account.
2. Revoke active sessions and refresh tokens.
3. Reset the account password.
4. Re-register or review MFA methods.
5. Remove unauthorized inbox rules.
6. Disable unauthorized external forwarding.
7. Review delegated mailbox permissions.
8. Review OAuth application grants.
9. Search for additional fraudulent outbound messages.
10. Search the organization for related attacker indicators.
11. Notify affected vendors or recipients.
12. Verify whether fraudulent payment instructions were acted upon.
13. Review identity-provider logs for the initial access mechanism.
14. Investigate the endpoint for token or credential theft.

## Evidence Gaps

The available evidence does not establish:

- the original credential or token acquisition method
- whether the legitimate endpoint was compromised
- whether payment instructions resulted in financial loss
- whether additional accounts were affected
- whether the attacker retained another access mechanism

These questions would require additional evidence collection.

## Conclusion

The investigation identified a coherent sequence of malicious cloud-mailbox activity tied to a single suspicious session.

The evidence demonstrates successful account access, mailbox reconnaissance, persistence and concealment through mailbox configuration, fraudulent use of the trusted account, and subsequent deletion of evidence.

The investigation also demonstrates the importance of distinguishing confirmed observations from hypotheses about how initial access occurred.
