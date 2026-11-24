# Security Policy

## Scope

wsmancer is an offensive security tool. Its purpose is to run commands on remote
Windows hosts during authorized penetration tests, so "it can execute commands
on a target" is by design, not a vulnerability.

A security issue in wsmancer is a flaw in the tool itself that could harm its
users or the systems they run it on in unintended ways. Examples:

- Credential leakage: passwords, NT hashes, or Kerberos tickets exposed to
  unauthorized parties, leaked into logs or history, or transmitted when they
  should not be.
- Remote code execution in the tool (not in the target): input from the remote
  PowerShell session, a crafted PSRP response, or a malicious certificate that
  leads to code execution on the operator's machine.
- Path traversal in file transfer: a crafted remote filename that writes outside
  the intended destination directory during `download`.
- TLS verification bypass: a code path where `--ca-cert` or
  `--accept-fingerprint` silently falls through to no verification.
- Message sealing bypass: a code path where the NTLM or Kerberos integrity
  check is skipped, allowing an in-path attacker to modify sealed responses.
- Denial of service against the operator's machine (resource exhaustion from
  crafted PSRP responses).
- Dependency vulnerabilities that are reachable through wsmancer's code paths.

Not in scope: vulnerabilities in targets discovered using wsmancer, or the
intended ability to execute commands, transfer files, and inject payloads on
authorized targets.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report via one of:

- **GitHub Security Advisories:** use the "Report a vulnerability" button on the
  Security tab of the repository. This creates a private advisory visible only to
  maintainers.
- **GitHub:** contact [@SREsAreHumanToo](https://github.com/SREsAreHumanToo)
  directly.

Include:

1. A description of the vulnerability and its impact.
2. Steps to reproduce or a proof of concept.
3. The version or commit hash you tested against.
4. Your assessment of severity (optional but helpful).

## Response timeline

- **Acknowledgment:** within 72 hours of receipt.
- **Initial assessment:** within 7 days. We will confirm whether the report is
  accepted and provide an estimated timeline for a fix.
- **Fix release:** we aim to release a patch within 30 days of confirming a
  vulnerability, though complex issues may take longer. We will keep you informed
  of progress.
- **Disclosure:** we will coordinate disclosure timing with you. We ask for a
  90-day disclosure window from the date of the report, but we are open to
  negotiation.

## Credit

We are happy to credit reporters in release notes and the advisory unless you
prefer to remain anonymous. Let us know your preference when reporting.
