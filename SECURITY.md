# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities through GitHub's private vulnerability
reporting on this repository (Security tab, "Report a vulnerability"). Please do
not open a public issue for anything exploitable.

Include what you can: affected version or commit, reproduction steps, and the
impact you believe it has.

## Scope

This project is a read-only auditing script. The findings most relevant to it
are the ones that could expose the credentials it handles or corrupt the
evidence it produces:

- Leakage of `GITHUB_TOKEN` into process arguments, logs, or the output tree
- Command or argument injection through an organization or repository name
- Evidence tampering, including manifest collisions or omitted files
- Report content that would cause an assessor to accept a control that is not
  actually in place

## Handling audit output

Run directories contain organization membership, repository inventory, and open
vulnerability details. Treat them at the same sensitivity as the organization
they describe:

- `.gitignore` already excludes `github_compliance_audit_*/`; keep it that way
- Store completed runs where your other assessment evidence lives, not in a
  shared scratch directory
- `evidence_manifest.txt` records a SHA-256 of every collected file, so a
  package can be shown to be unmodified after the fact

## Token guidance

Use the narrowest token that completes the run. The script never writes and
never needs write scopes. Prefer a short-lived `gh auth` session over a
long-lived classic PAT, and revoke tokens created for a one-off assessment when
that assessment is done.
