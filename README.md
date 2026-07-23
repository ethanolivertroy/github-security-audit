# GitHub Multi-Framework Compliance Audit

Auditors keep asking the same question: *is this GitHub org actually configured the way FedRAMP, SOC 2, HIPAA, ISO 27001, or PCI-DSS expect?* This Bash tool answers that with evidence, not vibes.

Point it at an organization. It pulls org- and repo-level security settings through the GitHub API, scores the gaps, and writes a markdown report mapped to the framework you care about. Pair it with the [manual evaluation guide](./github_evaluation_guide.md) when you need UI walkthroughs and checklist depth the API cannot see.

<img src="graphic.webp" width="500" alt="GitHub multi-framework compliance audit overview">

## What it checks

**Organization**
- Mandatory 2FA, security managers, audit log access
- GHAS status, enterprise settings, org webhooks, installed GitHub Apps
- Org-level security policy presence

**Repositories**
- Branch protection and repository rulesets
- Dependabot, code scanning, secret scanning (including push protection)
- CODEOWNERS, security policies, workflow permission and action-pinning heuristics

**Supply chain**
- SBOM signals, artifact signing, provenance and attestation clues
- Dependency review and Action pinning patterns

**Reports**
- One framework or all at once
- Risk score from 0–100 (lower is better) plus High / Medium / Low compliance level
- Control mappings and prioritized remediation

Supported frameworks: FedRAMP, NIST SP 800-53, NIST SP 800-161, SOC 2 Type II, HIPAA Security Rule, ISO 27001:2022, PCI-DSS v4.0.

## Quick start

```bash
# Dependencies
brew install gh jq parallel   # macOS
# sudo apt install gh jq parallel   # Debian/Ubuntu

gh auth login
chmod +x github_compliance_audit.sh

# All frameworks (default)
./github_compliance_audit.sh your-org-name

# One framework
./github_compliance_audit.sh your-org-name soc2
```

Or download just the script:

```bash
curl -O https://raw.githubusercontent.com/ethanolivertroy/github-security-audit/main/github_compliance_audit.sh
chmod +x github_compliance_audit.sh
```

You need admin (or equivalent) access to the org. Security manager role helps for the deeper security endpoints.

### Framework flags

| Flag | Report focus |
|------|----------------|
| `all` (default) | Combined multi-framework summary |
| `fedramp` / `nist` | FedRAMP + NIST 800-53 / 800-161 |
| `soc2` | SOC 2 Trust Service Criteria |
| `hipaa` | HIPAA Security Rule (45 CFR § 164.308–312) |
| `iso27001` | ISO 27001:2022 Annex A |
| `pci-dss` | PCI-DSS v4.0 |

Each run writes a timestamped directory: `github_compliance_audit_<framework>_<timestamp>/`.

## Authentication

**Preferred:** `gh auth login`, then run the script. It reuses your CLI session.

**Token (CI, headless, or higher rate limits):**

```bash
export GITHUB_TOKEN=ghp_xxxxxxxxxxxx
./github_compliance_audit.sh your-org-name [framework]
```

Classic PAT scopes that matter:

- `repo`
- `read:org`
- `admin:org_hook`
- `security_events`

Create one under **Settings → Developer settings → Personal access tokens → Tokens (classic)**. Copy it once; GitHub will not show it again.

### Finding your org name

It is the slug in the URL: `https://github.com/acme-corporation` means the org name is `acme-corporation`. You can also find it under your profile menu → **Your organizations**.

## Output

Inside the run directory you get:

- `organization_info.json` and `org_security/` (members, teams, 2FA, audit sample, webhooks, apps, …)
- `repositories/<repo>/` with branch protection, alerts, and related JSON evidence
- A framework report:

| Framework | Report file |
|-----------|-------------|
| `all` | `multi_framework_compliance_report.md` |
| `fedramp` / `nist` | `fedramp_nist_compliance_report.md` |
| `soc2` | `soc2_compliance_report.md` |
| `hipaa` | `hipaa_compliance_report.md` |
| `iso27001` | `iso27001_compliance_report.md` |
| `pci-dss` | `pci_dss_compliance_report.md` |

Browse [`sample_output/`](./sample_output) for a fictional walkthrough:

- [Organization info](./sample_output/organization_info.json)
- [Branch protection](./sample_output/repositories/example-repo/branches/main_protection.json)
- [Dependabot / code / secret alerts](./sample_output/repositories/example-repo/)
- [FedRAMP/NIST sample report](./sample_output/fedramp_nist_compliance_report.md)

## Manual evaluation guide

Automation catches configuration. Humans still need to click through policy, process, and intent. The [evaluation guide](./github_evaluation_guide.md) walks org and repo controls with UI steps, `gh api` checks, and checklists mapped across the same frameworks, including NIST 800-161 supply chain, EO 14028, and Zero Trust angles.

Use the script for breadth. Use the guide when an assessor asks *how* you verified a control.

## Control families (NIST-focused runs)

**800-53:** AC, IA, AU, CM, RA, SI, SC, SA  
**800-161:** SR-2 through SR-5, SR-8 through SR-11, SR-13 (provenance, authenticity, incident response, and related supply-chain controls)

FedRAMP authorization packages lean on those 800-53 baselines. EO 14028 expectations show up largely through the 800-161 supply-chain lens. This tool does not authorize you. It gives you a faster, evidence-backed starting point for the SSP and continuous monitoring story.

## Rate limits and cadence

Large orgs burn through API quota. Authenticated tokens raise the ceiling; off-peak runs and framework-scoped passes help when you hit walls.

Practical rhythm:

1. Run monthly or quarterly (more often before an assessment).
2. File the report and JSON tree with your continuous monitoring evidence.
3. Close the gaps the report flags, then re-run to prove movement.
4. Feed findings into the SSP, not as a substitute for one.

## References

**GitHub**
- [Org security settings](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization)
- [Branch protection](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
- [Security managers](https://docs.github.com/en/organizations/managing-peoples-access-to-your-organization-with-roles/managing-security-managers-in-your-organization)
- [GitHub Advanced Security](https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security)
- [Audit log](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization)

**Supply chain**
- [Dependency review](https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/about-dependency-review) · [Dependency graph](https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/about-the-dependency-graph) · [SBOM export](https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/exporting-a-software-bill-of-materials-for-your-repository)
- [SLSA](https://slsa.dev/) · [Sigstore](https://www.sigstore.dev/)
- [NIST SP 800-161r1-upd1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-161r1-upd1.pdf)
- [Executive Order 14028](https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/)

## Disclaimer

This tool is not endorsed by GitHub or any accreditation body. It helps you assess configuration against common control language. It is not, by itself, compliance.

Bring qualified security and compliance judgment to any authorization or certification effort.

## Contributing

Pull requests welcome.

## License

[MIT](./LICENSE). If you use the tool, please keep attribution to the original author.
