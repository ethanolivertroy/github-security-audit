# GitHub Multi-Framework Compliance Audit

Auditors keep asking the same question: *is this GitHub org actually configured the way FedRAMP, SOC 2, HIPAA, ISO 27001, or PCI-DSS expect?* This Bash tool answers that with evidence, not vibes.

Point it at an organization. It pulls org- and repo-level security settings through the GitHub API, scores the gaps, and writes a markdown report mapped to the framework you care about. Pair it with the [manual evaluation guide](./github_evaluation_guide.md) when you need UI walkthroughs and checklist depth the API cannot see.

<img src="graphic.webp" width="500" alt="GitHub multi-framework compliance audit overview">

## What it checks

**Organization**
- Mandatory 2FA, security managers actually assigned, audit log access
- Default security settings for new repositories, org webhooks, installed GitHub Apps
- Org-level security policy presence

**Repositories**
- Branch protection *and* repository rulesets, including how strong the rule is: required approvals, code owner review, stale review dismissal, admin enforcement, signed commits, linear history
- Dependabot, code scanning, secret scanning and push protection enablement
- CODEOWNERS and per-repository security policies

**Supply chain**
- Actions pinned to a full commit SHA, parsed out of the workflow files themselves
- Explicit `permissions:` blocks in workflows
- SBOM, signing, and provenance steps in workflow bodies, plus `.sig` and SBOM attachments on the latest release

**Findings**
- Open alerts only, counted by severity
- Age against a remediation window (critical 15 days, high 30, medium 90, low 180) so overdue findings are visible

**Reports**
- One framework or all at once
- Risk score from 0-100 (lower is better) with a published per-control breakdown, plus a High / Medium / Low compliance level
- Control mappings and prioritized remediation
- `summary.json` for dashboards and `evidence_manifest.txt` for chain of custody

Supported frameworks: FedRAMP, NIST SP 800-53, NIST SP 800-161, SOC 2 Type II, HIPAA Security Rule, ISO 27001:2022, PCI-DSS v4.0.

### What it does not do

A control the token cannot see is reported as `?`, not as a pass or a failure.
Common causes: the organization audit log needs GitHub Enterprise Cloud, and
alert endpoints need `security_events` plus the feature switched on. The report
says so at the top rather than quietly scoring you.

Archived and empty repositories are excluded from coverage percentages, because
neither can carry branch protection and counting them produces a gap you cannot
close. Set `INCLUDE_ARCHIVED=true` to score them anyway.

## Quick start

```bash
# Dependencies: jq and curl are required, GNU parallel is optional
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

### Tuning

| Environment variable | Default | Purpose |
|----------------------|---------|---------|
| `GITHUB_TOKEN` | `gh auth token` | Token to authenticate with |
| `GITHUB_API_URL` | `https://api.github.com` | Point at GitHub Enterprise Server |
| `MAX_PARALLEL_JOBS` | `10` | Concurrent repository scans |
| `MAX_WORKFLOWS_PER_REPO` | `25` | Caps workflow file downloads per repository |
| `INCLUDE_ARCHIVED` | `false` | Score archived repositories too |
| `OUTPUT_DIR` | timestamped | Where to write evidence |
| `AUDIT_RUNNER` | auto | Force `parallel` or `xargs` |
| `AUDIT_NOW_EPOCH` | now | Pin the clock so a run can be re-scored identically later |

Exit codes: `0` success, `1` usage or access error, `2` the run produced a Low
compliance level. The last one lets CI gate on posture without parsing markdown.

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

| Path | Contents |
|------|----------|
| `summary.json` | Every measurement and score in one machine-readable file |
| `<framework>_compliance_report.md` | The narrative report |
| `evidence_manifest.txt` | SHA-256 of every collected file |
| `organization_info.json`, `org_security/` | Members, teams, 2FA, audit sample, webhooks, apps |
| `repositories/<repo>/analysis.json` | Per-repository findings, already reduced |
| `repositories/<repo>/` | Raw API evidence: protection, rulesets, alerts, workflows, releases |
| `repository_analysis.jsonl` | All per-repository findings, one JSON object per line |

Report file names by framework:

| Framework | Report file |
|-----------|-------------|
| `all` | `multi_framework_compliance_report.md` |
| `fedramp` / `nist` | `fedramp_nist_compliance_report.md` |
| `soc2` | `soc2_compliance_report.md` |
| `hipaa` | `hipaa_compliance_report.md` |
| `iso27001` | `iso27001_compliance_report.md` |
| `pci-dss` | `pci_dss_compliance_report.md` |

Browse [`sample_output/`](./sample_output) for a fictional walkthrough of an
organization with one well-governed repository, one neglected one, one governed
by a ruleset instead of branch protection, one archived, and one empty:

- [Multi-framework report](./sample_output/multi_framework_compliance_report.md)
- [Machine-readable summary](./sample_output/summary.json)
- [Per-repository findings](./sample_output/repositories/payments-api/analysis.json)
- [Branch protection evidence](./sample_output/repositories/payments-api/branches/default_protection.json)

The sample is generated by `tests/refresh_sample_output.sh` from the same
fixtures the test suite uses, so it cannot drift from what the script emits.

### Scoring

The risk score is 100 minus the points earned across ten weighted controls, and
every report prints the breakdown so you can argue with the weighting:

| Control | Max points |
|---------|-----------|
| Multi-factor authentication | 15 |
| Branch protection or ruleset coverage | 20 |
| Secret scanning push protection | 15 |
| Review quality (code owner review required) | 10 |
| Code scanning coverage | 10 |
| Remediation timeliness (nothing past due) | 10 |
| Dependency monitoring | 5 |
| Code ownership | 5 |
| Actions pinned to a commit SHA | 5 |
| SBOM and provenance | 5 |

0-20 is High, 21-50 Medium, above 50 Low. The number is a prioritisation aid,
not an assessment outcome.

## Manual evaluation guide

Automation catches configuration. Humans still need to click through policy, process, and intent. The [evaluation guide](./github_evaluation_guide.md) walks org and repo controls with UI steps, `gh api` checks, and checklists mapped across the same frameworks, including NIST 800-161 supply chain, EO 14028, and Zero Trust angles.

Use the script for breadth. Use the guide when an assessor asks *how* you verified a control.

## Control families (NIST-focused runs)

**800-53:** AC, IA, AU, CM, RA, SI, SC, SA  
**800-161:** SR-2 through SR-5, SR-8 through SR-11, SR-13 (provenance, authenticity, incident response, and related supply-chain controls)

FedRAMP authorization packages lean on those 800-53 baselines. EO 14028 expectations show up largely through the 800-161 supply-chain lens. This tool does not authorize you. It gives you a faster, evidence-backed starting point for the SSP and continuous monitoring story.

## Rate limits and cadence

Large orgs burn through API quota. Budget roughly a dozen API calls per
repository plus one per workflow file, so a 500-repository org costs several
thousand calls against a 5,000/hour authenticated ceiling. Lower
`MAX_PARALLEL_JOBS` or `MAX_WORKFLOWS_PER_REPO` if you are sharing the quota.
The script backs off on `Retry-After` and `x-ratelimit-reset` rather than
guessing, and it does not retry a 403 caused by missing scopes.

Practical rhythm:

1. Run monthly or quarterly (more often before an assessment).
2. File the report, `summary.json`, and `evidence_manifest.txt` with your continuous monitoring evidence.
3. Close the gaps the report flags, then re-run and diff `summary.json` to prove movement.
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

## Development

The test suite runs the script end to end against a mock GitHub API, so it needs
no network access and no GitHub account:

```bash
bash tests/run_tests.sh
shellcheck github_compliance_audit.sh tests/run_tests.sh tests/mock_api/curl
```

`tests/mock_api/curl` shadows the real `curl` on `PATH` and serves the fixture
tree under `tests/fixtures/`. To add a case, drop a JSON file at the path that
mirrors the API endpoint. A `.status` file next to it forces a non-200 response,
which is how the fixtures exercise the "control could not be assessed" path.

After changing collection, scoring, or a report template, refresh the published
sample so it matches:

```bash
bash tests/refresh_sample_output.sh
```

## Contributing

Pull requests welcome. Please keep `shellcheck` clean and add a test for any
control whose scoring you change: a compliance tool that reports a false pass is
worse than no tool at all.

## License

[MIT](./LICENSE). If you use the tool, please keep attribution to the original author.
