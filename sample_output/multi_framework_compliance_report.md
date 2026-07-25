# GitHub Multi-Framework Compliance Report for acme-corp

**Generated**: 2026-07-25T12:00:00Z (UTC) by github_compliance_audit.sh v2.0.0

## Executive Summary

| | |
|---|---|
| Organization | acme-corp |
| Repositories discovered | 5 |
| Repositories scored | 3 (archived: 1, excluded unless `INCLUDE_ARCHIVED=true`) |
| Risk score | **47/100** (lower is better) |
| Compliance level | **Medium** |

### Scope and evidence quality

- Coverage percentages are calculated over the 3 scored repositories.
- `?` marks a control that could not be assessed with this token rather than one that failed.
- **Repositories that returned no alert data: 1.** Dependabot, code scanning,
  or secret scanning is disabled there, or the token lacks `security_events`. Treat their
  vulnerability posture as unknown, not clean.
- **The organization audit log was not readable.** It requires GitHub Enterprise Cloud plus
  an owner-scoped token, so audit trail controls below are reported as not assessed.

### Framework Readiness Summary

Readiness reflects only the configuration signals this tool can measure. It is an
input to an assessment, never a substitute for one.

| Framework | Branch protection | Review enforcement | Scanning | Overdue findings | Readiness |
|-----------|-------------------|--------------------|----------|------------------|-----------|
| FedRAMP / NIST | ⚠ 66% | ✗ 33% | ✗ 33% | ✗ 2 | Gaps identified |
| SOC 2 | ✗ 66% | ✗ 33% | ✗ 33% | ✗ 2 | Gaps identified |
| HIPAA | ✗ 66% | ✗ 33% | ✗ 33% | ✗ 2 | Gaps identified |
| ISO 27001 | ⚠ 66% | ✗ 33% | ✗ 33% | ✗ 2 | Gaps identified |
| PCI-DSS | ✗ 66% | ✗ 33% | ✗ 33% | ✗ 2 | Gaps identified |

### Universal Security Controls Assessment

| Control Area | Current State | FedRAMP | SOC 2 | HIPAA | ISO 27001 | PCI-DSS |
|-------------|--------------|---------|-------|-------|-----------|---------|
| Multi-factor authentication | true | Required | Required | Required | Required | Required |
| Branch protection or ruleset | 66% | 80%+ | 90%+ | 100% | 80%+ | 100% |
| Code owner review required | 33% | 80%+ | 90%+ | 100% | 80%+ | 100% |
| Code scanning coverage | 33% | Required | Required | Required | Required | Required |
| Secret scanning push protection | 33% | Required | Required | Required | Required | Required |
| Open findings past due | 2 | 0 | 0 | 0 | 0 | 0 |
| Audit log accessible | false | Required | Required | Required | Required | Required |
| Actions pinned to a commit SHA | 66% | 80%+ | Recommended | Recommended | 80%+ | Recommended |
| SBOM generation | 33% | 50%+ | N/A | N/A | 60%+ | Required (6.3.2) |
| Artifact signing or attestation | 33% | 50%+ | N/A | 95%+ | Recommended | Recommended |

### Open findings

| Source | Open | Critical | High | Past due | Repositories with no visibility |
|--------|------|----------|------|----------|---------------------------------|
| Dependabot | 4 | 1 | 1 | 2 | 0 |
| Code scanning | 0 | 0 | 0 | 0 | 1 |
| Secret scanning | 1 | - | 1 | 0 | 1 |

Remediation windows used: critical 15 days, high 30, medium 90, low 180.

### Critical Actions Required Across All Frameworks

- **CRITICAL**: Enable code scanning (currently 33% of repositories)
- **CRITICAL**: Enable secret scanning push protection (currently 33%)
- **HIGH**: Increase branch protection to 80%+ minimum (currently 66%)
- **HIGH**: Remediate 2 findings that are past their window
- **HIGH**: Obtain organization audit log access and configure log streaming
- **MEDIUM**: Pin third-party Actions to commit SHAs (currently 66%)

### Score breakdown

Every point below is attributable to a measured control. Total earned:
53/100, giving a risk score of 47.

| Control | Points earned | Maximum |
|---------|---------------|---------|
| Multi-factor authentication | 15 | 15 |
| Branch protection coverage | 13 | 20 |
| Review quality (code owners) | 3 | 10 |
| Secret scanning push protection | 4 | 15 |
| Code scanning coverage | 3 | 10 |
| Dependency monitoring | 3 | 5 |
| Remediation timeliness | 5 | 10 |
| Code ownership | 3 | 5 |
| Action pinning | 3 | 5 |
| SBOM and provenance | 1 | 5 |

### Detailed Framework Assessments

Re-run with a framework argument for the full control table:
`fedramp`, `nist`, `soc2`, `hipaa`, `iso27001`, `pci-dss`.

### Audit Metadata

- **Audit date**: 2026-07-25T12:00:00Z (UTC)
- **Tool version**: 2.0.0
- **Repositories discovered / scored**: 5 / 3
- **Machine-readable summary**: `summary.json`
- **Evidence manifest**: `evidence_manifest.txt` (SHA-256 of every collected file)
- **Output directory**: sample_output

