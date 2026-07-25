# GitHub Multi-Framework Compliance Evaluation Guide

The audit script tells you what the API can see. This guide is for everything else: the clicks, the policy questions, and the evidence an assessor will actually ask for.

Work through org settings, representative repositories, CI/CD, and supply chain controls against:

- **FedRAMP** and **NIST 800-53 Rev 5**
- **NIST 800-161 Rev 1 Update 1** (supply chain risk management)
- **SOC 2 Type II** (Trust Service Criteria)
- **HIPAA Security Rule** (45 CFR § 164.308–312)
- **ISO 27001:2022** (Annex A)
- **PCI-DSS v4.0.1**

Each section pairs Admin UI steps with `gh api` checks and a short checklist. Supply chain material leans on NIST 800-161r1-upd1 and Executive Order 14028. Use this beside `github_compliance_audit.sh`, not instead of it.

### Versions this guide is written against

Control identifiers move. Check these before quoting a mapping in a deliverable.

| Standard | Version used here | Notes |
|----------|-------------------|-------|
| NIST SP 800-53 | Rev 5 | FedRAMP baselines derive from it |
| NIST SP 800-161 | Rev 1 Update 1 | Supply chain, SR family |
| SOC 2 | TSC 2017 with 2022 points of focus | |
| HIPAA Security Rule | Current rule (2013) | A January 2025 proposed rule would add mandatory MFA, encryption, and asset inventory. Not final; final action projected 2027. The current rule still governs. |
| ISO/IEC 27001 | 2022 | 2013 certificates expired 31 October 2025 |
| PCI DSS | v4.0.1 | v4.0 retired 31 December 2024. The 51 future-dated requirements have been mandatory since 31 March 2025, so they are scored as ordinary requirements. |

On the GitHub side, Advanced Security was unbundled on 1 April 2025 into
**GitHub Code Security** and **GitHub Secret Protection**, and the organization
`*_enabled_for_new_repositories` API fields were removed on 21 April 2026 in
favour of code security configurations. Where this guide says "Advanced
Security", read it as whichever of the two products covers the feature.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Organization-level Security](#organization-level-security)
   - [Account Management](#account-management-ac-2)
   - [Access Enforcement](#access-enforcement-ac-3-ac-6)
   - [Information Flow Enforcement](#information-flow-enforcement-ac-4)
   - [Authentication Requirements](#authentication-requirements-ia-2-ia-5)
   - [Audit Logging](#audit-logging-au-2-au-3-au-12)
3. [Repository-level Security](#repository-level-security)
   - [Branch Protection](#branch-protection-cm-2-cm-3-cm-5)
   - [Code Ownership](#code-ownership-ac-5-ac-6)
   - [Vulnerability Management](#vulnerability-management-ra-5-si-2)
   - [Malicious Code Protection](#malicious-code-protection-si-3)
   - [Secret Management](#secret-management-sc-12-sc-13)
4. [CI/CD and Workflow Security](#cicd-and-workflow-security)
   - [Workflow Permissions](#workflow-permissions-cm-3-cm-4)
   - [Build Security](#build-security-sa-11)
5. [Supply Chain Security](#supply-chain-security)
   - [Dependency Management](#dependency-management-sr-3-sa-9-sr-11)
   - [Software Bill of Materials](#software-bill-of-materials-sr-4-sr-8)
   - [Artifact Integrity and Verification](#artifact-integrity-and-verification-sr-4-sr-10-sr-11)
   - [Build Provenance and Attestation](#build-provenance-and-attestation-sr-4-sr-9-sr-11)
   - [Supply Chain Incident Response](#supply-chain-incident-response-sr-8-sr-13)
6. [NIST Control Matrices](#nist-control-matrices)
   - [NIST 800-53 Controls](#nist-800-53-controls)
   - [NIST 800-161 Rev. 1 Update 1 Supply Chain Risk Management Controls](#nist-800-161-rev-1-update-1-supply-chain-risk-management-controls)
   - [Executive Order 14028 Requirements](#executive-order-14028-requirements)

## Prerequisites

Before you start:

1. **Admin access** to the GitHub organization under review
2. **A token** (or `gh` session) with the scopes you need, plus the org slug:
   ```
   export GH_TOKEN="your-github-token"
   export GH_ORG="your-organization-name"
   ```
3. **Tools**: `gh`, `curl`, `jq`, and a browser for the Admin UI
4. **Your baseline**: the security requirements or control set you are evaluating against

### Read this before you tick a box

Several checks below depend on plan tier or token scope rather than on how well
the organization is run:

| Check | Requires |
|-------|----------|
| Organization audit log | GitHub Enterprise Cloud, org owner |
| Audit log streaming | Enterprise account admin |
| IP allow list, SAML | GitHub Enterprise Cloud |
| Code scanning and secret scanning alerts | The feature enabled, plus `security_events` |
| Dependabot alerts | The feature enabled, plus `repo` or `security_events` |
| `security_and_analysis` fields on a repository | Admin on that repository |

When one of these returns 404 or 403, record **not assessed** and the reason.
Recording a pass because the command produced a file, or a failure because it
did not, are the two most common ways this exercise produces a misleading
report. The companion script marks these as `?` for the same reason.

## Framework Control Mapping

GitHub features rarely map one-to-one to a single framework. Start here when you need the crosswalk:

### Universal Security Controls

ISO 27001 identifiers below follow the **2022** revision (A.5 organizational,
A.6 people, A.7 physical, A.8 technological). The transition period from the
2013 revision closed on 31 October 2025, so 2013 certificates are no longer
valid and the A.5-A.18 numbering should not appear in current documentation.

| GitHub Feature | FedRAMP/NIST | SOC 2 | HIPAA | ISO 27001:2022 | PCI-DSS v4.0.1 |
|----------------|--------------|--------|--------|----------------|----------|
| Two-Factor Authentication | AC-2, IA-2 | CC6.1, CC6.7 | 164.308(a)(3) | A.5.17, A.8.5 | Req 8.3, 8.4 |
| Branch Protection / Rulesets | CM-2, CM-3, CM-5 | CC6.1, CC8.1 | 164.308(a)(4) | A.8.4, A.8.32 | Req 6.5.1 |
| Code Scanning | SI-3, RA-5 | CC7.1 | 164.308(a)(1) | A.8.8, A.8.28 | Req 6.2.1, 11.3.1 |
| Audit Logging | AU-2, AU-3, AU-12 | CC7.2, CC7.3 | 164.312(b) | A.8.15, A.8.16 | Req 10.2 |
| Secret Scanning | SC-12, SI-4 | CC7.1 | 164.312(a)(2) | A.8.12 | Req 3.3, 8.3.1 |
| Access Control | AC-3, AC-6 | CC6.3 | 164.312(a)(1) | A.5.15, A.5.18, A.8.3 | Req 7.2 |
| Vulnerability Management | RA-5, SI-2 | CC7.1 | 164.308(a)(1) | A.8.8 | Req 6.3.1, 6.3.3 |
| SBOM and Provenance | SR-4, SR-11 | CC8.1 | 164.312(c)(1) | A.8.30 | Req 6.3.2 |
| Pinned Actions | CM-7, SR-5 | CC8.1 | n/a | A.8.28 | Req 6.2.4 |

### Framework-Specific Requirements

#### SOC 2 Trust Service Criteria
- **CC6.1-CC6.8**: Logical and Physical Access Controls → GitHub 2FA, Branch Protection, RBAC
- **CC7.1-CC7.4**: System Operations → Code Security, Secret Protection, Audit Logs
- **CC8.1**: Change Management → PR Reviews, Branch Protection Rules

#### HIPAA Security Rule
- **Administrative Safeguards (164.308)**: Access Management, Risk Analysis, Workforce Security
- **Technical Safeguards (164.312)**: Access Control, Audit Controls, Integrity, Transmission Security
- **100% Requirements**: Branch protection, audit logging, and encryption are mandatory

#### ISO 27001:2022
- **A.5 Organizational**: A.5.1 policies, A.5.2 roles, A.5.9 asset inventory, A.5.15 access control, A.5.17 authentication information
- **A.8 Technological**: A.8.2 privileged access, A.8.4 access to source code, A.8.8 technical vulnerabilities, A.8.12 data leakage prevention, A.8.15 logging, A.8.25 secure development lifecycle, A.8.28 secure coding, A.8.30 outsourced development, A.8.32 change management

#### PCI-DSS v4.0.1
- **Requirements 1-2**: Network Security → Repository access controls
- **Requirements 3-4**: Data Protection → Secret scanning, encryption
- **Requirements 6**: Secure Development → Code scanning, PR reviews
- **Requirements 7-8**: Access Control → RBAC, MFA
- **Requirements 10-11**: Monitoring & Testing → Audit logs, vulnerability scanning

## Organization-level Security

### Account Management (AC-2)

**Framework Mappings:**
- **FedRAMP/NIST**: AC-2, AC-2(1), AC-2(4)
- **SOC 2**: CC6.1, CC6.2
- **HIPAA**: 164.308(a)(3), 164.308(a)(4)
- **ISO 27001:2022**: A.5.16, A.5.18
- **PCI-DSS v4.0.1**: Req 7.2, 8.2

#### Admin UI Steps
1. Navigate to **Organization Settings → People**
2. Review organization member list and roles
3. Check for appropriate role assignments
4. Navigate to **Organization Settings → Member privileges**
5. Review base permissions for organization members

#### API Verification
Execute these commands and save the outputs for your documentation:

```bash
# List organization members
gh api orgs/$GH_ORG/members --paginate > org_members.json

# List organization owners
gh api orgs/$GH_ORG/members --role admin > org_owners.json

# Get organization settings
gh api orgs/$GH_ORG > org_settings.json
```

#### Requirements Checklist
- [ ] Organization owners are limited to necessary personnel only
- [ ] Members have appropriate role assignments
- [ ] Regular review of membership is documented
- [ ] Centralized identity management integration is configured (if applicable)
- [ ] Onboarding/offboarding procedures are documented

### Access Enforcement (AC-3, AC-6)

#### Admin UI Steps
1. Navigate to **Organization Settings → Teams**
2. Review team structures and hierarchies
3. Check team permissions and repository access
4. Navigate to **Organization Settings → Member privileges**
5. Review organization-wide permission defaults

#### API Verification
```bash
# List all teams
gh api orgs/$GH_ORG/teams --paginate > org_teams.json

# For each team of interest, check their repositories
TEAM_SLUG="your-team-slug"
gh api orgs/$GH_ORG/teams/$TEAM_SLUG/repos > team_repos.json

# Base permissions are fields on the organization payload, not a separate
# settings endpoint.
gh api orgs/$GH_ORG --jq '{
  default_repository_permission,
  members_can_create_public_repositories,
  web_commit_signoff_required
}' > org_security_settings.json

# The security defaults for new repositories used to live on that payload as
# advanced_security_enabled_for_new_repositories and friends. Those fields were
# removed on 21 April 2026. Code security configurations replaced them, and the
# defaults endpoint is what now answers "what does a new repository inherit".
gh api "orgs/$GH_ORG/code-security/configurations" > code_security_configurations.json
gh api "orgs/$GH_ORG/code-security/configurations/defaults" > code_security_defaults.json

# An unenforced configuration can be switched off by a repository admin, which
# is the difference between a default and a control.
jq -r '.[] | "\(.name): enforcement=\(.enforcement)"' code_security_configurations.json
```

#### Requirements Checklist
- [ ] Teams follow logical functional separation
- [ ] Repository access follows the principle of least privilege
- [ ] Base permissions are set appropriately (private by default)
- [ ] Nested team structures reflect clear hierarchy of access
- [ ] Admin access is strictly limited and documented

### Information Flow Enforcement (AC-4)

#### Admin UI Steps
1. Navigate to **Organization Settings → Security → IP Allow List**
2. Review configured IP ranges and access rules
3. Check if IP allow list enforcement is enabled

#### API Verification

IP allow lists are exposed only through GraphQL; there is no REST endpoint for
them, so a `gh api orgs/.../security/ip_allow_list` call will always 404.

```bash
gh api graphql -f owner="$GH_ORG" -f query='
  query($owner: String!) {
    organization(login: $owner) {
      ipAllowListEnabledSetting
      ipAllowListForInstalledAppsEnabledSetting
      ipAllowListEntries(first: 100) {
        nodes { allowListValue name isActive }
      }
    }
  }' > ip_allow_list.json
```

#### Requirements Checklist
- [ ] IP restrictions are configured for organization access
- [ ] All allowed IP ranges are documented and justified
- [ ] IP allow list is enforced for installed GitHub Apps
- [ ] Regular review process exists for IP allow list entries
- [ ] IP restrictions align with organizational network security policies

### Authentication Requirements (IA-2, IA-5)

**Framework Mappings:**
- **FedRAMP/NIST**: IA-2, IA-2(1), IA-5
- **SOC 2**: CC6.1, CC6.7
- **HIPAA**: 164.308(a)(3), 164.312(a)(1)
- **ISO 27001:2022**: A.5.17, A.8.5
- **PCI-DSS v4.0.1**: Req 8.3, 8.4

#### Admin UI Steps
1. Navigate to **Organization Settings → Authentication security**
2. Check if two-factor authentication is required for the organization
3. Review session duration settings
4. If using SAML, navigate to **Organization Settings → Security → Authentication → SAML SSO**
5. Review SAML configuration and identity provider settings

#### API Verification
```bash
# Check if 2FA is required
gh api orgs/$GH_ORG | jq '.two_factor_requirement_enabled' > two_factor_required.json

# SAML configuration is GraphQL-only; there is no orgs/{org}/saml REST endpoint.
gh api graphql -f owner="$GH_ORG" -f query='
  query($owner: String!) {
    organization(login: $owner) {
      samlIdentityProvider {
        ssoUrl
        issuer
        digestMethod
        signatureMethod
        externalIdentities(first: 1) { totalCount }
      }
    }
  }' > saml_settings.json

# SCIM-provisioned identities, if the org uses them.
gh api "scim/v2/organizations/$GH_ORG/Users" > scim_users.json 2>/dev/null \
  || echo "SCIM not configured or token lacks admin:org scope"
```

#### Requirements Checklist
- [ ] Two-factor authentication is required for all organization members
- [ ] If using SAML SSO, it is properly configured with appropriate identity provider
- [ ] For FedRAMP High, phishing-resistant MFA is enforced via identity provider
- [ ] Session timeouts are configured appropriately
- [ ] Authentication method complies with NIST 800-63 guidelines

### Audit Logging (AU-2, AU-3, AU-12)

**Framework Mappings:**
- **FedRAMP/NIST**: AU-2, AU-3, AU-12
- **SOC 2**: CC7.2, CC7.3
- **HIPAA**: 164.312(b) (Required)
- **ISO 27001:2022**: A.8.15, A.8.16
- **PCI-DSS v4.0.1**: Req 10.2, 10.3

#### Admin UI Steps
1. Navigate to **Organization Settings → Audit log**
2. Sample various event types
3. Check for completeness of audit events
4. Review log export settings if configured

#### API Verification

The audit log API requires GitHub Enterprise Cloud and an owner-scoped token.
On any other plan it returns 404, which is a finding about your plan rather
than about your logging hygiene. Record which of the two you are looking at.

```bash
# Sample of audit log entries. gh api has no --limit flag; page size is a
# query parameter.
gh api "orgs/$GH_ORG/audit-log?per_page=100" > audit_log_sample.json \
  || echo "Audit log unavailable: requires Enterprise Cloud and an org owner token"

# Audit log streaming is configured at the enterprise level. There is no API to
# discover your enterprise slug from an org, so supply it.
ENTERPRISE="${GH_ENTERPRISE:-}"
if [ -n "$ENTERPRISE" ]; then
  gh api "enterprises/$ENTERPRISE/audit-log/streams" > audit_log_streaming.json \
    || echo "No audit log streams configured, or token lacks enterprise admin"
fi
```

#### Requirements Checklist
- [ ] Audit logging captures key security events
- [ ] If required, audit log streaming is configured to external systems
- [ ] Log retention meets FedRAMP requirements
- [ ] Audit log review process is documented
- [ ] Critical events trigger appropriate notifications

## Repository-level Security

Do not try to click through every repo on day one. Pick a representative sample (critical production services, high-traffic libs, and a couple of quiet ones), then run the same checks on each.

### Branch Protection (CM-2, CM-3, CM-5)

#### Admin UI Steps
1. Navigate to **Repository Settings → Branches**
2. Review protection rules for the default branch
3. Check for required status checks
4. Verify pull request requirements
5. Check restrictions on force pushes and deletions

#### API Verification

Classic branch protection and rulesets are two different mechanisms that
satisfy the same controls. A repository can be fully governed by an active
ruleset and still return 404 for the protection endpoint, so check both before
recording a gap.

```bash
# For each repository
REPO="your-repo-name"

# Classic branch protection on the default branch
DEFAULT_BRANCH=$(gh api repos/$GH_ORG/$REPO --jq '.default_branch')
gh api "repos/$GH_ORG/$REPO/branches/$DEFAULT_BRANCH/protection" > branch_protection.json \
  || echo "No classic branch protection; check rulesets below"

# Repository rulesets, and the org-level rulesets that apply to this repository
gh api "repos/$GH_ORG/$REPO/rulesets" > repo_rulesets.json
gh api "repos/$GH_ORG/$REPO/rules/branches/$DEFAULT_BRANCH" > effective_branch_rules.json
gh api "orgs/$GH_ORG/rulesets" > org_rulesets.json
```

`repos/{owner}/{repo}/rules/branches/{branch}` is the most useful of the three:
it returns the rules actually in effect on that branch from every source, which
is the question the control is asking.

#### Requirements Checklist
- [ ] Default branch is governed by classic protection or an **active** ruleset (`enforcement: active`, not `evaluate`)
- [ ] Pull requests are required for changes
- [ ] Required number of reviewers is specified (minimum 1)
- [ ] Code owner review is required, not merely a CODEOWNERS file existing
- [ ] Status checks are required before merging
- [ ] Branch is protected against force pushes
- [ ] Branch deletion protection is enabled
- [ ] Dismissal of stale approvals is enabled
- [ ] Enforcement applies to administrators, or bypass actors are documented and justified

### Code Ownership (AC-5, AC-6)

#### Admin UI Steps
1. Check for presence of CODEOWNERS file in:
   - `.github/CODEOWNERS`
   - `CODEOWNERS`
   - `docs/CODEOWNERS`
2. Review code ownership assignments
3. Verify code owner review requirements are enforced

#### API Verification
```bash
# Check for CODEOWNERS file
gh api repos/$GH_ORG/$REPO/contents/.github/CODEOWNERS > codeowners.json 2>/dev/null || \
gh api repos/$GH_ORG/$REPO/contents/CODEOWNERS > codeowners.json 2>/dev/null || \
gh api repos/$GH_ORG/$REPO/contents/docs/CODEOWNERS > codeowners.json 2>/dev/null || \
echo "No CODEOWNERS file found"

# Check if code owner reviews are required
gh api repos/$GH_ORG/$REPO/branches/$DEFAULT_BRANCH/protection/required_pull_request_reviews | \
  jq '.require_code_owner_reviews' > require_code_owner_reviews.json
```

#### Requirements Checklist
- [ ] CODEOWNERS file exists and is properly structured
- [ ] Critical code paths have designated owners
- [ ] Code owner reviews are required in branch protection
- [ ] CODEOWNERS entries follow the principle of least privilege
- [ ] Regular review process exists for code ownership assignments

### Vulnerability Management (RA-5, SI-2)

#### Admin UI Steps
1. Navigate to **Repository Settings → Security → Code security and analysis**
2. Check if Dependabot alerts are enabled
3. Verify Dependabot security updates configuration
4. Navigate to **Security → Dependabot alerts** tab
5. Review any existing alerts and their remediation status

#### API Verification
```bash
# Check security settings for the repository
gh api repos/$GH_ORG/$REPO/vulnerability-alerts > vulnerability_alerts_enabled.json 2>/dev/null || echo "No access to vulnerability alerts"

# Get Dependabot alerts
gh api repos/$GH_ORG/$REPO/dependabot/alerts > dependabot_alerts.json 2>/dev/null || echo "No access to Dependabot alerts"

# Check if automatic security updates are enabled
gh api repos/$GH_ORG/$REPO | jq '.security_and_analysis.dependabot_security_updates.status' > dependabot_security_updates.json
```

#### Requirements Checklist
- [ ] Dependabot alerts are enabled
- [ ] Automatic security updates are configured where appropriate
- [ ] Process exists for reviewing and remediating alerts
- [ ] Alert dismissal requires justification
- [ ] SLAs are defined for addressing critical vulnerabilities

### Malicious Code Protection (SI-3)

#### Admin UI Steps
1. Navigate to **Repository Settings → Security → Code security and analysis**
2. Check if code scanning is enabled
3. Verify CodeQL analysis configuration
4. Navigate to **Security → Code scanning alerts** tab
5. Review any existing alerts and their remediation status

#### API Verification
```bash
# Whether code scanning is licensed for this repository. Since the April 2025
# unbundling, repositories covered by the standalone GitHub Code Security
# product report through .code_security and leave .advanced_security unset, so
# checking only the legacy field reports a false negative.
gh api "repos/$GH_ORG/$REPO" --jq \
  '.security_and_analysis | {advanced_security: .advanced_security.status, code_security: .code_security.status}' \
  > code_security_status.json

# Get code scanning alerts
gh api repos/$GH_ORG/$REPO/code-scanning/alerts > code_scanning_alerts.json 2>/dev/null || echo "No access to code scanning alerts"

# Check code scanning configurations
gh api repos/$GH_ORG/$REPO/code-scanning/analyses > code_scanning_analyses.json 2>/dev/null || echo "No access to code scanning analyses"
```

#### Requirements Checklist
- [ ] Code scanning is enabled with appropriate scanning engine
- [ ] CodeQL analysis is configured for supported languages
- [ ] Custom code scanning configurations exist for specialized needs
- [ ] Process exists for reviewing and remediating alerts
- [ ] SLAs are defined for addressing critical findings

### Secret Management (SC-12, SC-13)

#### Admin UI Steps
1. Navigate to **Repository Settings → Security → Code security and analysis**
2. Check if secret scanning is enabled
3. Verify push protection configuration
4. Navigate to **Security → Secret scanning alerts** tab
5. Review any existing alerts and their remediation status

#### API Verification
```bash
# Check if secret scanning is enabled
gh api repos/$GH_ORG/$REPO | jq '.security_and_analysis.secret_scanning.status' > secret_scanning.json

# Check if push protection is enabled
gh api repos/$GH_ORG/$REPO | jq '.security_and_analysis.secret_scanning_push_protection.status' > secret_scanning_push_protection.json

# Delegated bypass routes an override through a reviewer. Without it, push
# protection is advisory: any contributor can wave a secret through.
gh api "repos/$GH_ORG/$REPO" \
  --jq '.security_and_analysis.secret_scanning_delegated_bypass.status' > delegated_bypass.json

# Bypasses that were actually granted. Each one means a secret reached the
# repository and should be treated as exposed.
gh api "repos/$GH_ORG/$REPO/bypass-requests/secret-scanning" --paginate \
  --jq '[.[] | select(.status == "approved" or .status == "completed")] | length' \
  > approved_bypasses.txt

# Get secret scanning alerts
gh api repos/$GH_ORG/$REPO/secret-scanning/alerts > secret_scanning_alerts.json 2>/dev/null || echo "No access to secret scanning alerts"
```

#### Requirements Checklist
- [ ] Secret scanning is enabled
- [ ] Push protection is enabled to prevent secret commits
- [ ] Delegated bypass is enabled so an override requires reviewer approval
- [ ] Any approved bypass has a corresponding secret rotation record
- [ ] Custom patterns are defined for organization-specific secrets (if applicable)
- [ ] Process exists for reviewing and remediating alerts
- [ ] SLAs are defined for addressing exposed secrets

## CI/CD and Workflow Security

### Workflow Permissions (CM-3, CM-4)

#### Admin UI Steps
1. Navigate to **Repository Settings → Actions → General**
2. Review workflow permissions settings
3. Check allowed actions configuration
4. Review workflows in the `.github/workflows` directory

#### API Verification
```bash
# Check Actions settings
gh api repos/$GH_ORG/$REPO/actions/permissions > actions_permissions.json

# List workflow files
gh api repos/$GH_ORG/$REPO/contents/.github/workflows > workflows.json 2>/dev/null || echo "No workflows found"

# For each workflow file of interest, examine contents
WORKFLOW_PATH=".github/workflows/your-workflow.yml"
gh api repos/$GH_ORG/$REPO/contents/$WORKFLOW_PATH > workflow_content.json 2>/dev/null || echo "Workflow not found"
```

#### Requirements Checklist
- [ ] Default token permissions are restricted
- [ ] Workflow permissions follow principle of least privilege
- [ ] Third-party actions are limited to verified or allowed actions
- [ ] Workflows use pinned action versions (preferably with SHA)
- [ ] Self-hosted runners have appropriate security controls

### Build Security (SA-11)

#### Admin UI Steps
1. Review workflows for security testing integration
2. Check for dependency review configuration
3. Verify status checks required for merging

#### API Verification
```bash
# Dependency review is enforced by running the dependency-review-action as a
# required status check; there is no repository setting that reports it.
gh api "repos/$GH_ORG/$REPO/contents/.github/workflows" --jq '.[].path' \
  | while read -r wf; do
      gh api "repos/$GH_ORG/$REPO/contents/$wf" \
        -H "Accept: application/vnd.github.raw" \
        | grep -l "dependency-review-action" - > /dev/null && echo "$wf"
    done > dependency_review_workflows.txt

# Status checks required for merging
gh api "repos/$GH_ORG/$REPO/branches/$DEFAULT_BRANCH/protection/required_status_checks" \
  > required_status_checks.json 2>/dev/null || echo "No required status checks"
```

#### Requirements Checklist
- [ ] Security testing is integrated into workflows
- [ ] Status checks for security scans are required for merging
- [ ] Dependency review is enforced for pull requests
- [ ] Build artifacts are properly signed or verified
- [ ] Workflows include appropriate testing for security requirements

## Supply Chain Security

Dependencies, builds, and artifacts are where many GitHub assessments get thin. This section tracks NIST SP 800-161 Rev. 1 Update 1 and the EO 14028 expectations that show up as SBOMs, signing, provenance, and incident response for the software you ship.

### Dependency Management (SR-3, SA-9, SR-11)

#### Admin UI Steps
1. Navigate to **Repository Settings → Security → Code security and analysis**
2. Check dependency review configuration
3. Verify Dependabot version updates configuration
4. Review any existing dependency update pull requests
5. Check organization-wide dependency insights (Enterprise)

#### API Verification
```bash
# Dependabot version updates configuration
gh api "repos/$GH_ORG/$REPO/contents/.github/dependabot.yml" \
  -H "Accept: application/vnd.github.raw" > dependabot_config.yml 2>/dev/null \
  || echo "No Dependabot configuration found"

# Dependabot security updates and alert enablement
gh api "repos/$GH_ORG/$REPO" \
  --jq '.security_and_analysis.dependabot_security_updates.status' > dependabot_security_updates.json
gh api "repos/$GH_ORG/$REPO/vulnerability-alerts" > /dev/null 2>&1 \
  && echo "enabled" > dependabot_alerts_enabled.txt \
  || echo "disabled" > dependabot_alerts_enabled.txt

# The dependency graph itself, as a live SBOM
gh api "repos/$GH_ORG/$REPO/dependency-graph/sbom" > dependency_graph_sbom.json 2>/dev/null \
  || echo "Dependency graph not enabled for this repository"
```

#### Requirements Checklist
- [ ] Dependency review is enforced for pull requests
- [ ] Dependabot version updates are configured (if applicable)
- [ ] Third-party dependencies are reviewed and approved
- [ ] Process exists for dependency license compliance
- [ ] Component inventory is maintained
- [ ] Critical dependency paths are identified and monitored (NIST 800-161)
- [ ] Dependency provenance is verified (EO 14028)

### Software Bill of Materials (SR-4, SR-8)

#### Admin UI Steps
1. Check repository for SBOM generation capabilities
2. Review SBOM workflow configuration if present
3. Verify SBOM format complies with NTIA minimum elements
4. Check SBOM distribution mechanism
5. Verify SBOM includes provenance attestation

#### API Verification
```bash
# GitHub can export an SPDX SBOM from the dependency graph directly. This is
# the fastest way to answer "is an SBOM available for this repository at all".
gh api "repos/$GH_ORG/$REPO/dependency-graph/sbom" > github_generated_sbom.json 2>/dev/null \
  || echo "Dependency graph SBOM unavailable"

# SBOM tooling in the workflows themselves. Matching on workflow *names* misses
# a release workflow that happens to generate an SBOM, so read the contents.
gh api "repos/$GH_ORG/$REPO/contents/.github/workflows" --jq '.[].path' \
  | while read -r wf; do
      if gh api "repos/$GH_ORG/$REPO/contents/$wf" \
           -H "Accept: application/vnd.github.raw" \
           | grep -qiE "cyclonedx|spdx|syft|sbom-action|attest-sbom"; then
        echo "$wf"
      fi
    done > sbom_workflows.txt

# SBOM artifacts attached to the latest release
if LATEST_RELEASE=$(gh api "repos/$GH_ORG/$REPO/releases/latest" --jq '.id' 2>/dev/null); then
  gh api "repos/$GH_ORG/$REPO/releases/$LATEST_RELEASE/assets" \
    --jq '[.[] | select(.name | test("sbom|cyclonedx|spdx"; "i"))]' > sbom_artifacts.json
fi
```

#### Requirements Checklist
- [ ] SBOM generation is automated (if applicable)
- [ ] SBOM format complies with NTIA minimum elements and organizational requirements
- [ ] SBOM is maintained with each release
- [ ] Process exists for SBOM review and validation
- [ ] SBOM is available to stakeholders through appropriate channels
- [ ] SBOM includes verified provenance information (EO 14028)
- [ ] SBOM contains complete dependency tree (NIST 800-161r1-upd1)
- [ ] SBOM format follows CycloneDX or SPDX standards
- [ ] SBOM includes vulnerability data (VEX when applicable)
- [ ] SBOM is cryptographically signed for integrity

### Artifact Integrity and Verification (SR-4, SR-10, SR-11)

#### Admin UI Steps
1. Navigate to **Repository Settings → Actions → General**
2. Check for artifact signing configuration
3. Review workflows for integrity verification steps
4. Verify cryptographic signature verification in deployment workflows
5. Check for Sigstore/Cosign integration in workflows

#### API Verification
```bash
# Signing and attestation steps in workflow contents
gh api "repos/$GH_ORG/$REPO/contents/.github/workflows" --jq '.[].path' \
  | while read -r wf; do
      if gh api "repos/$GH_ORG/$REPO/contents/$wf" \
           -H "Accept: application/vnd.github.raw" \
           | grep -qiE "cosign|sigstore|keyless|attest-build-provenance|slsa-framework"; then
        echo "$wf"
      fi
    done > signing_workflows.txt

# Signature and provenance artifacts on the latest release
if LATEST_RELEASE=$(gh api "repos/$GH_ORG/$REPO/releases/latest" --jq '.id' 2>/dev/null); then
  gh api "repos/$GH_ORG/$REPO/releases/$LATEST_RELEASE/assets" \
    --jq '[.[] | select(.name | test("\\.(sig|asc|pem|sigstore|intoto\\.jsonl)$"))]' \
    > signature_artifacts.json
fi

# Build provenance attestations stored by GitHub, looked up by artifact digest.
# This is the strongest single piece of evidence for SR-4 and SR-11.
ARTIFACT_DIGEST="sha256:<digest of a published artifact>"
gh api "repos/$GH_ORG/$REPO/attestations/$ARTIFACT_DIGEST" > attestations.json 2>/dev/null \
  || echo "No attestation stored for that digest"

# Or verify end to end, which also checks the signature chain:
#   gh attestation verify <artifact-path> --repo "$GH_ORG/$REPO"
```

#### Requirements Checklist
- [ ] Build artifacts are cryptographically signed
- [ ] Signature verification is required before deployment
- [ ] Secure key management process exists for signing keys
- [ ] Chain of custody is maintained through signature verification
- [ ] Artifact hashes are published with releases
- [ ] Immutable build records are maintained (NIST 800-161r1-upd1)
- [ ] Keyless signing is implemented where appropriate (Sigstore)
- [ ] Signature verification is automated in deployment pipelines
- [ ] Signature format follows industry standards

### Build Provenance and Attestation (SR-4, SR-9, SR-11)

Signing proves an artifact was not altered. Provenance proves *where it came
from*: which repository, which workflow, which commit, on which runner. EO 14028
and SLSA both ask for the second, and an assessor who accepts a `.sig` file as
provenance evidence has accepted the wrong thing.

#### Admin UI Steps
1. Open a recent release and check for an attestation badge or `.intoto.jsonl` asset
2. Navigate to the repository's **Actions → Attestations** view, if present
3. Open the release workflow and confirm it requests `id-token: write` and `attestations: write`
4. Confirm the build runs on a hosted runner or a documented, hardened self-hosted runner
5. Check whether consumers actually verify provenance before deploying

#### API Verification
```bash
# Workflows that produce provenance
gh api "repos/$GH_ORG/$REPO/contents/.github/workflows" --jq '.[].path' \
  | while read -r wf; do
      gh api "repos/$GH_ORG/$REPO/contents/$wf" -H "Accept: application/vnd.github.raw" \
        > "/tmp/$(basename "$wf")"
      if grep -qE "attest-build-provenance|attest-sbom|slsa-github-generator" "/tmp/$(basename "$wf")"; then
        echo "provenance: $wf"
        # The workflow must also grant the token that signs the attestation.
        grep -qE "id-token:[[:space:]]*write" "/tmp/$(basename "$wf")" \
          || echo "  WARNING: no id-token: write permission, attestation will fail"
      fi
    done > provenance_workflows.txt

# Stored attestations for a published artifact
ARTIFACT_DIGEST="sha256:<digest>"
gh api "repos/$GH_ORG/$REPO/attestations/$ARTIFACT_DIGEST" \
  --jq '.attestations[].bundle.dsseEnvelope.payloadType' > attestation_types.json 2>/dev/null \
  || echo "No attestation for that digest"

# End-to-end verification, including the certificate chain and the identity of
# the workflow that produced the artifact
gh attestation verify ./downloaded-artifact --repo "$GH_ORG/$REPO" --format json \
  > attestation_verification.json
```

#### Requirements Checklist
- [ ] Release workflows produce build provenance attestations
- [ ] Attestation subject digests match the artifacts actually published
- [ ] Workflows grant `id-token: write` and `attestations: write`, and nothing broader
- [ ] Provenance records the source repository, commit, and workflow
- [ ] Consumers verify provenance before deployment, and the failure path blocks the deploy
- [ ] Self-hosted runners used for release builds are ephemeral and documented
- [ ] Verification identity is pinned to the expected workflow, not just the repository

### Supply Chain Incident Response (SR-8, SR-13)

The controls above are preventative. SR-8 and SR-13 ask what happens on the day
a dependency you ship is found to be compromised: how you learn about it, how
fast you can tell whether you are affected, and how you tell your own consumers.

#### Admin UI Steps
1. Navigate to **Security → Advisories** and review any drafted or published advisories
2. Check **Organization Settings → Notifications** for who receives security alerts
3. Confirm Dependabot alert recipients are a monitored team, not an individual
4. Review the incident response plan for a supply chain compromise scenario specifically
5. Confirm you can answer "which of our releases contain this package version" from stored SBOMs

#### API Verification
```bash
# Published and draft security advisories for this repository
gh api "repos/$GH_ORG/$REPO/security-advisories" > repository_advisories.json 2>/dev/null \
  || echo "No advisories, or token lacks access"

# Organization-wide view of open alerts, which is the blast-radius question
gh api "orgs/$GH_ORG/dependabot/alerts?state=open&severity=critical,high" --paginate \
  --jq '[.[] | {repo: .repository.name, package: .dependency.package.name,
                severity: .security_advisory.severity, created: .created_at}]' \
  > org_critical_dependency_alerts.json

# Time-to-remediate evidence: how long open findings have been open
gh api "orgs/$GH_ORG/dependabot/alerts?state=open" --paginate \
  --jq 'map(.created_at) | sort | first' > oldest_open_alert.txt
```

#### Requirements Checklist
- [ ] A named team, not an individual, receives Dependabot and advisory notifications
- [ ] Remediation windows are defined per severity and are actually met (see `summary.json` for past-due counts)
- [ ] The incident response plan covers dependency and build system compromise, not only application breaches
- [ ] Stored SBOMs let you answer which shipped releases contain an affected component
- [ ] A process exists to publish advisories to downstream consumers
- [ ] Notification agreements with critical suppliers are documented (SR-8)
- [ ] Supply chain incidents are exercised, not just documented (SR-13)

## NIST Control Matrices

### NIST 800-53 Controls

The following matrix maps key GitHub settings to NIST 800-53 controls:

| Control | Description | Evaluation Areas | GitHub Settings to Review |
|---------|-------------|------------------|---------------------------|
| **AC-2** | Account Management | Organization members, teams | Member list, role assignments, offboarding procedures |
| **AC-3** | Access Enforcement | Repository permissions | Repository access settings, team permissions, base access levels |
| **AC-5** | Separation of Duties | Code ownership, branch protection | CODEOWNERS file, required reviews, protected branches |
| **AC-6** | Least Privilege | Repository access, admin rights | Team assignments, repository permissions, admin users |
| **AC-17** | Remote Access | IP restrictions | IP allow list configuration and enforcement |
| **AU-2** | Audit Events | Organization audit log | Audit log configuration, event types captured |
| **AU-3** | Content of Audit Records | Audit log detail | Audit log content, detail level, context |
| **AU-12** | Audit Generation | Audit logging | Audit log streaming, comprehensive event capture |
| **CM-2** | Baseline Configuration | Branch protection | Default branch protection, status checks |
| **CM-3** | Configuration Change Control | Branch protection, workflows | PR requirements, approval process, status checks |
| **CM-5** | Access Restrictions for Change | Branch protection | Branch protection rules, required approvals |
| **IA-2** | Identification and Authentication | 2FA, SSO | Two-factor requirements, SSO configuration |
| **IA-5** | Authenticator Management | 2FA enforcement | Two-factor compliance, token management |
| **RA-5** | Vulnerability Scanning | Dependabot, code scanning | Dependabot alerts, CodeQL configuration |
| **SA-9** | External System Services | Dependency management | Dependency review, third-party actions |
| **SA-11** | Developer Security Testing | CI/CD security | Workflow security checks, integration testing |
| **SC-12** | Cryptographic Key Management | Secret scanning | Secret scanning configuration, key rotation |
| **SI-2** | Flaw Remediation | Dependabot | Dependabot alerts, automated updates |
| **SI-3** | Malicious Code Protection | Code scanning | CodeQL analysis, security scans |
| **SI-4** | Information System Monitoring | Secret scanning | Secret scanning alerts, push protection |
| **SR-3** | Supply Chain Controls and Processes | Dependency management | Dependency review enforcement |
| **SR-4** | Provenance | SBOMs, attestation | SBOM generation, build provenance attestation |
| **SR-5** | Acquisition Strategies, Tools, and Methods | Pinned actions | Third-party actions pinned to a commit SHA |
| **SR-11** | Component Authenticity | Artifact signing | Signature and attestation verification |

### NIST 800-161 Rev. 1 Update 1 Supply Chain Risk Management Controls

The following matrix maps GitHub features to NIST 800-161r1-upd1 controls for supply chain risk management:

| Control | Description | GitHub Features | Evaluation Areas |
|---------|-------------|----------------|------------------|
| **SR-2** | Supply Chain Risk Management Plan | Organization security policies | Security policy documentation, dependency management strategy |
| **SR-3** | Supply Chain Controls and Processes | Dependency management | Dependency review workflow, Dependabot configuration |
| **SR-4** | Provenance | SBOM generation, attestation | SBOM format compliance, dependency origin verification, SLSA provenance |
| **SR-5** | Acquisition Strategies | Verified dependencies | Third-party action verification, dependency approval process, pinned dependencies |
| **SR-6** | Supplier Assessments and Reviews | Dependency insights | Dependency publisher verification, action verification, maintainer activity |
| **SR-8** | Notification Agreements | Security advisories | Security advisory monitoring, vulnerability alerts, CVE mapping |
| **SR-9** | Tamper Protection | Code signing | Artifact signing, commit verification, branch protection |
| **SR-10** | Inspection of Systems or Components | Code scanning | CodeQL analysis, custom code scanning tools integration, SAST/DAST integration |
| **SR-11** | Component Authenticity | Artifact signing | Package signature verification, artifact hash verification, provenance validation |
| **SR-12** | Component Disposal | Repository archiving | Archiving policies, dependency cleanup |
| **SR-13** | Supply Chain Incident Management | Response plans | Supply chain compromise procedures, dependency remediation process |

### Executive Order 14028 Requirements

The following matrix identifies how GitHub features address key requirements from Executive Order 14028 on Improving the Nation's Cybersecurity:

| Requirement | GitHub Features | Evaluation Areas |
|-------------|----------------|------------------|
| Software Bill of Materials | SBOM generation | SBOM workflow configuration, NTIA minimum element compliance, VEX integration |
| Secure Software Development | Secure development lifecycle | Branch protection, code reviews, automated security testing, reproducible builds |
| Artifact Signing | Action and package signing | Cryptographic signature verification, signing workflow, Sigstore integration |
| Vulnerability Management | Dependabot | Alert severity, remediation timeframes, automated updates, dependency pinning |
| Multi-Factor Authentication | 2FA enforcement | Organization 2FA requirement, phishing-resistant options, SSO integration |
| Verifiable Artifacts | Release verification | Signature verification, provenance attestation, SLSA framework adherence |
| Zero Trust Architecture | Fine-grained access | Repository permissions, IP restrictions, token scoping, ephemeral credentials |
| Software Supply Chain Security | SLSA framework | Build provenance, tamper resistance, build service security |

## Documentation Template

For each section you evaluate, capture:

1. **Current configuration**: What the UI and API showed
2. **Compliance status**: Compliant, Partially Compliant, or Non-Compliant
3. **Gaps**: What is missing or weak
4. **Recommendations**: Concrete fixes, not slogans
5. **Evidence**: Screenshots or saved API output

## Final Compliance Report

When you roll findings up for leadership or an assessor, include:

1. Executive summary
2. Scope
3. Methodology
4. Findings by section
5. Gap analysis
6. Remediation plan with owners and dates
7. Appendices with evidence

## Additional Resources

- [NIST 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) - Security and Privacy Controls for Information Systems and Organizations
- [NIST 800-161 Rev 1 Update 1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-161r1-upd1.pdf) - Cybersecurity Supply Chain Risk Management Practices for Systems and Organizations
- [Executive Order 14028](https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/) - Improving the Nation's Cybersecurity
- [FedRAMP Security Controls](https://www.fedramp.gov/assets/resources/documents/FedRAMP_Security_Controls_Baseline.xlsx) - FedRAMP Security Control Baselines
- [NTIA SBOM Minimum Elements](https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom) - Minimum Requirements for SBOMs
- [SLSA Framework](https://slsa.dev/) - Supply chain Levels for Software Artifacts
- [Sigstore](https://www.sigstore.dev/) - Keyless signing for software artifacts
- [GitHub Security Documentation](https://docs.github.com/en/enterprise-cloud@latest/code-security/getting-started/github-security-features) - Overview of GitHub Security Features
- [GitHub Code Security](https://docs.github.com/en/code-security) and [GitHub Secret Protection](https://docs.github.com/en/code-security/secret-scanning) - the two products Advanced Security was unbundled into on 1 April 2025
- [Code security configurations](https://docs.github.com/en/rest/code-security/configurations) - the replacement for the removed organization security API fields
- [GitHub Dependency Review Action](https://github.com/actions/dependency-review-action) - Automated dependency review for pull requests
- [GitHub SBOM Generator Action](https://github.com/marketplace/actions/software-bill-of-materials-sbom-generator) - SBOM generation in GitHub Actions

## Framework-Specific Evaluation Guidelines

Use these as pressure tests after the shared walkthrough. Each framework raises the bar differently.

### SOC 2 Type II
- **Access controls**: Aim for 90%+ branch protection coverage
- **Monitoring**: Continuous security monitoring actually turned on and reviewed
- **Incident response**: Documented *and* exercised
- **Change management**: Production changes go through PR review, not side doors

### HIPAA Security Rule
- **Hard floor**: Branch protection, audit logging, and access controls at 100% where in scope
- **Encryption**: Transit and at rest, including secrets handling
- **Audit controls**: Retention and review that match your policy
- **Access management**: Tight authn/authz, no shared convenience accounts

### ISO 27001:2022
- **ISMS documentation**: Policies exist and match how the org really works
- **Risk management**: Assessment and treatment are written down
- **Asset management**: Repo inventory and ownership (CODEOWNERS)
- **Continuous improvement**: Regular security review evidence, not a one-time audit

### PCI-DSS v4.0.1
- **Zero open vulns** in in-scope production code paths
- **100% code review** via PRs
- **MFA** for all users with access
- **Audit logging** of access and changes
- **Secure development**: Code Security (or equivalent) enabled for vulnerability scanning

## Automated evaluation

For the machine-readable pass, run the companion script:

```bash
# All frameworks
./github_compliance_audit.sh "$GH_ORG"

# One framework
./github_compliance_audit.sh "$GH_ORG" soc2
```

The run writes `summary.json` alongside the markdown report. It is the faster
way to answer most of the checklist questions above in bulk:

```bash
RUN=github_compliance_audit_all_20260725_120000

# Repositories with no branch protection and no active ruleset
jq -r 'select(.protected | not) | .name' "$RUN/repository_analysis.jsonl"

# Repositories where alert data could not be collected, which are the ones the
# checklists must not record as clean
jq -r 'select(.alerts.dependabot.available and .alerts.code_scanning.available | not)
       | .name' "$RUN/repository_analysis.jsonl"

# Findings past their remediation window, by repository
jq -r 'select(.alerts.dependabot.past_due > 0)
       | "\(.name): \(.alerts.dependabot.past_due) past due,
          oldest \(.alerts.dependabot.oldest_open_days) days"' \
  "$RUN/repository_analysis.jsonl"

# Unpinned third-party actions
jq -r 'select(.supply_chain.actions_total > .supply_chain.actions_pinned_to_sha)
       | "\(.name): \(.supply_chain.actions_pinned_to_sha)/\(.supply_chain.actions_total) pinned"' \
  "$RUN/repository_analysis.jsonl"
```

Use the script for breadth and the sections above for the controls it cannot
reach: process, intent, and anything that lives outside the API.

Treat the script output as a draft evidence pack. This guide is where you confirm, challenge, and document what automation cannot assert.