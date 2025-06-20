# GitHub Multi-Framework Compliance Evaluation Guide

This guide provides a systematic approach for manually evaluating GitHub implementations for compliance with multiple regulatory frameworks:
- **FedRAMP** and **NIST 800-53 Rev 5**
- **NIST 800-161 Rev 1 Update 1** (Supply Chain Risk Management)
- **SOC 2 Type II** (Trust Service Criteria)
- **HIPAA Security Rule** (45 CFR § 164.308-312)
- **ISO 27001:2022** (Annex A Controls)
- **PCI-DSS v4.0** (Payment Card Industry Data Security Standard)

This guide complements the automated `github_compliance_audit.sh` script and provides step-by-step instructions for hands-on evaluation, with special attention to supply chain security requirements from NIST 800-161r1-upd1 and Executive Order 14028 on Improving the Nation's Cybersecurity.

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
   - [Zero Trust Architecture Requirements](#zero-trust-architecture-requirements)

## Prerequisites

Before beginning your evaluation, ensure you have:

1. **Administrative access** to the GitHub organization being evaluated
2. **Personal access token** with appropriate scopes:
   ```
   export GH_TOKEN="your-github-token"
   export GH_ORG="your-organization-name"
   ```
3. **Required tools**:
   - GitHub CLI (`gh`) installed and authenticated
   - Command line with `curl` and `jq` installed
   - Web browser for GitHub Admin UI access
4. **Documentation** of your organization's security requirements

## Framework Control Mapping

This section maps GitHub security features to controls across different compliance frameworks:

### Universal Security Controls

| GitHub Feature | FedRAMP/NIST | SOC 2 | HIPAA | ISO 27001 | PCI-DSS |
|----------------|--------------|--------|--------|-----------|----------|
| Two-Factor Authentication | AC-2, IA-2 | CC6.1, CC6.7 | 164.308(a)(3) | A.9.2 | Req 8.3 |
| Branch Protection | CM-2, CM-3 | CC6.1, CC8.1 | 164.308(a)(4) | A.9.1, A.12.1 | Req 6.3.2 |
| Code Scanning | SI-3, RA-5 | CC7.1 | 164.308(a)(1) | A.12.2, A.12.6 | Req 6.3.1 |
| Audit Logging | AU-2, AU-3 | CC7.2, CC7.3 | 164.312(b) | A.12.4 | Req 10.2 |
| Secret Scanning | SC-12, SI-4 | CC7.1 | 164.312(a)(2) | A.12.2 | Req 3.4 |
| Access Control | AC-3, AC-6 | CC6.3 | 164.312(a)(1) | A.9.1, A.9.4 | Req 7.1 |
| Vulnerability Management | RA-5, SI-2 | CC7.1 | 164.308(a)(1) | A.12.6 | Req 6.3.1 |

### Framework-Specific Requirements

#### SOC 2 Trust Service Criteria
- **CC6.1-CC6.8**: Logical and Physical Access Controls → GitHub 2FA, Branch Protection, RBAC
- **CC7.1-CC7.4**: System Operations → GitHub Advanced Security, Audit Logs
- **CC8.1**: Change Management → PR Reviews, Branch Protection Rules

#### HIPAA Security Rule
- **Administrative Safeguards (164.308)**: Access Management, Risk Analysis, Workforce Security
- **Technical Safeguards (164.312)**: Access Control, Audit Controls, Integrity, Transmission Security
- **100% Requirements**: Branch protection, audit logging, and encryption are mandatory

#### ISO 27001:2022
- **A.5**: Organizational controls → Security policies, roles
- **A.8**: Asset management → Repository inventory, CODEOWNERS
- **A.9**: Access control → Authentication, authorization
- **A.12**: Operations security → Monitoring, vulnerability management

#### PCI-DSS v4.0
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
- **ISO 27001**: A.9.2
- **PCI-DSS**: Req 7.1, 8.1

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

# Check base permissions
gh api orgs/$GH_ORG/settings/security_analysis > org_security_settings.json
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
```bash
# Get IP allow list entries
gh api orgs/$GH_ORG/security/ip_allow_list > ip_allow_list.json

# Check if IP allow list is enabled
gh api orgs/$GH_ORG | jq '.ip_allow_list_enabled_for_installed_apps, .ip_allow_list_enabled' > ip_allow_list_status.json
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
- **ISO 27001**: A.9.2, A.9.4
- **PCI-DSS**: Req 8.3, 8.4

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

# Check SAML settings if applicable
gh api orgs/$GH_ORG/saml > saml_settings.json 2>/dev/null || echo "SAML settings not available"
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
- **ISO 27001**: A.12.4
- **PCI-DSS**: Req 10.2, 10.3

#### Admin UI Steps
1. Navigate to **Organization Settings → Audit log**
2. Sample various event types
3. Check for completeness of audit events
4. Review log export settings if configured

#### API Verification
```bash
# Get sample of audit log entries
gh api orgs/$GH_ORG/audit-log --paginate --limit 100 > audit_log_sample.json

# Check for enterprise audit log streaming if applicable
if gh api enterprises > /dev/null 2>&1; then
  ENTERPRISE=$(gh api enterprises --jq '.[0].slug')
  gh api enterprises/$ENTERPRISE/audit-log-streaming > audit_log_streaming.json 2>/dev/null || echo "Enterprise audit log streaming not configured"
fi
```

#### Requirements Checklist
- [ ] Audit logging captures key security events
- [ ] If required, audit log streaming is configured to external systems
- [ ] Log retention meets FedRAMP requirements
- [ ] Audit log review process is documented
- [ ] Critical events trigger appropriate notifications

## Repository-level Security

Select a representative sample of repositories for this evaluation. For each repository, perform the following checks:

### Branch Protection (CM-2, CM-3, CM-5)

#### Admin UI Steps
1. Navigate to **Repository Settings → Branches**
2. Review protection rules for the default branch
3. Check for required status checks
4. Verify pull request requirements
5. Check restrictions on force pushes and deletions

#### API Verification
```bash
# For each repository
REPO="your-repo-name"

# Get branch protection rules for default branch
DEFAULT_BRANCH=$(gh api repos/$GH_ORG/$REPO | jq -r '.default_branch')
gh api repos/$GH_ORG/$REPO/branches/$DEFAULT_BRANCH/protection > branch_protection.json
```

#### Requirements Checklist
- [ ] Default branch has protection rules enabled
- [ ] Pull requests are required for changes
- [ ] Required number of reviewers is specified (minimum 1)
- [ ] Status checks are required before merging
- [ ] Branch is protected against force pushes
- [ ] Branch deletion protection is enabled
- [ ] Dismissal of stale approvals is enabled

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
# Check if code scanning is enabled
gh api repos/$GH_ORG/$REPO | jq '.security_and_analysis.advanced_security.status' > advanced_security.json

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

# Get secret scanning alerts
gh api repos/$GH_ORG/$REPO/secret-scanning/alerts > secret_scanning_alerts.json 2>/dev/null || echo "No access to secret scanning alerts"
```

#### Requirements Checklist
- [ ] Secret scanning is enabled
- [ ] Push protection is enabled to prevent secret commits
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
# Check dependency review enforcement
gh api repos/$GH_ORG/$REPO | jq '.security_and_analysis.dependency_review_enforcement_level' > dependency_review.json

# Check status checks required for merging
gh api repos/$GH_ORG/$REPO/branches/$DEFAULT_BRANCH/protection/required_status_checks > required_status_checks.json 2>/dev/null || echo "No required status checks"
```

#### Requirements Checklist
- [ ] Security testing is integrated into workflows
- [ ] Status checks for security scans are required for merging
- [ ] Dependency review is enforced for pull requests
- [ ] Build artifacts are properly signed or verified
- [ ] Workflows include appropriate testing for security requirements

## Supply Chain Security

This section addresses NIST SP 800-161 Rev. 1 Update 1 (NIST 800-161r1-upd1) requirements and the Executive Order 14028 on Improving the Nation's Cybersecurity. Special attention is given to the enhanced supply chain security controls from the latest NIST 800-161 update.

### Dependency Management (SR-3, SA-9, SR-11)

#### Admin UI Steps
1. Navigate to **Repository Settings → Security → Code security and analysis**
2. Check dependency review configuration
3. Verify Dependabot version updates configuration
4. Review any existing dependency update pull requests
5. Check organization-wide dependency insights (Enterprise)

#### API Verification
```bash
# Check dependency review settings
gh api repos/$GH_ORG/$REPO | jq '.security_and_analysis.dependency_review_enforcement_level' > dependency_review.json

# Check for Dependabot configuration file
gh api repos/$GH_ORG/$REPO/contents/.github/dependabot.yml > dependabot_config.json 2>/dev/null || echo "No Dependabot configuration found"

# Check dependency graph availability
gh api repos/$GH_ORG/$REPO | jq '.security_and_analysis.dependency_graph.status' > dependency_graph.json
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
# Check for SBOM workflow or configuration
gh api repos/$GH_ORG/$REPO/contents/.github/workflows | jq '.[] | select(.name | contains("sbom"))' > sbom_workflow.json 2>/dev/null || echo "No SBOM workflow found"

# Check specific SBOM tools in use (e.g., CycloneDX, SPDX, Syft)
for workflow in $(gh api repos/$GH_ORG/$REPO/contents/.github/workflows --jq '.[].path'); do
  gh api repos/$GH_ORG/$REPO/contents/$workflow --raw | grep -i -E "cyclonedx|spdx|syft|sbom-action" > sbom_tools.txt || echo "No SBOM tools found in $workflow"
done

# Check for SBOM artifacts in releases
LATEST_RELEASE=$(gh api repos/$GH_ORG/$REPO/releases/latest 2>/dev/null | jq -r '.id' 2>/dev/null) || echo "No releases found"
if [ "$LATEST_RELEASE" != "No releases found" ]; then
  gh api repos/$GH_ORG/$REPO/releases/$LATEST_RELEASE/assets | jq '.[] | select(.name | contains("sbom") or .name | contains("cyclonedx") or .name | contains("spdx"))' > sbom_artifacts.json
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
# Check for signing configurations in workflows
gh api repos/$GH_ORG/$REPO/contents/.github/workflows | jq '.[] | select(.name | contains("sign") or .name | contains("verify"))' > signing_workflows.json 2>/dev/null || echo "No signing workflows found"

# Look for Cosign or Sigstore in workflow contents
for workflow in $(gh api repos/$GH_ORG/$REPO/contents/.github/workflows --jq '.[].path'); do
  gh api repos/$GH_ORG/$REPO/contents/$workflow --raw | grep -i -E "cosign|sigstore|keyless" > cosign_usage.txt || echo "No Cosign usage found in $workflow"
done

# Check for signature verification on releases
if [ "$LATEST_RELEASE" != "No releases found" ]; then
  gh api repos/$GH_ORG/$REPO/releases/$LATEST_RELEASE | jq '.assets[] | select(.name | contains(".sig") or .name | contains(".asc") or .name | contains("sbom"))' > signature_artifacts.json
fi
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
| **SR-3** | Supply Chain Protection | Dependency management | Dependency review enforcement |
| **SR-4** | Component Authenticity | SBOMs, signing | SBOM generation, artifact signing |

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

For each section evaluated, document:
1. **Current Configuration**: Findings from the GitHub UI and API checks
2. **Compliance Status**: Compliant, Partially Compliant, Non-Compliant
3. **Gaps**: Any identified compliance gaps
4. **Recommendations**: Specific actions to address gaps
5. **Evidence**: Screenshots or API outputs demonstrating compliance

## Final Compliance Report

Compile your findings into a comprehensive compliance report that includes:
1. Executive summary
2. Scope of evaluation
3. Methodology
4. Detailed findings by section
5. Gap analysis
6. Remediation plan
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
- [GitHub Advanced Security Documentation](https://docs.github.com/en/enterprise-cloud@latest/get-started/learning-about-github/about-github-advanced-security) - Information on GitHub Advanced Security offerings
- [GitHub Dependency Review Action](https://github.com/actions/dependency-review-action) - Automated dependency review for pull requests
- [GitHub SBOM Generator Action](https://github.com/marketplace/actions/software-bill-of-materials-sbom-generator) - SBOM generation in GitHub Actions

## Framework-Specific Evaluation Guidelines

### SOC 2 Type II Evaluation Focus
- **Access Controls**: Verify 90%+ branch protection coverage
- **Monitoring**: Ensure continuous security monitoring is enabled
- **Incident Response**: Document and test incident response procedures
- **Change Management**: Verify all changes go through PR review process

### HIPAA Security Rule Evaluation Focus
- **100% Requirements**: Branch protection, audit logging, and access controls must be at 100%
- **Encryption**: Verify data encryption in transit and at rest
- **Audit Controls**: Ensure comprehensive audit logging with appropriate retention
- **Access Management**: Verify strict access controls and authentication

### ISO 27001:2022 Evaluation Focus
- **ISMS Documentation**: Verify information security policies exist
- **Risk Management**: Document risk assessment and treatment
- **Asset Management**: Ensure repository inventory and ownership (CODEOWNERS)
- **Continuous Improvement**: Evidence of regular security reviews

### PCI-DSS v4.0 Evaluation Focus
- **Zero Tolerance**: No open vulnerabilities in production code
- **100% Code Review**: All code must go through PR review
- **Strong Authentication**: MFA required for all users
- **Audit Logging**: Comprehensive logging of all access and changes
- **Secure Development**: GHAS must be enabled for vulnerability scanning

## Automated Evaluation Option

For automated assessment, use the `github_compliance_audit.sh` script included in this repository. The script supports multiple compliance frameworks:

Usage:
```bash
# All frameworks
./github_compliance_audit.sh <organization-name>

# Specific framework
./github_compliance_audit.sh <organization-name> [fedramp|soc2|hipaa|iso27001|pci-dss]
```