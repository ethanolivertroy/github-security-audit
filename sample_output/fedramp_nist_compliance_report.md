# GitHub FedRAMP/NIST Compliance Report for acme-corporation
## Generated on Mon Mar 25 11:45:32 UTC 2025

### Organization Overview
- Organization: acme-corporation
- Total repositories: 3
- Repositories with protected default branches: 2 (67%)
- Two-factor authentication required: true
- Security manager role configured: Yes

### NIST SP 800-53 Compliance Summary

#### Access Control (AC)
- **AC-2 Account Management**
  - Security manager role implemented: Yes
  - Two-factor authentication required: true

- **AC-3/AC-6 Access Enforcement and Least Privilege**
  - Branch protection rules in place: 67% of repositories
  - Repository CODEOWNERS files will be manually reviewed

- **AC-4 Information Flow Enforcement**
  - IP allow lists: Check sample_output/org_security/ip_allow_lists.json for details

#### Identification and Authentication (IA)
- **IA-2 Identification and Authentication**
  - Two-factor authentication required: true
  - SSO configuration will need to be manually reviewed

#### Risk Assessment (RA)
- **RA-5 Vulnerability Scanning**
  - Dependabot alerts: Check repository-specific files
  - Code scanning alerts: Check repository-specific files

#### System and Information Integrity (SI)
- **SI-2 Flaw Remediation**
  - Dependabot security updates: Check repository-specific files
  
- **SI-3 Malicious Code Protection**
  - Code scanning alerts: Check repository-specific files
  
- **SI-4 Information System Monitoring**
  - Secret scanning alerts: Check repository-specific files

#### Configuration Management (CM)
- **CM-2 Baseline Configuration**
  - Branch protection rules in place: 67% of repositories

- **CM-3/CM-5 Configuration Change Control and Access Restrictions**
  - Branch protection rules in place: 67% of repositories
  - Required reviews: Check repository-specific branch protection files

#### Audit and Accountability (AU)
- **AU-2/AU-3/AU-12 Audit Events and Content**
  - Audit logging enabled: Check sample_output/org_security/audit_log_sample.json

### FedRAMP-Specific Controls
- **Secret Management (SC-12, SC-13)**
  - Secret scanning enabled: Check repository-specific settings
  - Push protection: Check repository-specific branch protection settings

- **Code Review Requirements (CM-3, CM-4)**
  - Required approvals: Check repository-specific branch protection settings
  - Status checks: Check repository-specific branch protection settings

### Security Recommendations
The following recommendations should be implemented to improve FedRAMP/NIST compliance:

1. Ensure all repositories have branch protection rules, including:
   - Required reviews for pull requests
   - Status checks required before merging
   - Restrictions on force pushes
   - Branch deletion protection

2. Enable all available security features on all repositories:
   - Dependabot alerts and security updates
   - Code scanning (with CodeQL or other tools)
   - Secret scanning with push protection

3. Implement and enforce the following organization-wide policies:
   - Require two-factor authentication for all members
   - Define IP allow lists for access restrictions
   - Configure a security manager role and team

4. Ensure all repositories have:
   - SECURITY.md file with vulnerability disclosure process
   - CODEOWNERS file with appropriate review requirements
   - CI/CD workflows with security checks

5. Configure audit logging and maintain logs for required retention periods
   - Consider setting up audit log streaming for long-term storage

### Detailed Findings
For detailed analysis of each repository and organization setting, review the JSON files in the output directory.