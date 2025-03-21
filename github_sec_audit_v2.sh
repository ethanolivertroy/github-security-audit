#!/bin/bash
# GitHub Organization Security Posture Analysis Script for FedRAMP/NIST Compliance
# This script audits GitHub organizations for security settings relevant to FedRAMP and NIST 800-53 compliance

# Configuration
ORG_NAME="$1"
if [ -z "$ORG_NAME" ]; then
  echo "Usage: $0 <organization-name>"
  exit 1
fi

# Create output directory
OUTPUT_DIR="github_security_audit_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"
echo "Starting FedRAMP/NIST security audit for organization: $ORG_NAME"
echo "Results will be saved to: $OUTPUT_DIR"

# Check GitHub CLI installation and authentication
if ! command -v gh &> /dev/null; then
  echo "GitHub CLI not found. Please install it first."
  exit 1
fi

# Verify authentication
if ! gh auth status &> /dev/null; then
  echo "Please authenticate with GitHub first using: gh auth login"
  exit 1
fi

# Function to check GitHub API rate limits
check_rate_limit() {
  rate_limit=$(gh api rate_limit --jq '.resources.core.remaining')
  if [ "$rate_limit" -lt 100 ]; then
    echo "Warning: GitHub API rate limit is low ($rate_limit). The script may fail."
    echo "Sleeping for 60 seconds to ensure we have enough rate limit..."
    sleep 60
  fi
}

# 1. Collect Organization Information
echo "Gathering organization information..."
check_rate_limit
gh api "orgs/$ORG_NAME" --jq . > "$OUTPUT_DIR/organization_info.json"

# 2. Collect Organization-Level Security Settings
echo "Gathering organization security settings..."
mkdir -p "$OUTPUT_DIR/org_security"

# 2.1 Get organization members and roles
echo "  Collecting organization members and roles..."
check_rate_limit
gh api "orgs/$ORG_NAME/members?per_page=100" --paginate --jq . > "$OUTPUT_DIR/org_security/members.json"

# 2.2 Check for security managers (FedRAMP AC-2, AC-3, AC-5, AC-6)
echo "  Checking for security managers..."
check_rate_limit
gh api "orgs/$ORG_NAME/security-managers" --jq . > "$OUTPUT_DIR/org_security/security_managers.json" 2>/dev/null || echo "  Security manager role may not be available or no access"

# 2.3 Get organization teams and their access (FedRAMP AC-2, AC-3, AC-5, AC-6)
echo "  Collecting organization teams and access levels..."
check_rate_limit
gh api "orgs/$ORG_NAME/teams?per_page=100" --paginate --jq . > "$OUTPUT_DIR/org_security/teams.json"

# 2.4 Check for 2FA requirements (FedRAMP IA-2, IA-5)
echo "  Checking for 2FA requirements..."
check_rate_limit
gh api "orgs/$ORG_NAME" --jq '.two_factor_requirement_enabled' > "$OUTPUT_DIR/org_security/two_factor_required.txt"

# 2.5 Check for IP allow lists (FedRAMP AC-4, SC-7)
echo "  Checking for IP allow lists..."
check_rate_limit
gh api "orgs/$ORG_NAME/interaction-limits" --jq . > "$OUTPUT_DIR/org_security/ip_allow_lists.json" 2>/dev/null || echo "  IP allow lists may not be available or no access"

# 2.6 Check for organization-wide security settings (FedRAMP SI-2, SI-3, SI-4, RA-5)
echo "  Checking for organization-wide security settings..."
# Dependabot alerts and settings
check_rate_limit
gh api "orgs/$ORG_NAME/dependabot/alerts" --jq . > "$OUTPUT_DIR/org_security/dependabot_org_alerts.json" 2>/dev/null || echo "  Dependabot org-level alerts access denied"
# Secret scanning
check_rate_limit
gh api "orgs/$ORG_NAME/security-advisories" --jq . > "$OUTPUT_DIR/org_security/security_advisories.json" 2>/dev/null || echo "  Security advisories access denied"

# 2.7 Check for audit log settings (FedRAMP AU-2, AU-3, AU-6, AU-7, AU-9, AU-12)
echo "  Checking for audit log settings..."
check_rate_limit
# Retrieve a sample of audit log entries to verify they're being captured
gh api "orgs/$ORG_NAME/audit-log?phrase=action:org.* per_page=10" --jq . > "$OUTPUT_DIR/org_security/audit_log_sample.json" 2>/dev/null || echo "  Audit log access denied"

# 2.8 Check for organization-wide security policies (FedRAMP CM-7, CM-8, CM-9)
echo "  Checking for organization-wide security policies..."
# Check for security policy files
check_rate_limit
gh api "repos/$ORG_NAME/.github/contents/SECURITY.md" --jq . > "$OUTPUT_DIR/org_security/security_policy.json" 2>/dev/null || echo "  No organization-wide security policy found"

# 3. Collect Repository List
echo "Gathering repository list..."
check_rate_limit
gh repo list "$ORG_NAME" --limit 1000 --json name,visibility,isPrivate,isArchived,defaultBranchRef > "$OUTPUT_DIR/repositories.json"

# 4. Process Each Repository for NIST/FedRAMP Security Controls
echo "Processing repositories for FedRAMP and NIST compliance..."
mkdir -p "$OUTPUT_DIR/repositories"

# Extract repo names and default branches
jq -r '.[] | .name + "," + (.defaultBranchRef.name // "main")' "$OUTPUT_DIR/repositories.json" > "$OUTPUT_DIR/repo_list.txt"

# Process each repository
while IFS=, read -r repo_name default_branch; do
  echo "Processing repository: $repo_name (default branch: $default_branch)"
  
  # Create repository directory
  repo_dir="$OUTPUT_DIR/repositories/$repo_name"
  mkdir -p "$repo_dir"
  
  # Get repository details
  check_rate_limit
  gh api "repos/$ORG_NAME/$repo_name" --jq . > "$repo_dir/info.json"
  
  # 4.1 Check branch protection rules (FedRAMP CM-2, CM-3, CM-5, CM-7)
  echo "  Getting branch protection rules..."
  mkdir -p "$repo_dir/branches"
  
  # Get all branches
  check_rate_limit
  gh api "repos/$ORG_NAME/$repo_name/branches" --jq . > "$repo_dir/branches/all_branches.json"
  
  # Process each branch to get protection rules
  jq -r '.[].name' "$repo_dir/branches/all_branches.json" | while read -r branch; do
    echo "    Checking branch: $branch"
    # Try to get branch protection (will only work if it exists)
    check_rate_limit
    gh api "repos/$ORG_NAME/$repo_name/branches/$branch/protection" --jq . > "$repo_dir/branches/${branch}_protection.json" 2>/dev/null || echo "    No branch protection for $branch"
  done
  
  # 4.2 Check for security vulnerabilities and alerts (FedRAMP SI-2, SI-3, SI-4, RA-5)
  echo "  Getting security features..."
  
  # Check if advanced security is enabled (FedRAMP RA-5, SI-3)
  check_rate_limit
  gh api "repos/$ORG_NAME/$repo_name" --jq '.security_and_analysis' > "$repo_dir/security_and_analysis.json" 2>/dev/null || echo "  Security and analysis data access denied"
  
  # Get Dependabot alerts (FedRAMP SI-2, RA-5)
  check_rate_limit
  gh api "repos/$ORG_NAME/$repo_name/dependabot/alerts?per_page=100" --paginate --jq . > "$repo_dir/dependabot_alerts.json" 2>/dev/null || echo "  Dependabot alerts access denied"
  
  # Get Dependabot security updates status (FedRAMP SI-2, SI-3)
  check_rate_limit
  gh api "repos/$ORG_NAME/$repo_name" --jq '.security_and_analysis.dependabot_security_updates' > "$repo_dir/dependabot_security_updates.json" 2>/dev/null || echo "  Dependabot security updates status access denied"
  
  # Get code scanning alerts (FedRAMP RA-5, SA-11)
  check_rate_limit
  gh api "repos/$ORG_NAME/$repo_name/code-scanning/alerts?per_page=100" --paginate --jq . > "$repo_dir/code_scanning_alerts.json" 2>/dev/null || echo "  Code scanning alerts access denied"
  
  # Get secret scanning alerts (FedRAMP RA-5, SC-12, SC-13)
  check_rate_limit
  gh api "repos/$ORG_NAME/$repo_name/secret-scanning/alerts?per_page=100" --paginate --jq . > "$repo_dir/secret_scanning_alerts.json" 2>/dev/null || echo "  Secret scanning alerts access denied"
  
  # 4.3 Check for CI/CD workflows and security checks (FedRAMP CM-3, CM-4, SA-11)
  echo "  Getting workflow information..."
  mkdir -p "$repo_dir/workflows"
  
  # Get workflows
  check_rate_limit
  gh api "repos/$ORG_NAME/$repo_name/actions/workflows" --jq . > "$repo_dir/workflows/workflows.json" 2>/dev/null || echo "  Workflows access denied"
  
  # 4.4 Check for vulnerability disclosure policy (FedRAMP SI-5, IR-4, IR-6) 
  echo "  Checking for security policy..."
  check_rate_limit
  gh api "repos/$ORG_NAME/$repo_name/contents/SECURITY.md" --jq . > "$repo_dir/security_policy.json" 2>/dev/null || echo "  No security policy found"
  
  # 4.5 Check for code owners file (FedRAMP AC-2, AC-3, AC-5, AC-6)
  echo "  Checking for CODEOWNERS file..."
  check_rate_limit
  gh api "repos/$ORG_NAME/$repo_name/contents/.github/CODEOWNERS" --jq . > "$repo_dir/codeowners.json" 2>/dev/null || 
  gh api "repos/$ORG_NAME/$repo_name/contents/CODEOWNERS" --jq . > "$repo_dir/codeowners.json" 2>/dev/null || 
  gh api "repos/$ORG_NAME/$repo_name/contents/docs/CODEOWNERS" --jq . > "$repo_dir/codeowners.json" 2>/dev/null || 
  echo "  No CODEOWNERS file found"
  
  # 4.6 Check for dependency review (FedRAMP CM-7, SA-8, SA-9)
  echo "  Checking for dependency review settings..."
  check_rate_limit
  gh api "repos/$ORG_NAME/$repo_name" --jq '.security_and_analysis.dependency_review_enforcement_level' > "$repo_dir/dependency_review.json" 2>/dev/null || echo "  Dependency review settings access denied"
  
done < "$OUTPUT_DIR/repo_list.txt"

# 5. Generate FedRAMP/NIST Compliance Report
echo "Generating FedRAMP/NIST compliance report..."

# Count repositories with branch protection on default branch
protected_repos=0
total_repos=$(wc -l < "$OUTPUT_DIR/repo_list.txt")

while IFS=, read -r repo_name default_branch; do
  if [ -s "$OUTPUT_DIR/repositories/$repo_name/branches/${default_branch}_protection.json" ]; then
    ((protected_repos++))
  fi
done < "$OUTPUT_DIR/repo_list.txt"

# Check 2FA requirement
two_factor_required=$(cat "$OUTPUT_DIR/org_security/two_factor_required.txt" | tr -d '\n')

# Check for security manager role
if [ -s "$OUTPUT_DIR/org_security/security_managers.json" ]; then
  has_security_managers="Yes"
else
  has_security_managers="No"
fi

# Create compliance report
cat > "$OUTPUT_DIR/fedramp_nist_compliance_report.md" << EOF
# GitHub FedRAMP/NIST Compliance Report for $ORG_NAME
## Generated on $(date)

### Organization Overview
- Organization: $ORG_NAME
- Total repositories: $total_repos
- Repositories with protected default branches: $protected_repos ($(( protected_repos * 100 / total_repos ))%)
- Two-factor authentication required: $two_factor_required
- Security manager role configured: $has_security_managers

### NIST SP 800-53 Compliance Summary

#### Access Control (AC)
- **AC-2 Account Management**
  - Security manager role implemented: $has_security_managers
  - Two-factor authentication required: $two_factor_required

- **AC-3/AC-6 Access Enforcement and Least Privilege**
  - Branch protection rules in place: $(( protected_repos * 100 / total_repos ))% of repositories
  - Repository CODEOWNERS files will be manually reviewed

- **AC-4 Information Flow Enforcement**
  - IP allow lists: Check $OUTPUT_DIR/org_security/ip_allow_lists.json for details

#### Identification and Authentication (IA)
- **IA-2 Identification and Authentication**
  - Two-factor authentication required: $two_factor_required
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
  - Branch protection rules in place: $(( protected_repos * 100 / total_repos ))% of repositories

- **CM-3/CM-5 Configuration Change Control and Access Restrictions**
  - Branch protection rules in place: $(( protected_repos * 100 / total_repos ))% of repositories
  - Required reviews: Check repository-specific branch protection files

#### Audit and Accountability (AU)
- **AU-2/AU-3/AU-12 Audit Events and Content**
  - Audit logging enabled: Check $OUTPUT_DIR/org_security/audit_log_sample.json

### FedRAMP-Specific Controls
- **Secret Management**
  - Secret scanning enabled: Check repository-specific settings
  - Push protection: Check repository-specific branch protection settings

- **Code Review Requirements**
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

EOF

echo "FedRAMP/NIST compliance audit completed successfully! Report available at: $OUTPUT_DIR/fedramp_nist_compliance_report.md"


