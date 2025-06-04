#!/bin/bash
# GitHub Organization Multi-Framework Compliance Audit
# Supports FedRAMP, NIST, SOC2, HIPAA, ISO 27001, PCI-DSS
# Features parallel processing, robust error handling, and comprehensive security checks

set -euo pipefail

# Configuration
ORG_NAME="$1"
FRAMEWORK="${2:-all}"  # Default to all frameworks
MAX_PARALLEL_JOBS=10  # Number of parallel repository scans
RETRY_ATTEMPTS=3
RETRY_DELAY=5

# Supported frameworks
SUPPORTED_FRAMEWORKS=("fedramp" "nist" "soc2" "hipaa" "iso27001" "pci-dss" "all")

# Display usage if organization name is missing
if [ -z "$ORG_NAME" ]; then
  echo "Usage: $0 <organization-name> [framework]"
  echo "  - organization-name: Your GitHub organization name (required)"
  echo "  - framework: Compliance framework (optional, default: all)"
  echo "    Supported: fedramp, nist, soc2, hipaa, iso27001, pci-dss, all"
  echo ""
  echo "Set GITHUB_TOKEN environment variable or authenticate with gh CLI"
  echo "Example: GITHUB_TOKEN=ghp_xxxx $0 my-org soc2"
  exit 1
fi

# Validate framework
if [[ ! " ${SUPPORTED_FRAMEWORKS[@]} " =~ " ${FRAMEWORK} " ]]; then
  echo "Error: Invalid framework '$FRAMEWORK'"
  echo "Supported frameworks: ${SUPPORTED_FRAMEWORKS[*]}"
  exit 1
fi

# Create output directory
OUTPUT_DIR="github_compliance_audit_${FRAMEWORK}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"
echo "Starting $FRAMEWORK compliance audit for organization: $ORG_NAME"
echo "Results will be saved to: $OUTPUT_DIR"

# Initialize progress tracking
echo "0" > "$OUTPUT_DIR/.progress"
echo "0" > "$OUTPUT_DIR/.total"

# Check for required tools
for tool in jq curl parallel; do
  if ! command -v "$tool" &> /dev/null; then
    echo "Error: $tool is required but not installed."
    if [ "$tool" = "parallel" ]; then
      echo "Install with: brew install parallel (macOS) or apt install parallel (Ubuntu)"
    fi
    exit 1
  fi
done

# Setup authentication
if [ -n "${GITHUB_TOKEN:-}" ]; then
  echo "Using GitHub token from environment variable"
  AUTH_HEADER="Authorization: token $GITHUB_TOKEN"
  AUTH_METHOD="token"
else
  # Check for GitHub CLI authentication
  if ! command -v gh &> /dev/null; then
    echo "Error: Either set GITHUB_TOKEN environment variable or install GitHub CLI"
    exit 1
  fi
  
  if ! gh auth status &> /dev/null; then
    echo "Error: Please authenticate with GitHub CLI first using: gh auth login"
    exit 1
  fi
  
  echo "Using GitHub CLI authentication"
  AUTH_METHOD="cli"
  # Export token for parallel jobs
  export GITHUB_TOKEN=$(gh auth token)
  AUTH_HEADER="Authorization: token $GITHUB_TOKEN"
fi

# Utility Functions

# Enhanced API call with retry logic
api_call_with_retry() {
  local endpoint="$1"
  local output_file="$2"
  local attempt=1
  local response
  local http_code
  
  while [ $attempt -le $RETRY_ATTEMPTS ]; do
    if [ "$AUTH_METHOD" = "cli" ] && [ $attempt -eq 1 ]; then
      # Try gh CLI first for better error messages
      if gh api "$endpoint" > "$output_file" 2>/dev/null; then
        return 0
      fi
    fi
    
    # Use curl with retry
    response=$(curl -s -w "\n%{http_code}" -H "$AUTH_HEADER" \
      -H "Accept: application/vnd.github.v3+json" \
      "https://api.github.com/$endpoint")
    
    http_code=$(echo "$response" | tail -n1)
    content=$(echo "$response" | sed '$d')
    
    if [ "$http_code" = "200" ] || [ "$http_code" = "201" ]; then
      echo "$content" > "$output_file"
      return 0
    elif [ "$http_code" = "404" ]; then
      echo "{\"error\": \"Not found\"}" > "$output_file"
      return 0
    elif [ "$http_code" = "403" ] && echo "$content" | grep -q "rate limit"; then
      echo "Rate limit hit, waiting 60 seconds..."
      sleep 60
    else
      echo "API call failed (attempt $attempt/$RETRY_ATTEMPTS): HTTP $http_code"
      if [ $attempt -lt $RETRY_ATTEMPTS ]; then
        sleep $RETRY_DELAY
      fi
    fi
    
    ((attempt++))
  done
  
  echo "{\"error\": \"Failed after $RETRY_ATTEMPTS attempts\"}" > "$output_file"
  return 1
}

# Paginated API calls with retry
api_call_paginated() {
  local endpoint="$1"
  local output_file="$2"
  local all_data="[]"
  local page=1
  local per_page=100
  
  while true; do
    local page_file="${output_file}.page${page}"
    
    if api_call_with_retry "${endpoint}?per_page=${per_page}&page=${page}" "$page_file"; then
      local page_data=$(cat "$page_file")
      
      # Check if we got data
      if [ "$page_data" = "[]" ] || [ "$page_data" = "{\"error\": \"Not found\"}" ]; then
        rm -f "$page_file"
        break
      fi
      
      # Merge data
      if [ "$all_data" = "[]" ]; then
        all_data="$page_data"
      else
        all_data=$(echo "$all_data" | jq --argjson new "$page_data" '. + $new')
      fi
      
      rm -f "$page_file"
      
      # Check if we got a full page (might be more)
      local count=$(echo "$page_data" | jq '. | length')
      if [ "$count" -lt "$per_page" ]; then
        break
      fi
      
      ((page++))
    else
      break
    fi
  done
  
  echo "$all_data" > "$output_file"
}

# Progress tracking
update_progress() {
  local current=$(cat "$OUTPUT_DIR/.progress")
  local total=$(cat "$OUTPUT_DIR/.total")
  ((current++))
  echo "$current" > "$OUTPUT_DIR/.progress"
  
  if [ "$total" -gt 0 ]; then
    local percentage=$((current * 100 / total))
    echo -ne "\rProgress: $current/$total ($percentage%)"
  fi
}

# Function to process a single repository (for parallel execution)
process_repository() {
  local repo_name="$1"
  local org_name="$2"
  local output_dir="$3"
  local auth_header="$4"
  
  # Re-export functions for parallel execution
  export -f api_call_with_retry
  export -f api_call_paginated
  export AUTH_HEADER="$auth_header"
  export RETRY_ATTEMPTS
  export RETRY_DELAY
  
  echo "Processing repository: $repo_name"
  
  # Create repository directory
  local repo_dir="$output_dir/repositories/$repo_name"
  mkdir -p "$repo_dir"
  
  # Get repository details
  api_call_with_retry "repos/$org_name/$repo_name" "$repo_dir/info.json"
  
  # Extract default branch
  local default_branch=$(jq -r '.default_branch // "main"' "$repo_dir/info.json")
  
  # Check branch protection rules
  mkdir -p "$repo_dir/branches"
  api_call_with_retry "repos/$org_name/$repo_name/branches" "$repo_dir/branches/all_branches.json"
  
  # Get protection for default branch
  api_call_with_retry "repos/$org_name/$repo_name/branches/$default_branch/protection" \
    "$repo_dir/branches/${default_branch}_protection.json"
  
  # Security features
  api_call_with_retry "repos/$org_name/$repo_name" "$repo_dir/security_features.json"
  
  # Check for repository rulesets (new feature)
  api_call_with_retry "repos/$org_name/$repo_name/rulesets" "$repo_dir/rulesets.json"
  
  # Dependabot alerts
  api_call_paginated "repos/$org_name/$repo_name/dependabot/alerts" "$repo_dir/dependabot_alerts.json"
  
  # Code scanning alerts
  api_call_paginated "repos/$org_name/$repo_name/code-scanning/alerts" "$repo_dir/code_scanning_alerts.json"
  
  # Secret scanning alerts
  api_call_paginated "repos/$org_name/$repo_name/secret-scanning/alerts" "$repo_dir/secret_scanning_alerts.json"
  
  # Check for push protection bypasses
  api_call_with_retry "repos/$org_name/$repo_name/secret-scanning/push-protection-bypasses" \
    "$repo_dir/push_protection_bypasses.json"
  
  # Workflows
  mkdir -p "$repo_dir/workflows"
  api_call_with_retry "repos/$org_name/$repo_name/actions/workflows" "$repo_dir/workflows/workflows.json"
  
  # Check for GitHub Advanced Security
  api_call_with_retry "repos/$org_name/$repo_name/vulnerability-alerts" "$repo_dir/ghas_status.json"
  
  # Security policy
  api_call_with_retry "repos/$org_name/$repo_name/contents/SECURITY.md" "$repo_dir/security_policy.json"
  
  # CODEOWNERS
  for path in ".github/CODEOWNERS" "CODEOWNERS" "docs/CODEOWNERS"; do
    if api_call_with_retry "repos/$org_name/$repo_name/contents/$path" "$repo_dir/codeowners.json"; then
      if ! grep -q '"error"' "$repo_dir/codeowners.json"; then
        break
      fi
    fi
  done
  
  # Supply chain security
  mkdir -p "$repo_dir/supply_chain"
  
  # Check for SBOM generation
  if [ -f "$repo_dir/workflows/workflows.json" ]; then
    jq -r '.workflows[]?.name // empty' "$repo_dir/workflows/workflows.json" 2>/dev/null | \
      grep -i -E "sbom|cyclonedx|spdx|syft" > "$repo_dir/supply_chain/sbom_workflows.txt" || \
      echo "No SBOM workflows found" > "$repo_dir/supply_chain/sbom_workflows.txt"
  fi
  
  # Check for signing workflows
  if [ -f "$repo_dir/workflows/workflows.json" ]; then
    jq -r '.workflows[]?.name // empty' "$repo_dir/workflows/workflows.json" 2>/dev/null | \
      grep -i -E "sign|cosign|sigstore|signature" > "$repo_dir/supply_chain/signing_workflows.txt" || \
      echo "No signing workflows found" > "$repo_dir/supply_chain/signing_workflows.txt"
  fi
  
  # Check for dependency pinning in workflows
  mkdir -p "$repo_dir/supply_chain/workflow_analysis"
  if [ -f "$repo_dir/workflows/workflows.json" ]; then
    # Get workflow files to check for pinned actions
    jq -r '.workflows[]?.path // empty' "$repo_dir/workflows/workflows.json" 2>/dev/null | while read -r workflow_path; do
      if [ -n "$workflow_path" ]; then
        local workflow_name=$(basename "$workflow_path")
        api_call_with_retry "repos/$org_name/$repo_name/contents/$workflow_path" \
          "$repo_dir/supply_chain/workflow_analysis/${workflow_name}.json"
      fi
    done
  fi
  
  # Check latest release for supply chain artifacts
  api_call_with_retry "repos/$org_name/$repo_name/releases/latest" "$repo_dir/supply_chain/latest_release.json"
  
  if [ -f "$repo_dir/supply_chain/latest_release.json" ] && ! grep -q '"error"' "$repo_dir/supply_chain/latest_release.json"; then
    local release_id=$(jq -r '.id // empty' "$repo_dir/supply_chain/latest_release.json")
    if [ -n "$release_id" ]; then
      api_call_with_retry "repos/$org_name/$repo_name/releases/$release_id/assets" \
        "$repo_dir/supply_chain/release_assets.json"
    fi
  fi
  
  # Update progress
  update_progress
}

# Export functions for parallel execution
export -f process_repository
export -f api_call_with_retry
export -f api_call_paginated
export -f update_progress

# Framework-specific check functions

# Check if a control is applicable to the selected framework
is_control_applicable() {
  local control="$1"
  local framework="$2"
  
  case "$framework" in
    "fedramp"|"nist"|"all")
      # All controls apply for FedRAMP/NIST
      return 0
      ;;
    "soc2")
      # SOC2 Trust Service Criteria mapping
      case "$control" in
        "access_control"|"authentication"|"monitoring"|"encryption"|"audit_logs"|"vulnerability_management")
          return 0 ;;
        *) return 1 ;;
      esac
      ;;
    "hipaa")
      # HIPAA Security Rule controls
      case "$control" in
        "access_control"|"authentication"|"encryption"|"audit_logs"|"integrity"|"transmission_security")
          return 0 ;;
        *) return 1 ;;
      esac
      ;;
    "iso27001")
      # ISO 27001 Annex A controls
      case "$control" in
        "access_control"|"authentication"|"monitoring"|"encryption"|"audit_logs"|"vulnerability_management"|"incident_response")
          return 0 ;;
        *) return 1 ;;
      esac
      ;;
    "pci-dss")
      # PCI-DSS requirements
      case "$control" in
        "access_control"|"authentication"|"monitoring"|"encryption"|"vulnerability_management"|"secure_development")
          return 0 ;;
        *) return 1 ;;
      esac
      ;;
  esac
}

# Get framework-specific requirements
get_framework_requirements() {
  local framework="$1"
  
  case "$framework" in
    "soc2")
      echo "SOC 2 Type II Trust Service Criteria (TSC)"
      echo "- CC6.1: Logical and Physical Access Controls"
      echo "- CC6.6: System Operations" 
      echo "- CC7.1: System Monitoring"
      echo "- CC7.2: Anomaly Detection"
      ;;
    "hipaa")
      echo "HIPAA Security Rule Requirements"
      echo "- 164.308(a)(1): Security Management Process"
      echo "- 164.308(a)(3): Workforce Security"
      echo "- 164.308(a)(4): Information Access Management"
      echo "- 164.312(a)(1): Access Control"
      echo "- 164.312(b): Audit Controls"
      ;;
    "iso27001")
      echo "ISO 27001:2022 Annex A Controls"
      echo "- A.9: Access Control"
      echo "- A.12: Operations Security"
      echo "- A.14: System Development Security"
      echo "- A.16: Incident Management"
      ;;
    "pci-dss")
      echo "PCI-DSS v4.0 Requirements"
      echo "- Requirement 1-2: Network Security"
      echo "- Requirement 3-4: Data Protection"
      echo "- Requirement 7-8: Access Control"
      echo "- Requirement 10: Logging and Monitoring"
      echo "- Requirement 11: Security Testing"
      ;;
  esac
}

# Check framework-specific compliance
check_framework_compliance() {
  local framework="$1"
  local metric="$2"
  local value="$3"
  local threshold="$4"
  
  case "$framework" in
    "soc2")
      # SOC2 generally requires 90%+ compliance
      [ "$value" -ge 90 ] && return 0 || return 1
      ;;
    "hipaa")
      # HIPAA has strict requirements
      case "$metric" in
        "encryption"|"audit_logs"|"access_control")
          [ "$value" -eq 100 ] && return 0 || return 1
          ;;
        *)
          [ "$value" -ge 95 ] && return 0 || return 1
          ;;
      esac
      ;;
    "iso27001")
      # ISO 27001 requirements vary by control
      [ "$value" -ge "$threshold" ] && return 0 || return 1
      ;;
    "pci-dss")
      # PCI-DSS has very strict requirements
      case "$metric" in
        "vulnerability_scanning"|"access_control"|"monitoring")
          [ "$value" -eq 100 ] && return 0 || return 1
          ;;
        *)
          [ "$value" -ge 95 ] && return 0 || return 1
          ;;
      esac
      ;;
    *)
      # Default FedRAMP/NIST thresholds
      [ "$value" -ge "$threshold" ] && return 0 || return 1
      ;;
  esac
}

# Main execution

# 1. Organization Information
echo "Gathering organization information..."
api_call_with_retry "orgs/$ORG_NAME" "$OUTPUT_DIR/organization_info.json"

# Check if organization exists
if grep -q '"error"' "$OUTPUT_DIR/organization_info.json"; then
  echo "Error: Unable to access organization $ORG_NAME"
  exit 1
fi

# 2. Organization Security Settings
echo "Gathering organization security settings..."
mkdir -p "$OUTPUT_DIR/org_security"

# Organization members
api_call_paginated "orgs/$ORG_NAME/members" "$OUTPUT_DIR/org_security/members.json"

# Security managers
api_call_with_retry "orgs/$ORG_NAME/security-managers" "$OUTPUT_DIR/org_security/security_managers.json"

# Teams
api_call_paginated "orgs/$ORG_NAME/teams" "$OUTPUT_DIR/org_security/teams.json"

# 2FA requirement
api_call_with_retry "orgs/$ORG_NAME" "$OUTPUT_DIR/org_security/org_details.json"
jq -r '.two_factor_requirement_enabled' "$OUTPUT_DIR/org_security/org_details.json" > \
  "$OUTPUT_DIR/org_security/two_factor_required.txt"

# GitHub Advanced Security status
jq -r '.plan.advanced_security' "$OUTPUT_DIR/org_security/org_details.json" > \
  "$OUTPUT_DIR/org_security/ghas_enabled.txt" 2>/dev/null || echo "false" > "$OUTPUT_DIR/org_security/ghas_enabled.txt"

# Enterprise settings (if available)
api_call_with_retry "orgs/$ORG_NAME/settings" "$OUTPUT_DIR/org_security/enterprise_settings.json"

# Organization audit log
api_call_with_retry "orgs/$ORG_NAME/audit-log?per_page=10" "$OUTPUT_DIR/org_security/audit_log_sample.json"

# Organization webhooks
api_call_paginated "orgs/$ORG_NAME/hooks" "$OUTPUT_DIR/org_security/webhooks.json"

# GitHub Apps
api_call_paginated "orgs/$ORG_NAME/installations" "$OUTPUT_DIR/org_security/github_apps.json"

# Organization-wide security policy
api_call_with_retry "repos/$ORG_NAME/.github/contents/SECURITY.md" "$OUTPUT_DIR/org_security/security_policy.json"

# 3. Repository Processing
echo "Gathering repository list..."
api_call_paginated "orgs/$ORG_NAME/repos" "$OUTPUT_DIR/repositories.json"

# Count repositories
total_repos=$(jq '. | length' "$OUTPUT_DIR/repositories.json")
echo "$total_repos" > "$OUTPUT_DIR/.total"
echo "Found $total_repos repositories"

# Extract repository names
jq -r '.[].name' "$OUTPUT_DIR/repositories.json" > "$OUTPUT_DIR/repo_list.txt"

# Process repositories in parallel
echo "Processing repositories (parallel execution with $MAX_PARALLEL_JOBS workers)..."
mkdir -p "$OUTPUT_DIR/repositories"

cat "$OUTPUT_DIR/repo_list.txt" | \
  parallel -j "$MAX_PARALLEL_JOBS" \
    process_repository {} "$ORG_NAME" "$OUTPUT_DIR" "$AUTH_HEADER"

echo -e "\n"

# 4. Generate Enhanced Compliance Report
echo "Generating $FRAMEWORK compliance report..."

# Calculate metrics
protected_repos=0
sbom_repos=0
signing_repos=0
rulesets_repos=0
ghas_repos=0
codeowners_repos=0

while read -r repo_name; do
  repo_dir="$OUTPUT_DIR/repositories/$repo_name"
  
  # Check branch protection
  default_branch=$(jq -r '.default_branch // "main"' "$repo_dir/info.json" 2>/dev/null || echo "main")
  if [ -f "$repo_dir/branches/${default_branch}_protection.json" ] && \
     ! grep -q '"error"' "$repo_dir/branches/${default_branch}_protection.json" 2>/dev/null; then
    ((protected_repos++))
  fi
  
  # Check for rulesets
  if [ -f "$repo_dir/rulesets.json" ] && \
     [ "$(jq '. | length' "$repo_dir/rulesets.json" 2>/dev/null || echo 0)" -gt 0 ]; then
    ((rulesets_repos++))
  fi
  
  # Check GHAS
  if [ -f "$repo_dir/security_features.json" ]; then
    if jq -e '.security_and_analysis.advanced_security.status == "enabled"' "$repo_dir/security_features.json" &>/dev/null; then
      ((ghas_repos++))
    fi
  fi
  
  # Check CODEOWNERS
  if [ -f "$repo_dir/codeowners.json" ] && ! grep -q '"error"' "$repo_dir/codeowners.json" 2>/dev/null; then
    ((codeowners_repos++))
  fi
  
  # Check SBOM
  if [ -f "$repo_dir/supply_chain/sbom_workflows.txt" ] && \
     [ "$(cat "$repo_dir/supply_chain/sbom_workflows.txt")" != "No SBOM workflows found" ]; then
    ((sbom_repos++))
  fi
  
  # Check signing
  if [ -f "$repo_dir/supply_chain/signing_workflows.txt" ] && \
     [ "$(cat "$repo_dir/supply_chain/signing_workflows.txt")" != "No signing workflows found" ]; then
    ((signing_repos++))
  fi
done < "$OUTPUT_DIR/repo_list.txt"

# Get organization metrics
two_factor_required=$(cat "$OUTPUT_DIR/org_security/two_factor_required.txt" 2>/dev/null || echo "false")
ghas_enabled=$(cat "$OUTPUT_DIR/org_security/ghas_enabled.txt" 2>/dev/null || echo "false")
has_security_managers="No"
if [ -f "$OUTPUT_DIR/org_security/security_managers.json" ] && \
   ! grep -q '"error"' "$OUTPUT_DIR/org_security/security_managers.json" 2>/dev/null; then
  has_security_managers="Yes"
fi

# Count security alerts
total_dependabot_alerts=0
total_code_scanning_alerts=0
total_secret_scanning_alerts=0

while read -r repo_name; do
  repo_dir="$OUTPUT_DIR/repositories/$repo_name"
  
  if [ -f "$repo_dir/dependabot_alerts.json" ]; then
    count=$(jq '. | length' "$repo_dir/dependabot_alerts.json" 2>/dev/null || echo 0)
    ((total_dependabot_alerts += count))
  fi
  
  if [ -f "$repo_dir/code_scanning_alerts.json" ]; then
    count=$(jq '. | length' "$repo_dir/code_scanning_alerts.json" 2>/dev/null || echo 0)
    ((total_code_scanning_alerts += count))
  fi
  
  if [ -f "$repo_dir/secret_scanning_alerts.json" ]; then
    count=$(jq '. | length' "$repo_dir/secret_scanning_alerts.json" 2>/dev/null || echo 0)
    ((total_secret_scanning_alerts += count))
  fi
done < "$OUTPUT_DIR/repo_list.txt"

# Calculate percentages safely
if [ "$total_repos" -eq 0 ]; then
  total_repos=1  # Prevent division by zero
fi

protected_percentage=$((protected_repos * 100 / total_repos))
rulesets_percentage=$((rulesets_repos * 100 / total_repos))
ghas_percentage=$((ghas_repos * 100 / total_repos))
codeowners_percentage=$((codeowners_repos * 100 / total_repos))
sbom_percentage=$((sbom_repos * 100 / total_repos))
signing_percentage=$((signing_repos * 100 / total_repos))

# Calculate risk score (0-100, lower is better)
risk_score=100

# Deduct points for good security practices
[ "$two_factor_required" = "true" ] && ((risk_score -= 10))
[ "$has_security_managers" = "Yes" ] && ((risk_score -= 5))
[ "$ghas_enabled" = "true" ] && ((risk_score -= 10))
((risk_score -= protected_percentage / 4))  # Max -25 points
((risk_score -= rulesets_percentage / 10))  # Max -10 points
((risk_score -= sbom_percentage / 10))      # Max -10 points
((risk_score -= signing_percentage / 10))   # Max -10 points

# Ensure risk score doesn't go below 0
[ $risk_score -lt 0 ] && risk_score=0

# Determine compliance level
if [ $risk_score -le 20 ]; then
  compliance_level="High"
elif [ $risk_score -le 50 ]; then
  compliance_level="Medium"
else
  compliance_level="Low"
fi

# Framework-specific report generation functions

# Generate SOC2 report
generate_soc2_report() {
  cat > "$REPORT_FILE" << EOF
# GitHub SOC 2 Type II Compliance Report for $ORG_NAME
## Generated on $(date)

## Executive Summary

**Organization**: $ORG_NAME  
**Total Repositories**: $total_repos  
**Risk Score**: $risk_score/100 (lower is better)  
**Compliance Level**: $compliance_level  

### SOC 2 Trust Service Criteria (TSC) Assessment

#### Security (Common Criteria)

| Criteria | Description | Status | Evidence |
|----------|-------------|--------|----------|
| CC6.1 | Logical and Physical Access Controls | $([ "$two_factor_required" = "true" ] && [ $protected_percentage -gt 90 ] && echo "✓" || echo "✗") | 2FA: $two_factor_required, Branch Protection: $protected_percentage% |
| CC6.2 | Prior to Issuing System Credentials | $([ "$has_security_managers" = "Yes" ] && echo "✓" || echo "✗") | Security managers configured |
| CC6.3 | Role-Based Access Control | $([ $codeowners_percentage -gt 90 ] && echo "✓" || echo "⚠") | CODEOWNERS: $codeowners_percentage% |
| CC6.6 | Logical Access Security Measures | $([ "$ghas_enabled" = "true" ] && echo "✓" || echo "✗") | GHAS enabled: $ghas_enabled |
| CC6.7 | System User Authentication | $([ "$two_factor_required" = "true" ] && echo "✓" || echo "✗") | Multi-factor authentication enforced |
| CC6.8 | System Component Removal | $([ $protected_percentage -gt 90 ] && echo "✓" || echo "⚠") | Access controls in place |

#### System Operations

| Criteria | Description | Status | Evidence |
|----------|-------------|--------|----------|
| CC7.1 | Detection and Monitoring | $([ $total_secret_scanning_alerts -lt 5 ] && echo "✓" || echo "⚠") | Secret scanning: $total_secret_scanning_alerts alerts |
| CC7.2 | System Monitoring | $([ "$ghas_enabled" = "true" ] && echo "✓" || echo "⚠") | Continuous monitoring enabled |
| CC7.3 | Evaluating Security Events | $([ -f "$OUTPUT_DIR/org_security/audit_log_sample.json" ] && echo "✓" || echo "✗") | Audit logging configured |
| CC7.4 | Responding to Security Incidents | $([ -f "$OUTPUT_DIR/org_security/security_policy.json" ] && ! grep -q '"error"' "$OUTPUT_DIR/org_security/security_policy.json" && echo "✓" || echo "⚠") | Security policy exists |

### Compliance Gaps

EOF

  # Add SOC2-specific gaps
  [ "$two_factor_required" != "true" ] && echo "- **CC6.7**: Enable mandatory 2FA for all users" >> "$REPORT_FILE"
  [ $protected_percentage -lt 90 ] && echo "- **CC6.1**: Increase branch protection coverage to 90%+ (currently $protected_percentage%)" >> "$REPORT_FILE"
  [ $codeowners_percentage -lt 90 ] && echo "- **CC6.3**: Implement CODEOWNERS in 90%+ of repositories (currently $codeowners_percentage%)" >> "$REPORT_FILE"
  
  cat >> "$REPORT_FILE" << EOF

### Recommendations

1. **Access Control**: Achieve 100% 2FA enforcement and 95%+ branch protection
2. **Monitoring**: Enable GHAS and configure comprehensive audit log retention
3. **Incident Response**: Document and test security incident procedures
4. **Change Management**: Implement repository rulesets for all critical repositories

EOF
}

# Generate HIPAA report
generate_hipaa_report() {
  cat > "$REPORT_FILE" << EOF
# GitHub HIPAA Security Rule Compliance Report for $ORG_NAME
## Generated on $(date)

## Executive Summary

**Organization**: $ORG_NAME  
**Total Repositories**: $total_repos  
**Risk Score**: $risk_score/100 (lower is better)  
**Compliance Level**: $compliance_level  

### HIPAA Security Rule Assessment

#### Administrative Safeguards (45 CFR § 164.308)

| Standard | Implementation Specification | Status | Evidence |
|----------|----------------------------|--------|----------|
| 164.308(a)(1) | Risk Analysis | $([ "$ghas_enabled" = "true" ] && echo "✓" || echo "✗") | Security scanning: $ghas_enabled |
| 164.308(a)(1) | Risk Management | $([ $total_dependabot_alerts -lt 20 ] && echo "✓" || echo "⚠") | Vulnerability alerts: $total_dependabot_alerts |
| 164.308(a)(3) | Workforce Security | $([ "$two_factor_required" = "true" ] && echo "✓" || echo "✗") | 2FA enforcement: $two_factor_required |
| 164.308(a)(4) | Access Management | $([ $protected_percentage -eq 100 ] && echo "✓" || echo "✗") | Branch protection: $protected_percentage% |
| 164.308(a)(5) | Security Training | $([ -f "$OUTPUT_DIR/org_security/security_policy.json" ] && ! grep -q '"error"' "$OUTPUT_DIR/org_security/security_policy.json" && echo "✓" || echo "⚠") | Security policy documented |

#### Technical Safeguards (45 CFR § 164.312)

| Standard | Implementation Specification | Status | Evidence |
|----------|----------------------------|--------|----------|
| 164.312(a)(1) | Unique User Identification | $([ "$two_factor_required" = "true" ] && echo "✓" || echo "✗") | User authentication enforced |
| 164.312(a)(2) | Automatic Logoff | N/A | GitHub session management |
| 164.312(a)(2) | Encryption and Decryption | ✓ | GitHub uses encryption in transit/at rest |
| 164.312(b) | Audit Controls | $([ -f "$OUTPUT_DIR/org_security/audit_log_sample.json" ] && echo "✓" || echo "✗") | Audit logging enabled |
| 164.312(c) | Integrity Controls | $([ $signing_percentage -gt 95 ] && echo "✓" || echo "✗") | Artifact signing: $signing_percentage% |
| 164.312(e) | Transmission Security | ✓ | HTTPS enforced by GitHub |

### Critical HIPAA Gaps

EOF

  # HIPAA requires 100% compliance for certain controls
  [ "$two_factor_required" != "true" ] && echo "- **CRITICAL**: Enable mandatory 2FA (164.308(a)(3))" >> "$REPORT_FILE"
  [ $protected_percentage -lt 100 ] && echo "- **CRITICAL**: Achieve 100% branch protection (164.308(a)(4))" >> "$REPORT_FILE"
  [ $signing_percentage -lt 95 ] && echo "- **CRITICAL**: Implement artifact signing for integrity (164.312(c))" >> "$REPORT_FILE"
  
  cat >> "$REPORT_FILE" << EOF

### Required Actions for HIPAA Compliance

1. **Immediate**: Enable 2FA and achieve 100% branch protection
2. **Within 30 days**: Implement comprehensive audit logging with retention
3. **Within 60 days**: Deploy artifact signing and integrity controls
4. **Ongoing**: Regular risk assessments and workforce training

EOF
}

# Generate ISO 27001 report
generate_iso27001_report() {
  cat > "$REPORT_FILE" << EOF
# GitHub ISO 27001:2022 Compliance Report for $ORG_NAME
## Generated on $(date)

## Executive Summary

**Organization**: $ORG_NAME  
**Total Repositories**: $total_repos  
**Risk Score**: $risk_score/100 (lower is better)  
**Compliance Level**: $compliance_level  

### ISO 27001 Annex A Controls Assessment

#### A.5 - Organizational Controls

| Control | Description | Status | Evidence |
|---------|-------------|--------|----------|
| A.5.1 | Policies for information security | $([ -f "$OUTPUT_DIR/org_security/security_policy.json" ] && ! grep -q '"error"' "$OUTPUT_DIR/org_security/security_policy.json" && echo "✓" || echo "⚠") | Security policy exists |
| A.5.2 | Information security roles | $([ "$has_security_managers" = "Yes" ] && echo "✓" || echo "✗") | Security managers: $has_security_managers |

#### A.8 - Asset Management

| Control | Description | Status | Evidence |
|---------|-------------|--------|----------|
| A.8.1 | Inventory of assets | ✓ | Repository inventory maintained |
| A.8.2 | Ownership of assets | $([ $codeowners_percentage -gt 80 ] && echo "✓" || echo "⚠") | CODEOWNERS: $codeowners_percentage% |

#### A.9 - Access Control

| Control | Description | Status | Evidence |
|---------|-------------|--------|----------|
| A.9.1 | Access control policy | $([ $protected_percentage -gt 80 ] && echo "✓" || echo "⚠") | Branch protection: $protected_percentage% |
| A.9.2 | User access management | $([ "$two_factor_required" = "true" ] && echo "✓" || echo "✗") | 2FA required: $two_factor_required |
| A.9.3 | User responsibilities | $([ $codeowners_percentage -gt 50 ] && echo "✓" || echo "⚠") | Defined in CODEOWNERS |
| A.9.4 | System access control | $([ "$ghas_enabled" = "true" ] && echo "✓" || echo "⚠") | Advanced security controls |

#### A.12 - Operations Security

| Control | Description | Status | Evidence |
|---------|-------------|--------|----------|
| A.12.1 | Operational procedures | $([ $rulesets_percentage -gt 50 ] && echo "✓" || echo "⚠") | Repository rulesets: $rulesets_percentage% |
| A.12.2 | Protection from malware | $([ $total_code_scanning_alerts -lt 50 ] && echo "✓" || echo "⚠") | Code scanning: $total_code_scanning_alerts alerts |
| A.12.6 | Vulnerability management | $([ $total_dependabot_alerts -lt 50 ] && echo "✓" || echo "⚠") | Dependabot alerts: $total_dependabot_alerts |

### ISO 27001 Compliance Gaps

EOF

  # Add ISO 27001 specific gaps
  [ "$two_factor_required" != "true" ] && echo "- **A.9.2**: Enable mandatory 2FA" >> "$REPORT_FILE"
  [ $protected_percentage -lt 80 ] && echo "- **A.9.1**: Increase branch protection to 80%+ (currently $protected_percentage%)" >> "$REPORT_FILE"
  [ $sbom_percentage -lt 60 ] && echo "- **A.12.1**: Implement SBOM generation (currently $sbom_percentage%)" >> "$REPORT_FILE"
  
  cat >> "$REPORT_FILE" << EOF

### ISO 27001 Implementation Roadmap

1. **Phase 1 (1-3 months)**: Establish ISMS foundation
   - Enable 2FA and branch protection
   - Document security policies and procedures
   - Assign security roles and responsibilities

2. **Phase 2 (3-6 months)**: Implement technical controls
   - Deploy GHAS across all repositories
   - Configure vulnerability management
   - Establish incident response procedures

3. **Phase 3 (6-12 months)**: Continuous improvement
   - Regular security assessments
   - Metrics and KPI tracking
   - Internal audit program

EOF
}

# Generate PCI-DSS report
generate_pcidss_report() {
  cat > "$REPORT_FILE" << EOF
# GitHub PCI-DSS v4.0 Compliance Report for $ORG_NAME
## Generated on $(date)

## Executive Summary

**Organization**: $ORG_NAME  
**Total Repositories**: $total_repos  
**Risk Score**: $risk_score/100 (lower is better)  
**Compliance Level**: $compliance_level  

### PCI-DSS Requirements Assessment

#### Requirement 1-2: Network Security Controls

| Requirement | Description | Status | Evidence |
|-------------|-------------|--------|----------|
| 1.2.1 | Restrict inbound/outbound traffic | $([ $protected_percentage -eq 100 ] && echo "✓" || echo "✗") | Access controls: $protected_percentage% |
| 2.2.1 | Configuration standards | $([ $rulesets_percentage -gt 90 ] && echo "✓" || echo "⚠") | Repository rulesets: $rulesets_percentage% |

#### Requirement 3-4: Protect Stored Data

| Requirement | Description | Status | Evidence |
|-------------|-------------|--------|----------|
| 3.4.1 | Strong cryptography | ✓ | GitHub encryption enabled |
| 4.1.1 | Strong cryptography in transit | ✓ | HTTPS enforced |

#### Requirement 6: Secure Development

| Requirement | Description | Status | Evidence |
|-------------|-------------|--------|----------|
| 6.2.1 | Secure development process | $([ "$ghas_enabled" = "true" ] && echo "✓" || echo "✗") | GHAS: $ghas_enabled |
| 6.3.1 | Security vulnerabilities addressed | $([ $total_dependabot_alerts -eq 0 ] && echo "✓" || echo "✗") | Open vulnerabilities: $total_dependabot_alerts |
| 6.3.2 | Code review | $([ $protected_percentage -eq 100 ] && echo "✓" || echo "✗") | PR reviews enforced: $protected_percentage% |
| 6.5.1 | Secure coding training | $([ -f "$OUTPUT_DIR/org_security/security_policy.json" ] && ! grep -q '"error"' "$OUTPUT_DIR/org_security/security_policy.json" && echo "✓" || echo "⚠") | Security guidelines documented |

#### Requirement 7-8: Access Control

| Requirement | Description | Status | Evidence |
|-------------|-------------|--------|----------|
| 7.1.1 | Access control policy | $([ $codeowners_percentage -eq 100 ] && echo "✓" || echo "✗") | CODEOWNERS: $codeowners_percentage% |
| 8.3.1 | Strong authentication | $([ "$two_factor_required" = "true" ] && echo "✓" || echo "✗") | MFA enforced: $two_factor_required |

#### Requirement 10: Logging and Monitoring

| Requirement | Description | Status | Evidence |
|-------------|-------------|--------|----------|
| 10.2.1 | Audit logs implemented | $([ -f "$OUTPUT_DIR/org_security/audit_log_sample.json" ] && echo "✓" || echo "✗") | Audit logging enabled |
| 10.3.1 | Audit log protection | $([ $protected_percentage -eq 100 ] && echo "✓" || echo "✗") | Access controls in place |

### PCI-DSS v4.0 Critical Failures

EOF

  # PCI-DSS has zero tolerance for certain requirements
  [ "$two_factor_required" != "true" ] && echo "- **FAIL - Req 8.3.1**: MFA not enforced" >> "$REPORT_FILE"
  [ $protected_percentage -lt 100 ] && echo "- **FAIL - Req 6.3.2**: Code review not enforced on all repos" >> "$REPORT_FILE"
  [ $total_dependabot_alerts -gt 0 ] && echo "- **FAIL - Req 6.3.1**: $total_dependabot_alerts unresolved vulnerabilities" >> "$REPORT_FILE"
  [ "$ghas_enabled" != "true" ] && echo "- **FAIL - Req 6.2.1**: Secure development tools not enabled" >> "$REPORT_FILE"
  
  cat >> "$REPORT_FILE" << EOF

### Required for PCI-DSS Compliance

1. **IMMEDIATE ACTION REQUIRED**:
   - Enable mandatory 2FA for all users
   - Achieve 100% branch protection with code review
   - Resolve all security vulnerabilities
   - Enable GitHub Advanced Security

2. **Customized Approach Considerations**:
   - Document compensating controls
   - Perform targeted risk analysis
   - Implement additional monitoring

EOF
}

# Generate framework-specific report
generate_framework_report() {
  local framework="$1"
  
  case "$framework" in
    "fedramp"|"nist")
      generate_fedramp_nist_report
      ;;
    "soc2")
      generate_soc2_report
      ;;
    "hipaa")
      generate_hipaa_report
      ;;
    "iso27001")
      generate_iso27001_report
      ;;
    "pci-dss")
      generate_pcidss_report
      ;;
  esac
}

# Generate combined report for all frameworks
generate_combined_report() {
  cat > "$REPORT_FILE" << EOF
# GitHub Multi-Framework Compliance Report for $ORG_NAME
## Generated on $(date)

## Executive Summary

**Organization**: $ORG_NAME  
**Total Repositories**: $total_repos  
**Risk Score**: $risk_score/100 (lower is better)  
**Overall Compliance Level**: $compliance_level  

### Framework Compliance Summary

| Framework | Compliance Status | Key Gaps | Recommended Actions |
|-----------|------------------|----------|-------------------|
| FedRAMP/NIST | $([ $protected_percentage -gt 80 ] && [ "$two_factor_required" = "true" ] && echo "✓ Compliant" || echo "⚠ Gaps Identified") | $([ "$two_factor_required" != "true" ] && echo "2FA, " || echo "")$([ $protected_percentage -lt 80 ] && echo "Branch Protection" || echo "None") | See detailed assessment |
| SOC 2 | $([ $protected_percentage -gt 90 ] && [ "$two_factor_required" = "true" ] && echo "✓ Compliant" || echo "⚠ Gaps Identified") | $([ $protected_percentage -lt 90 ] && echo "90%+ coverage needed" || echo "Minor gaps") | Focus on monitoring |
| HIPAA | $([ $protected_percentage -eq 100 ] && [ "$two_factor_required" = "true" ] && echo "✓ Compliant" || echo "✗ Non-Compliant") | $([ $protected_percentage -lt 100 ] && echo "100% protection required" || echo "Audit controls") | Immediate action required |
| ISO 27001 | $([ $protected_percentage -gt 80 ] && [ "$two_factor_required" = "true" ] && echo "✓ Ready for Certification" || echo "⚠ Preparation Needed") | Documentation gaps | Implement ISMS |
| PCI-DSS | $([ $protected_percentage -eq 100 ] && [ "$two_factor_required" = "true" ] && [ $total_dependabot_alerts -eq 0 ] && echo "✓ Compliant" || echo "✗ Non-Compliant") | $([ $total_dependabot_alerts -gt 0 ] && echo "$total_dependabot_alerts vulnerabilities" || echo "Access controls") | Critical remediation |

### Universal Security Controls Assessment

| Control Area | Current State | FedRAMP | SOC2 | HIPAA | ISO 27001 | PCI-DSS |
|-------------|--------------|---------|------|-------|-----------|---------|
| Multi-Factor Auth | $two_factor_required | Required | Required | Required | Required | Required |
| Branch Protection | $protected_percentage% | 80%+ | 90%+ | 100% | 80%+ | 100% |
| Vulnerability Mgmt | $total_dependabot_alerts alerts | <100 | <50 | <20 | <50 | 0 |
| Code Scanning | $([ "$ghas_enabled" = "true" ] && echo "Enabled" || echo "Disabled") | Recommended | Required | Required | Recommended | Required |
| Audit Logging | $([ -f "$OUTPUT_DIR/org_security/audit_log_sample.json" ] && echo "Enabled" || echo "Disabled") | Required | Required | Required | Required | Required |
| SBOM Generation | $sbom_percentage% | 50%+ | N/A | N/A | 60%+ | Recommended |
| Artifact Signing | $signing_percentage% | 50%+ | N/A | 95%+ | Recommended | Recommended |

### Critical Actions Required Across All Frameworks

1. **Immediate (All Frameworks)**:
EOF

  # Add universal critical actions
  [ "$two_factor_required" != "true" ] && echo "   - ⚠️ **CRITICAL**: Enable mandatory 2FA organization-wide" >> "$REPORT_FILE"
  [ "$ghas_enabled" != "true" ] && echo "   - ⚠️ **CRITICAL**: Enable GitHub Advanced Security" >> "$REPORT_FILE"
  [ $protected_percentage -lt 80 ] && echo "   - ⚠️ **HIGH**: Increase branch protection to 80%+ minimum" >> "$REPORT_FILE"
  
  cat >> "$REPORT_FILE" << EOF

2. **Framework-Specific Requirements**:
   - **HIPAA**: Achieve 100% branch protection and resolve all vulnerabilities
   - **PCI-DSS**: Zero tolerance for vulnerabilities, 100% code review required
   - **SOC 2**: Implement comprehensive monitoring and incident response
   - **ISO 27001**: Document ISMS and establish risk management processes
   - **FedRAMP**: Implement continuous monitoring and supply chain controls

### Detailed Framework Assessments

For detailed compliance requirements and gaps for each framework, generate individual reports:
- FedRAMP/NIST: Run with 'fedramp' or 'nist' parameter
- SOC 2: Run with 'soc2' parameter  
- HIPAA: Run with 'hipaa' parameter
- ISO 27001: Run with 'iso27001' parameter
- PCI-DSS: Run with 'pci-dss' parameter

### Risk Prioritization Matrix

| Risk Level | Frameworks Affected | Required Action | Timeline |
|-----------|-------------------|----------------|----------|
| CRITICAL | All | Enable 2FA, GHAS | Immediate |
| HIGH | HIPAA, PCI-DSS | 100% branch protection | 1 week |
| MEDIUM | SOC2, ISO 27001 | Enhanced monitoring | 1 month |
| LOW | FedRAMP | Supply chain security | 3 months |

### Audit Metadata
- **Audit Date**: $(date)
- **Total Repositories**: $total_repos
- **Frameworks Assessed**: All (FedRAMP, NIST, SOC2, HIPAA, ISO 27001, PCI-DSS)
- **Output Directory**: $OUTPUT_DIR

EOF
}

# Generate FedRAMP/NIST report (original)
generate_fedramp_nist_report() {
cat > "$REPORT_FILE" << EOF
# GitHub FedRAMP/NIST Compliance Report for $ORG_NAME
## Generated on $(date)

## Executive Summary

**Organization**: $ORG_NAME  
**Total Repositories**: $total_repos  
**Risk Score**: $risk_score/100 (lower is better)  
**Compliance Level**: $compliance_level  

### Key Security Metrics

| Security Control | Status | Coverage |
|-----------------|--------|----------|
| Two-Factor Authentication | $two_factor_required | Organization-wide |
| GitHub Advanced Security | $ghas_enabled | Organization-wide |
| Branch Protection | Enabled | $protected_percentage% of repos |
| Repository Rulesets | Configured | $rulesets_percentage% of repos |
| CODEOWNERS Files | Present | $codeowners_percentage% of repos |
| SBOM Generation | Implemented | $sbom_percentage% of repos |
| Artifact Signing | Configured | $signing_percentage% of repos |

### Security Alerts Summary

- **Dependabot Alerts**: $total_dependabot_alerts total
- **Code Scanning Alerts**: $total_code_scanning_alerts total  
- **Secret Scanning Alerts**: $total_secret_scanning_alerts total

## Detailed Compliance Assessment

### NIST SP 800-53 Rev 5 Controls

#### Access Control (AC) Family
| Control | Description | Status | Evidence |
|---------|-------------|--------|-----------|
| AC-2 | Account Management | $([ "$has_security_managers" = "Yes" ] && echo "✓" || echo "✗") | Security managers: $has_security_managers |
| AC-2(1) | Automated Account Management | $([ "$two_factor_required" = "true" ] && echo "✓" || echo "✗") | 2FA enforcement: $two_factor_required |
| AC-3 | Access Enforcement | $([ $protected_percentage -gt 80 ] && echo "✓" || echo "⚠") | Branch protection: $protected_percentage% |
| AC-6 | Least Privilege | $([ $codeowners_percentage -gt 50 ] && echo "✓" || echo "⚠") | CODEOWNERS: $codeowners_percentage% |

#### Identification and Authentication (IA) Family
| Control | Description | Status | Evidence |
|---------|-------------|--------|-----------|
| IA-2 | Identification and Authentication | $([ "$two_factor_required" = "true" ] && echo "✓" || echo "✗") | 2FA required: $two_factor_required |
| IA-2(1) | Multi-factor Authentication | $([ "$two_factor_required" = "true" ] && echo "✓" || echo "✗") | 2FA enforcement: $two_factor_required |
| IA-5 | Authenticator Management | $([ "$two_factor_required" = "true" ] && echo "✓" || echo "⚠") | Strong authentication required |

#### Risk Assessment (RA) Family
| Control | Description | Status | Evidence |
|---------|-------------|--------|-----------|
| RA-5 | Vulnerability Monitoring | $([ "$ghas_enabled" = "true" ] && echo "✓" || echo "⚠") | GHAS: $ghas_enabled, Alerts: $total_dependabot_alerts |
| RA-5(2) | Update Vulnerabilities | $([ $total_dependabot_alerts -lt 50 ] && echo "✓" || echo "⚠") | Active vulnerability management |

#### System and Information Integrity (SI) Family
| Control | Description | Status | Evidence |
|---------|-------------|--------|-----------|
| SI-2 | Flaw Remediation | $([ $total_dependabot_alerts -lt 100 ] && echo "✓" || echo "⚠") | Dependabot alerts: $total_dependabot_alerts |
| SI-3 | Malicious Code Protection | $([ $total_code_scanning_alerts -lt 50 ] && echo "✓" || echo "⚠") | Code scanning alerts: $total_code_scanning_alerts |
| SI-4 | System Monitoring | $([ $total_secret_scanning_alerts -lt 10 ] && echo "✓" || echo "⚠") | Secret scanning alerts: $total_secret_scanning_alerts |

#### Configuration Management (CM) Family
| Control | Description | Status | Evidence |
|---------|-------------|--------|-----------|
| CM-2 | Baseline Configuration | $([ $protected_percentage -gt 80 ] && echo "✓" || echo "⚠") | Protected branches: $protected_percentage% |
| CM-3 | Configuration Change Control | $([ $rulesets_percentage -gt 50 ] && echo "✓" || echo "⚠") | Repository rulesets: $rulesets_percentage% |
| CM-5 | Access Restrictions | $([ $protected_percentage -gt 80 ] && echo "✓" || echo "⚠") | Branch protection enforcement |

### NIST SP 800-161 Rev 1 Update 1 Supply Chain Controls

#### Supply Chain Risk Management (SR) Family
| Control | Description | Status | Evidence |
|---------|-------------|--------|-----------|
| SR-3 | Supply Chain Controls | $([ $protected_percentage -gt 80 ] && echo "✓" || echo "⚠") | Development controls enforced |
| SR-4 | Provenance | $([ $sbom_percentage -gt 50 ] && echo "✓" || echo "⚠") | SBOM generation: $sbom_percentage% |
| SR-10 | Inspection of Systems | $([ "$ghas_enabled" = "true" ] && echo "✓" || echo "⚠") | Automated security scanning |
| SR-11 | Component Authenticity | $([ $signing_percentage -gt 50 ] && echo "✓" || echo "⚠") | Artifact signing: $signing_percentage% |

### Critical Findings and Recommendations

#### 🔴 Critical Issues (Immediate Action Required)
EOF

# Add critical findings
if [ "$two_factor_required" != "true" ]; then
  echo "- **Enable mandatory 2FA**: Organization does not require two-factor authentication" >> "$OUTPUT_DIR/fedramp_nist_compliance_report.md"
fi

if [ "$ghas_enabled" != "true" ]; then
  echo "- **Enable GitHub Advanced Security**: GHAS provides critical security scanning capabilities" >> "$OUTPUT_DIR/fedramp_nist_compliance_report.md"
fi

if [ $protected_percentage -lt 50 ]; then
  echo "- **Implement branch protection**: Only $protected_percentage% of repositories have protected branches" >> "$OUTPUT_DIR/fedramp_nist_compliance_report.md"
fi

cat >> "$OUTPUT_DIR/fedramp_nist_compliance_report.md" << EOF

#### 🟡 High Priority Improvements
EOF

if [ $sbom_percentage -lt 50 ]; then
  echo "- Generate SBOMs for all repositories (currently $sbom_percentage%)" >> "$OUTPUT_DIR/fedramp_nist_compliance_report.md"
fi

if [ $signing_percentage -lt 50 ]; then
  echo "- Implement artifact signing (currently $signing_percentage%)" >> "$OUTPUT_DIR/fedramp_nist_compliance_report.md"
fi

if [ $rulesets_percentage -lt 50 ]; then
  echo "- Configure repository rulesets for advanced controls (currently $rulesets_percentage%)" >> "$OUTPUT_DIR/fedramp_nist_compliance_report.md"
fi

cat >> "$OUTPUT_DIR/fedramp_nist_compliance_report.md" << EOF

#### 🟢 Recommended Enhancements
- Implement automated compliance scanning in CI/CD pipelines
- Configure audit log streaming for long-term retention
- Document and test incident response procedures
- Establish automated dependency update policies
- Create security champions program

### Next Steps

1. **Immediate (Week 1)**
   - Enable mandatory 2FA for all organization members
   - Configure branch protection on all active repositories
   - Review and remediate critical security alerts

2. **Short-term (Month 1)**
   - Implement GitHub Advanced Security across all repositories
   - Deploy SBOM generation workflows
   - Configure artifact signing for releases

3. **Long-term (Quarter 1)**
   - Achieve 100% branch protection coverage
   - Implement repository rulesets for fine-grained controls
   - Establish continuous compliance monitoring

### Audit Details
- **Audit Date**: $(date)
- **Total Repositories Scanned**: $total_repos
- **Parallel Workers Used**: $MAX_PARALLEL_JOBS
- **Output Directory**: $OUTPUT_DIR

For detailed findings per repository, review the JSON files in the output directory.
EOF
}

# Generate report based on selected framework
if [ "$FRAMEWORK" = "all" ]; then
  # Generate combined report for all frameworks
  generate_combined_report
else
  # Generate specific framework report
  generate_framework_report "$FRAMEWORK"
fi

echo "$FRAMEWORK compliance audit completed!"
echo "Report available at: $REPORT_FILE"
echo "Risk Score: $risk_score/100 (Compliance Level: $compliance_level)"