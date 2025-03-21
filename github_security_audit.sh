#!/bin/bash
# GitHub Organization Security Posture Analysis Script

# Configuration
ORG_NAME="$1"
if [ -z "$ORG_NAME" ]; then
  echo "Usage: $0 <organization-name>"
  exit 1
fi

# Create output directory
OUTPUT_DIR="github_security_audit_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"
echo "Starting security audit for organization: $ORG_NAME"
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

# 1. Collect Organization Information
echo "Gathering organization information..."
gh api "orgs/$ORG_NAME" --jq . > "$OUTPUT_DIR/organization_info.json"

# 2. Collect Organization Security Settings
echo "Gathering organization security settings..."
gh api "orgs/$ORG_NAME/security-managers" --jq . > "$OUTPUT_DIR/security_managers.json"
gh api "orgs/$ORG_NAME/security-advisories" --jq . > "$OUTPUT_DIR/security_advisories.json"
gh api "orgs/$ORG_NAME/dependabot/alerts" --jq . > "$OUTPUT_DIR/dependabot_org_alerts.json" 2>/dev/null || echo "Dependabot org-level alerts access denied"

# 3. Collect Repository List
echo "Gathering repository list..."
gh repo list "$ORG_NAME" --limit 1000 --json name,visibility,isPrivate,isArchived,defaultBranchRef > "$OUTPUT_DIR/repositories.json"

# 4. Process Each Repository
echo "Processing repositories and their branch protection rules..."
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
  gh api "repos/$ORG_NAME/$repo_name" --jq . > "$repo_dir/info.json"
  
  # Get branch protection rules
  echo "  Getting branch protection rules..."
  mkdir -p "$repo_dir/branches"
  
  # Try to get all branches
  gh api "repos/$ORG_NAME/$repo_name/branches" --jq . > "$repo_dir/branches/all_branches.json"
  
  # Process each branch to get protection rules
  jq -r '.[].name' "$repo_dir/branches/all_branches.json" | while read -r branch; do
    echo "    Checking branch: $branch"
    # Try to get branch protection (will only work if it exists)
    gh api "repos/$ORG_NAME/$repo_name/branches/$branch/protection" --jq . > "$repo_dir/branches/${branch}_protection.json" 2>/dev/null || echo "    No branch protection for $branch"
  done
  
  # Get other security features
  echo "  Getting security features..."
  
  # Get Dependabot alerts
  gh api "repos/$ORG_NAME/$repo_name/dependabot/alerts?per_page=100" --jq . > "$repo_dir/dependabot_alerts.json" 2>/dev/null || echo "  Dependabot alerts access denied"
  
  # Get code scanning alerts 
  gh api "repos/$ORG_NAME/$repo_name/code-scanning/alerts?per_page=100" --jq . > "$repo_dir/code_scanning_alerts.json" 2>/dev/null || echo "  Code scanning alerts access denied"
  
  # Get secret scanning alerts
  gh api "repos/$ORG_NAME/$repo_name/secret-scanning/alerts?per_page=100" --jq . > "$repo_dir/secret_scanning_alerts.json" 2>/dev/null || echo "  Secret scanning alerts access denied"
  
  # Get workflows
  gh api "repos/$ORG_NAME/$repo_name/actions/workflows" --jq . > "$repo_dir/workflows.json" 2>/dev/null || echo "  Workflows access denied"
  
done < "$OUTPUT_DIR/repo_list.txt"

# 5. Generate Summary Report
echo "Generating summary report..."

# Count repositories with branch protection
protected_repos=0
total_repos=$(wc -l < "$OUTPUT_DIR/repo_list.txt")

while IFS=, read -r repo_name default_branch; do
  if [ -s "$OUTPUT_DIR/repositories/$repo_name/branches/${default_branch}_protection.json" ]; then
    ((protected_repos++))
  fi
done < "$OUTPUT_DIR/repo_list.txt"

# Create summary report
cat > "$OUTPUT_DIR/summary_report.md" << EOF
# GitHub Security Posture Summary for $ORG_NAME
## Generated on $(date)

### Overview
- Total repositories: $total_repos
- Repositories with protected default branches: $protected_repos ($(( protected_repos * 100 / total_repos ))%)

### Security Recommendations
- Ensure all repositories have branch protection rules
- Enable required reviews for all repositories
- Configure Dependabot alerts and secret scanning
- Implement code scanning with appropriate actions

### Detailed Findings
For detailed analysis, review the JSON files in the output directory.
EOF

echo "Audit completed successfully! Summary report available at: $OUTPUT_DIR/summary_report.md"