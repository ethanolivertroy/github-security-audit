# Github Security Audit

To use this script:

Save it as `github_security_audit.sh`
Make it executable: `chmod +x github_security_audit.sh`
Run it with your organization name: `./github_security_audit.sh your-org-name`

This script will:

- Create a timestamped output directory
- Gather organization-level information
- List all repositories
- Collect branch protection rules for all branches in each repository
- Gather Dependabot, code scanning, and secret scanning alerts
- Generate a basic summary report

The collected data will provide a comprehensive view of the GitHub security configurations across the entire organization, which you can then evaluate for security gaps and compliance issues.