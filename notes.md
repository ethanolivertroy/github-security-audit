

1. GitHub API access: Use the GitHub REST or GraphQL API to programmatically pull configuration data.

2. Security features assessment: Review enabled security settings like branch protection rules, code scanning alerts, and secret scanning.

3. Repository audit: Analyze repository-level settings across the organization.



```bash
# Install GitHub CLI if not already available
brew install gh # macOS
# Or use appropriate package manager for other platforms

# Authenticate with GitHub
gh auth login

# List organization repositories
gh repo list <organization-name> --limit 1000 --json name,visibility,isPrivate,isArchived > repos.json

# Get branch protection rules for a specific repo
gh api repos/<organization-name>/<repo-name>/branches/<branch-name>/protection --jq . > branch_protection.json

# Get organization-level security settings
gh api orgs/<organization-name>/security-managers --jq . > security_managers.json
```

List of things to evaluate:

- Branch protection rules
- Code scanning configurations
- Secret scanning settings
- Access controls and permissions
- Authentication requirements (2FA, SSO)
- Dependency review and management
- Security policy presence