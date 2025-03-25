# GitHub FedRAMP/NIST Compliance Audit Tool

A comprehensive Bash script for auditing GitHub organizations against FedRAMP and NIST 800-53 security requirements.

## Overview

This tool performs a comprehensive security audit of GitHub organizations to assess compliance with FedRAMP and NIST 800-53 security requirements. It collects data on organization-level and repository-level security settings and generates a detailed report that maps findings to specific compliance controls.

## Features

- **Organization-Level Assessment**
  - Two-factor authentication enforcement
  - Security manager role configuration
  - IP allow lists settings
  - Audit log configuration
  - Organization-wide security policies

- **Repository-Level Assessment**
  - Branch protection rules
  - Dependabot alerts and security updates
  - Code scanning configuration
  - Secret scanning with push protection
  - CODEOWNERS file verification
  - Security policy verification
  - CI/CD security checks

- **Compliance Mapping**
  - Maps findings to NIST SP 800-53 control families
  - Specifically addresses FedRAMP requirements
  - Provides compliance metrics and statistics

## Prerequisites

- GitHub CLI (`gh`) installed and configured
- `jq` for JSON processing
- Bash shell environment
- GitHub account with appropriate permissions:
  - Admin access to the organization to be audited
  - Security manager role is recommended

## Installation

1. Download the script file:
   ```bash
   curl -O https://raw.githubusercontent.com/yourusername/github-fedramp-audit/main/github_fedramp_audit.sh
   ```

2. Make the script executable:
   ```bash
   chmod +x github_fedramp_audit.sh
   ```

3. Ensure GitHub CLI is installed and authenticated:
   ```bash
   # Install GitHub CLI (if not already installed)
   # For Ubuntu/Debian:
   sudo apt install gh
   
   # For macOS:
   brew install gh
   
   # Install jq (if not already installed)
   # For Ubuntu/Debian:
   sudo apt install jq
   
   # For macOS:
   brew install jq
   
   # Authenticate with GitHub
   gh auth login
   ```

## Usage

Run the script with your organization name and optionally a GitHub token:

```bash
# Using GitHub CLI authentication
./github_fedramp_audit.sh your-organization-name

# Using a GitHub token (recommended for CI/CD or headless environments)
./github_fedramp_audit.sh your-organization-name your-github-token
```

The script will create an output directory with all collected data and a comprehensive compliance report.

### Finding Your GitHub Organization Name

Your GitHub organization name is the name that appears in your organization's URL. Here's how to find it:

1. **From the URL**: 
   - Go to your organization in GitHub
   - Look at the URL, which will be in the format: `https://github.com/YOUR-ORG-NAME`
   - The text after `github.com/` is your organization name

2. **From GitHub UI**:
   - Log in to GitHub
   - Click your profile photo in the top-right corner
   - Click "Your organizations" from the dropdown
   - Find your organization in the list - the name displayed is your organization name

For example, if your organization URL is `https://github.com/acme-corporation`, then your organization name is `acme-corporation`.

### GitHub Token

When using a token, ensure it has the following permissions:
- `repo` (full access to repositories)
- `read:org` (read organization information)
- `admin:org_hook` (for organization webhooks)
- `security_events` (for code scanning and secret scanning)

This is particularly useful for:
- Running the script in CI/CD pipelines
- Running on systems without GitHub CLI installed
- When you need higher API rate limits
- Running on headless environments

#### Creating a GitHub Token

To generate a GitHub token:

1. Log in to GitHub
2. Click your profile photo in the top-right corner
3. Click "Settings"
4. Scroll down to "Developer settings" in the left sidebar
5. Click "Personal access tokens" → "Tokens (classic)"
6. Click "Generate new token" → "Generate new token (classic)"
7. Give your token a descriptive name (e.g., "FedRAMP Audit Script")
8. Set an expiration date
9. Select the following scopes:
   - `repo` (all repo permissions)
   - `read:org`
   - `admin:org_hook`
   - `security_events`
10. Click "Generate token"
11. Copy the token immediately (you won't be able to see it again)

Use this token when running the script: `./github_fedramp_audit.sh your-organization-name your-token`

## Output

The tool generates the following outputs:

- `organization_info.json`: Basic organization information
- `/org_security/`: Organization security settings
  - `members.json`: Organization members and roles
  - `security_managers.json`: Security manager configuration
  - `teams.json`: Team structure and permissions
  - `two_factor_required.txt`: 2FA requirement status
  - `audit_log_sample.json`: Sample audit log events
  - And more...

- `/repositories/`: Per-repository data
  - `/[repo_name]/info.json`: Repository information
  - `/[repo_name]/branches/`: Branch protection settings
  - `/[repo_name]/dependabot_alerts.json`: Vulnerability alerts
  - `/[repo_name]/code_scanning_alerts.json`: Code scanning results
  - `/[repo_name]/secret_scanning_alerts.json`: Secret scanning results
  - And more...

- `fedramp_nist_compliance_report.md`: Comprehensive compliance report with:
  - Compliance summary statistics
  - Mapping to NIST 800-53 controls
  - FedRAMP-specific requirements assessment
  - Detailed recommendations

### Sample Output

This repository includes a [`sample_output`](./sample_output) directory showing what the audit results look like. Key sample files include:

- [Organization information](./sample_output/organization_info.json)
- [Branch protection rules](./sample_output/repositories/example-repo/branches/main_protection.json)
- [Dependabot alerts](./sample_output/repositories/example-repo/dependabot_alerts.json)
- [Code scanning alerts](./sample_output/repositories/example-repo/code_scanning_alerts.json)
- [Secret scanning alerts](./sample_output/repositories/example-repo/secret_scanning_alerts.json)
- [FedRAMP/NIST compliance report](./sample_output/fedramp_nist_compliance_report.md)

Browse the sample output to understand what data is collected and how the compliance mapping works.

## NIST 800-53 Control Families

The tool evaluates controls across these NIST 800-53 families:

- **AC**: Access Control
- **IA**: Identification and Authentication
- **AU**: Audit and Accountability
- **CM**: Configuration Management
- **RA**: Risk Assessment
- **SI**: System and Information Integrity
- **SC**: System and Communications Protection
- **SA**: System and Services Acquisition

## FedRAMP Alignment

This tool is specifically designed to help organizations prepare for FedRAMP authorization by assessing GitHub security controls against FedRAMP requirements, which are based on NIST 800-53 controls.

## API Rate Limits

The script includes measures to monitor GitHub API rate limits, but if you have a large organization with many repositories, you may encounter rate limiting. In such cases:

- Use a GitHub token with higher rate limits
- Run the script during off-peak hours
- Consider breaking the assessment into smaller segments

## Recommendations for Use

1. Run this audit tool regularly (monthly or quarterly)
2. Include the results in your continuous monitoring documentation
3. Address any compliance gaps identified in the report
4. Use the detailed findings to inform your System Security Plan (SSP)

## Documentation Links

For detailed information on the GitHub security features that this tool evaluates, refer to:

- [Organization security settings](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization)
- [Branch protection rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
- [Security manager role](https://docs.github.com/en/organizations/managing-peoples-access-to-your-organization-with-roles/managing-security-managers-in-your-organization)
- [GitHub Advanced Security](https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security)
- [Audit log documentation](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization)

## Disclaimer

This tool is provided as-is and is not officially endorsed by GitHub or any compliance body. While it helps assess compliance with FedRAMP and NIST 800-53 requirements, it should be used as part of a comprehensive compliance program, not as the sole means of achieving compliance.

Organizations should consult with qualified security professionals and compliance experts when pursuing FedRAMP authorization or implementing NIST 800-53 controls.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details. If you use this tool, please provide attribution to the original author.