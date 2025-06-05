# GitHub Multi-Framework Compliance Audit Tool

A comprehensive Bash script for auditing GitHub organizations against multiple compliance frameworks including FedRAMP, NIST 800-53/800-161, SOC 2, HIPAA, ISO 27001, and PCI-DSS.

## Overview

This tool performs a comprehensive security audit of GitHub organizations to assess compliance with multiple regulatory frameworks:

- **FedRAMP** - Federal Risk and Authorization Management Program
- **NIST 800-53** - Security and Privacy Controls
- **NIST 800-161** - Supply Chain Risk Management
- **SOC 2** - Service Organization Control 2 (Type II)
- **HIPAA** - Health Insurance Portability and Accountability Act
- **ISO 27001** - Information Security Management Systems
- **PCI-DSS** - Payment Card Industry Data Security Standard

The tool collects data on organization-level and repository-level security settings and generates framework-specific compliance reports that map findings to relevant controls and requirements.

<img src="graphic.webp" width="500">

## Features

### Performance & Reliability
- **Parallel Processing**: Scans repositories concurrently for 10x+ performance improvement
- **Robust Error Handling**: Automatic retry logic with exponential backoff
- **Progress Tracking**: Real-time progress indicators during audit
- **Secure Authentication**: Environment variable support to avoid token exposure

### Security Assessments

- **Organization-Level Assessment**
  - Two-factor authentication enforcement
  - Security manager role configuration
  - IP allow lists settings
  - Audit log configuration
  - Organization-wide security policies
  - GitHub Advanced Security status
  - Enterprise security settings
  - Organization webhooks audit
  - GitHub Apps permissions review

- **Repository-Level Assessment**
  - Branch protection rules
  - Repository rulesets (new GitHub feature)
  - Dependabot alerts and security updates
  - Code scanning configuration
  - Secret scanning with push protection
  - Push protection bypass tracking
  - CODEOWNERS file verification
  - Security policy verification
  - CI/CD security checks
  - Workflow dependency pinning analysis

- **Supply Chain Security Assessment**
  - Software Bill of Materials (SBOM) generation
  - Artifact signing and verification
  - Build provenance and attestation
  - Dependency review enforcement
  - Supply chain vulnerability management
  - Action pinning verification

### Reporting & Compliance

- **Multi-Framework Support**: Generate reports for individual frameworks or all at once
- **Risk Scoring**: Executive summary with 0-100 risk score and compliance level assessment
- **Framework-Specific Mapping**: 
  - FedRAMP/NIST: Maps to SP 800-53 and 800-161 control families
  - SOC 2: Maps to Trust Service Criteria (TSC)
  - HIPAA: Maps to Security Rule requirements (45 CFR § 164.308-312)
  - ISO 27001: Maps to Annex A controls
  - PCI-DSS: Maps to v4.0 requirements
- **Actionable Insights**: Framework-specific remediation steps with priority levels
- **Compliance Gaps**: Clear identification of gaps for each framework
- **Metrics Dashboard**: Comprehensive security metrics and statistics

## Prerequisites

- GitHub CLI (`gh`) installed and configured (or GitHub token)
- `jq` for JSON processing
- `parallel` for concurrent processing
- Bash shell environment
- GitHub account with appropriate permissions:
  - Admin access to the organization to be audited
  - Security manager role is recommended

## Installation

1. Download the script file:
   ```bash
   curl -O https://raw.githubusercontent.com/yourusername/github-compliance-audit/main/github_compliance_audit.sh
   ```

2. Make the script executable:
   ```bash
   chmod +x github_compliance_audit.sh
   ```

3. Ensure dependencies are installed:
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
   
   # Install GNU parallel
   # For Ubuntu/Debian:
   sudo apt install parallel
   
   # For macOS:
   brew install parallel
   
   # Authenticate with GitHub (if using CLI)
   gh auth login
   ```

## Usage

```bash
# Basic usage - runs audit for all frameworks
./github_compliance_audit.sh your-organization-name

# Audit for specific framework
./github_compliance_audit.sh your-organization-name fedramp
./github_compliance_audit.sh your-organization-name soc2
./github_compliance_audit.sh your-organization-name hipaa
./github_compliance_audit.sh your-organization-name iso27001
./github_compliance_audit.sh your-organization-name pci-dss

# Using environment variable for token (recommended - more secure)
export GITHUB_TOKEN=ghp_xxxxxxxxxxxx
./github_compliance_audit.sh your-organization-name [framework]

# Using GitHub CLI authentication
./github_compliance_audit.sh your-organization-name [framework]
```

### Supported Frameworks

- `all` (default) - Generates a combined report for all frameworks
- `fedramp` - Federal Risk and Authorization Management Program
- `nist` - NIST 800-53 and 800-161 controls
- `soc2` - SOC 2 Type II Trust Service Criteria
- `hipaa` - HIPAA Security Rule requirements
- `iso27001` - ISO 27001:2022 Annex A controls
- `pci-dss` - PCI-DSS v4.0 requirements

The script will create an output directory with all collected data and a comprehensive compliance report.

## Manual Evaluation Guide

In addition to the automated audit script, this repository includes a detailed [GitHub FedRAMP and NIST Compliance Evaluation Guide](./github_evaluation_guide.md) for manually assessing GitHub implementations. The guide:

- Provides step-by-step instructions for hands-on evaluation
- Includes both GitHub UI navigation and API commands for verification
- Features detailed checklists for each security control
- Covers all aspects of the NIST 800-53 and 800-161 requirements
- Includes specific guidance for supply chain security (NIST 800-161r1-upd1)
- Maps controls to Executive Order 14028 requirements
- Addresses Zero Trust Architecture principles

Use the evaluation guide alongside the automated script for a comprehensive compliance assessment.

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

## NIST Control Families

### NIST 800-53 Control Families

The tool evaluates controls across these NIST 800-53 families:

- **AC**: Access Control
- **IA**: Identification and Authentication
- **AU**: Audit and Accountability
- **CM**: Configuration Management
- **RA**: Risk Assessment
- **SI**: System and Information Integrity
- **SC**: System and Communications Protection
- **SA**: System and Services Acquisition

### NIST 800-161 Supply Chain Risk Management Controls

The tool also evaluates the following supply chain risk management controls from NIST 800-161 Rev. 1 Update 1:

- **SR-2**: Supply Chain Risk Management Plan
- **SR-3**: Supply Chain Controls and Processes
- **SR-4**: Provenance
- **SR-5**: Acquisition Strategies
- **SR-8**: Notification Agreements
- **SR-9**: Tamper Protection
- **SR-10**: Inspection of Systems or Components
- **SR-11**: Component Authenticity
- **SR-13**: Supply Chain Incident Management

## FedRAMP Alignment

This tool is specifically designed to help organizations prepare for FedRAMP authorization by assessing GitHub security controls against FedRAMP requirements, which are based on NIST 800-53 controls. It also addresses Executive Order 14028 on Improving the Nation's Cybersecurity requirements through the NIST 800-161 supply chain controls.

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

### GitHub Security Features
- [Organization security settings](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization)
- [Branch protection rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
- [Security manager role](https://docs.github.com/en/organizations/managing-peoples-access-to-your-organization-with-roles/managing-security-managers-in-your-organization)
- [GitHub Advanced Security](https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security)
- [Audit log documentation](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization)

### Supply Chain Security Resources
- [Dependency review](https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/about-dependency-review)
- [Dependency graph](https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/about-the-dependency-graph)
- [SBOM generation](https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/exporting-a-software-bill-of-materials-for-your-repository)
- [SLSA Framework](https://slsa.dev/)
- [Sigstore](https://www.sigstore.dev/)
- [NIST SP 800-161 Rev. 1 Update 1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-161r1-upd1.pdf)
- [Executive Order 14028](https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/)

## Disclaimer

This tool is provided as-is and is not officially endorsed by GitHub or any compliance body. While it helps assess compliance with FedRAMP and NIST 800-53 requirements, it should be used as part of a comprehensive compliance program, not as the sole means of achieving compliance.

Organizations should consult with qualified security professionals and compliance experts when pursuing FedRAMP authorization or implementing NIST 800-53 controls.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details. If you use this tool, please provide attribution to the original author.