#!/bin/bash
# GitHub Organization Multi-Framework Compliance Audit
# Supports FedRAMP, NIST, SOC2, HIPAA, ISO 27001, PCI-DSS
# Features parallel processing, robust error handling, and comprehensive security checks
#
# Repository collection runs inside GNU parallel (or xargs), which invokes the
# exported functions from a fresh shell. ShellCheck cannot see those call sites.
# shellcheck disable=SC2317

set -euo pipefail

AUDIT_TOOL_VERSION="2.0.0"

# Configuration
ORG_NAME="${1:-}"
FRAMEWORK="${2:-all}"  # Default to all frameworks
MAX_PARALLEL_JOBS="${MAX_PARALLEL_JOBS:-10}"  # Number of parallel repository scans
RETRY_ATTEMPTS="${RETRY_ATTEMPTS:-3}"
RETRY_DELAY="${RETRY_DELAY:-5}"
GITHUB_API_URL="${GITHUB_API_URL:-https://api.github.com}"
# Archived repositories are read-only and cannot receive branch protection, so
# including them understates coverage. Set to "true" to score them anyway.
INCLUDE_ARCHIVED="${INCLUDE_ARCHIVED:-false}"

# Supported frameworks
SUPPORTED_FRAMEWORKS=("fedramp" "nist" "soc2" "hipaa" "iso27001" "pci-dss" "all")

usage() {
  cat <<USAGE
Usage: $0 <organization-name> [framework]
  - organization-name: Your GitHub organization name (required)
  - framework: Compliance framework (optional, default: all)
    Supported: ${SUPPORTED_FRAMEWORKS[*]}

Environment variables:
  GITHUB_TOKEN        Token to authenticate with (falls back to 'gh auth token')
  GITHUB_API_URL      API base URL (default: https://api.github.com)
  MAX_PARALLEL_JOBS   Concurrent repository scans (default: 10)
  INCLUDE_ARCHIVED    Score archived repositories too (default: false)
  OUTPUT_DIR          Where to write evidence (default: timestamped directory)
  AUDIT_RUNNER        Force "parallel" or "xargs" for concurrency

Exit codes: 0 success, 1 usage or access error, 2 Low compliance level.

Example: GITHUB_TOKEN=ghp_xxxx $0 my-org soc2
USAGE
}

case "$ORG_NAME" in
  -h|--help)
    usage
    exit 0
    ;;
esac

# Display usage if organization name is missing
if [ -z "$ORG_NAME" ]; then
  usage >&2
  exit 1
fi

# Validate framework
framework_valid=false
for supported in "${SUPPORTED_FRAMEWORKS[@]}"; do
  if [ "$FRAMEWORK" = "$supported" ]; then
    framework_valid=true
    break
  fi
done
if [ "$framework_valid" != "true" ]; then
  echo "Error: Invalid framework '$FRAMEWORK'"
  echo "Supported frameworks: ${SUPPORTED_FRAMEWORKS[*]}"
  exit 1
fi

# Create output directory
AUDIT_STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
OUTPUT_DIR="${OUTPUT_DIR:-github_compliance_audit_${FRAMEWORK}_$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$OUTPUT_DIR"
echo "Starting $FRAMEWORK compliance audit for organization: $ORG_NAME"
echo "Results will be saved to: $OUTPUT_DIR"

# Progress is tracked by appending one line per finished repository. Appends of
# short lines are atomic, so parallel workers cannot corrupt the count.
: > "$OUTPUT_DIR/.progress"
echo "0" > "$OUTPUT_DIR/.total"

# Check for required tools
for tool in jq curl; do
  if ! command -v "$tool" &> /dev/null; then
    echo "Error: $tool is required but not installed." >&2
    exit 1
  fi
done

# GNU parallel is preferred, but xargs -P is a fine substitute and is always
# present, so a missing parallel installation is not a hard failure.
RUNNER="${AUDIT_RUNNER:-}"
if [ -z "$RUNNER" ]; then
  if command -v parallel &> /dev/null; then
    RUNNER="parallel"
  else
    RUNNER="xargs"
    echo "Note: GNU parallel not found, using 'xargs -P' instead."
    echo "      For nicer output install it: brew install parallel / apt install parallel"
  fi
fi

# Setup authentication
if [ -n "${GITHUB_TOKEN:-}" ]; then
  echo "Using GitHub token from environment variable"
  AUTH_METHOD="token"
else
  # Check for GitHub CLI authentication
  if ! command -v gh &> /dev/null; then
    echo "Error: Either set GITHUB_TOKEN environment variable or install GitHub CLI" >&2
    exit 1
  fi

  if ! gh auth status &> /dev/null; then
    echo "Error: Please authenticate with GitHub CLI first using: gh auth login" >&2
    exit 1
  fi

  echo "Using GitHub CLI authentication"
  AUTH_METHOD="cli"
  # Export token for parallel jobs
  GITHUB_TOKEN="$(gh auth token)"
  export GITHUB_TOKEN
fi

# The token is deliberately kept in the environment rather than passed as an
# argument: process arguments are world-readable via ps(1).
export AUTH_METHOD
export GITHUB_API_URL
export RETRY_ATTEMPTS
export RETRY_DELAY

# Utility Functions

# Failed calls are recorded as a JSON object carrying the HTTP status rather
# than a bare {"error": ...}. Auditors need to tell "the control is absent"
# (404) apart from "we were not permitted to look" (403), and a repository
# whose description happens to contain the word error must not be mistaken
# for a failed call.
api_error_payload() {
  local http_code="$1"
  local reason="$2"
  jq -n --arg reason "$reason" --argjson code "$http_code" \
    '{_audit_error: $reason, _http_code: $code}'
}

# True when the file holds a real API response rather than an error marker.
api_ok() {
  local file="$1"
  [ -s "$file" ] || return 1
  jq -e 'if type == "object" then (has("_audit_error") | not) else true end' \
    "$file" > /dev/null 2>&1
}

# HTTP status recorded for a failed call ("200" when the call succeeded).
api_status() {
  local file="$1"
  if api_ok "$file"; then
    echo "200"
  else
    jq -r '._http_code // "unknown"' "$file" 2>/dev/null || echo "unknown"
  fi
}

# Enhanced API call with retry logic
api_call_with_retry() {
  local endpoint="$1"
  local output_file="$2"
  local attempt=1
  local response http_code content header_file wait_seconds reset_at

  # One header scratch file per process; parallel workers each have their own PID.
  header_file="${TMPDIR:-/tmp}/gh_compliance_audit_headers_$$"

  while [ "$attempt" -le "$RETRY_ATTEMPTS" ]; do
    response=$(curl -sS -D "$header_file" -w $'\n%{http_code}' \
      -H "Authorization: Bearer ${GITHUB_TOKEN}" \
      -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      "${GITHUB_API_URL}/${endpoint}" 2>/dev/null) || response=$'\n000'

    http_code="${response##*$'\n'}"
    content="${response%$'\n'*}"

    case "$http_code" in
      200|201)
        printf '%s\n' "$content" > "$output_file"
        return 0
        ;;
      404)
        api_error_payload 404 "Not found" > "$output_file"
        return 0
        ;;
      403|429)
        # Distinguish rate limiting from a genuine permission problem: retrying
        # a 403 caused by missing scopes just burns quota.
        if grep -qi '^x-ratelimit-remaining: 0' "$header_file" ||
           printf '%s' "$content" | grep -qi 'rate limit'; then
          wait_seconds=$(sed -n 's/^[Rr]etry-[Aa]fter: *\([0-9]*\).*/\1/p' "$header_file" | head -n1)
          if [ -z "$wait_seconds" ]; then
            reset_at=$(sed -n 's/^[Xx]-[Rr]ate[Ll]imit-[Rr]eset: *\([0-9]*\).*/\1/p' "$header_file" | head -n1)
            if [ -n "$reset_at" ]; then
              wait_seconds=$(( reset_at - $(date +%s) + 1 ))
            fi
          fi
          if [ -z "$wait_seconds" ] || [ "$wait_seconds" -lt 1 ]; then
            wait_seconds=60
          fi
          if [ "$wait_seconds" -gt 900 ]; then
            wait_seconds=900
          fi
          echo "Rate limit hit on $endpoint, waiting ${wait_seconds}s..." >&2
          sleep "$wait_seconds"
        else
          api_error_payload "$http_code" "Forbidden (check token scopes and org permissions)" \
            > "$output_file"
          return 0
        fi
        ;;
      *)
        echo "API call failed (attempt $attempt/$RETRY_ATTEMPTS): HTTP $http_code $endpoint" >&2
        if [ "$attempt" -lt "$RETRY_ATTEMPTS" ]; then
          sleep "$RETRY_DELAY"
        fi
        ;;
    esac

    attempt=$(( attempt + 1 ))
  done

  api_error_payload "${http_code:-000}" "Failed after $RETRY_ATTEMPTS attempts" > "$output_file"
  return 1
}

# Paginated API calls with retry
api_call_paginated() {
  local endpoint="$1"
  local output_file="$2"
  local all_data="[]"
  local page=1
  local per_page=100
  local separator="?"
  local page_file page_count

  case "$endpoint" in
    *\?*) separator="&" ;;
  esac

  while true; do
    page_file="${output_file}.page${page}"

    if ! api_call_with_retry "${endpoint}${separator}per_page=${per_page}&page=${page}" "$page_file"; then
      rm -f "$page_file"
      break
    fi

    # A non-array response means the endpoint is unavailable to us (404/403) or
    # returns an object; either way there is nothing to paginate.
    if ! page_count=$(jq -e 'if type == "array" then length else empty end' "$page_file" 2>/dev/null); then
      if [ "$all_data" = "[]" ] && ! api_ok "$page_file"; then
        cp "$page_file" "$output_file"
        rm -f "$page_file"
        return 0
      fi
      rm -f "$page_file"
      break
    fi

    if [ "$page_count" -gt 0 ]; then
      all_data=$(jq -n --slurpfile new "$page_file" --argjson acc "$all_data" '$acc + $new[0]')
    fi
    rm -f "$page_file"

    if [ "$page_count" -lt "$per_page" ]; then
      break
    fi

    page=$(( page + 1 ))
  done

  printf '%s\n' "$all_data" > "$output_file"
}

# Progress tracking
update_progress() {
  local total current percentage
  echo "." >> "$OUTPUT_DIR/.progress"
  total=$(cat "$OUTPUT_DIR/.total")
  current=$(wc -l < "$OUTPUT_DIR/.progress" | tr -d ' ')

  if [ "$total" -gt 0 ]; then
    percentage=$(( current * 100 / total ))
    printf '\rProgress: %s/%s (%s%%)' "$current" "$total" "$percentage"
  fi
}

# GNU coreutils uses --decode, BSD/macOS uses -D. Probe once, not per call, so
# the flag choice cannot consume the stdin we are trying to decode.
if printf 'dGVzdA==' | base64 --decode > /dev/null 2>&1; then
  B64_DECODE_FLAG="--decode"
else
  B64_DECODE_FLAG="-D"
fi
export B64_DECODE_FLAG

b64_decode() {
  base64 "$B64_DECODE_FLAG" 2>/dev/null || true
}

# Summarise the security posture of one workflow file. Reads YAML on stdin.
# GitHub's own hardening guidance (and NIST SR-11 / SLSA) asks for actions
# pinned to a full commit SHA and for explicit least-privilege permissions.
analyze_workflow_yaml() {
  awk '
    BEGIN { total = 0; pinned = 0; permissions = 0; sbom = 0; signing = 0; attestation = 0 }
    # Strip comments so a commented-out "uses:" is not counted.
    { line = $0; sub(/#.*/, "", line) }
    line ~ /(^|[[:space:]-])uses:[[:space:]]*[^[:space:]]/ {
      ref = line
      sub(/.*uses:[[:space:]]*/, "", ref)
      gsub(/["'"'"']/, "", ref)
      # Local (./path) and container (docker://) references are not pinnable
      # in the same way, so they are excluded from the denominator.
      if (ref !~ /^\.\// && ref !~ /^docker:\/\//) {
        total++
        if (ref ~ /@[0-9a-fA-F]{40}$/) { pinned++ }
      }
    }
    line ~ /^[[:space:]]*permissions:/ { permissions = 1 }
    tolower(line) ~ /(sbom|cyclonedx|spdx|syft|anchore\/sbom-action)/ { sbom = 1 }
    tolower(line) ~ /(cosign|sigstore|sign-blob|gpg --detach-sign)/ { signing = 1 }
    tolower(line) ~ /(attest-build-provenance|attest-sbom|slsa-framework|provenance)/ { attestation = 1 }
    END {
      printf "{\"actions_total\":%d,\"actions_pinned_to_sha\":%d,\"explicit_permissions\":%s,\"sbom\":%s,\"signing\":%s,\"attestation\":%s}\n",
        total, pinned,
        (permissions ? "true" : "false"),
        (sbom ? "true" : "false"),
        (signing ? "true" : "false"),
        (attestation ? "true" : "false")
    }
  '
}

# Reduce the raw evidence for one repository to the facts the frameworks care
# about. Keeping scoring out of the collection path means the report can be
# regenerated from evidence without re-hitting the API.
summarize_repository() {
  local repo_dir="$1"
  local repo_name="$2"
  local now_epoch="$3"

  local protection_file rulesets_file
  protection_file="$repo_dir/branches/default_protection.json"
  rulesets_file="$repo_dir/rulesets.json"

  local protection='{"present":false}'
  if api_ok "$protection_file"; then
    protection=$(jq '{
      present: true,
      required_reviews: (.required_pull_request_reviews.required_approving_review_count // 0),
      dismiss_stale_reviews: (.required_pull_request_reviews.dismiss_stale_reviews // false),
      require_code_owner_reviews: (.required_pull_request_reviews.require_code_owner_reviews // false),
      required_status_checks: (.required_status_checks != null),
      strict_status_checks: (.required_status_checks.strict // false),
      enforce_admins: (.enforce_admins.enabled // false),
      required_signatures: (.required_signatures.enabled // false),
      linear_history: (.required_linear_history.enabled // false),
      allow_force_pushes: (.allow_force_pushes.enabled // false),
      allow_deletions: (.allow_deletions.enabled // false),
      required_conversation_resolution: (.required_conversation_resolution.enabled // false)
    }' "$protection_file")
  fi

  # Rulesets are the modern replacement for branch protection. A repository
  # governed only by an active ruleset is protected, and counting it as
  # unprotected is the most common false negative in GitHub compliance tooling.
  local rulesets='{"total":0,"active_branch_rulesets":0}'
  if api_ok "$rulesets_file"; then
    rulesets=$(jq '{
      total: length,
      active_branch_rulesets: ([.[] | select(.enforcement == "active" and .target == "branch")] | length)
    }' "$rulesets_file")
  fi

  local alerts
  alerts=$(jq -n \
    --argjson dependabot "$(summarize_alerts "$repo_dir/dependabot_alerts.json" dependabot "$now_epoch")" \
    --argjson code_scanning "$(summarize_alerts "$repo_dir/code_scanning_alerts.json" code_scanning "$now_epoch")" \
    --argjson secret_scanning "$(summarize_alerts "$repo_dir/secret_scanning_alerts.json" secret_scanning "$now_epoch")" \
    '{dependabot: $dependabot, code_scanning: $code_scanning, secret_scanning: $secret_scanning}')

  local supply_chain='{"workflows":0,"actions_total":0,"actions_pinned_to_sha":0,"workflows_with_permissions":0,"sbom":false,"signing":false,"attestation":false}'
  if [ -f "$repo_dir/supply_chain/workflow_findings.json" ]; then
    supply_chain=$(jq -s '{
      workflows: length,
      actions_total: (map(.actions_total) | add // 0),
      actions_pinned_to_sha: (map(.actions_pinned_to_sha) | add // 0),
      workflows_with_permissions: ([.[] | select(.explicit_permissions)] | length),
      sbom: (any(.[]; .sbom)),
      signing: (any(.[]; .signing)),
      attestation: (any(.[]; .attestation))
    }' "$repo_dir/supply_chain/workflow_findings.json")
  fi

  # Release assets are the other place provenance shows up: .sig/.intoto.jsonl
  # files next to a binary are evidence of signing even without a named workflow.
  local signed_release=false
  if api_ok "$repo_dir/supply_chain/release_assets.json"; then
    if jq -e 'any(.[]?.name; test("\\.(sig|asc|pem|sigstore|intoto\\.jsonl)$"))' \
      "$repo_dir/supply_chain/release_assets.json" > /dev/null 2>&1; then
      signed_release=true
    fi
  fi
  local sbom_release=false
  if api_ok "$repo_dir/supply_chain/release_assets.json"; then
    if jq -e 'any(.[]?.name; test("(sbom|spdx|cyclonedx)"; "i"))' \
      "$repo_dir/supply_chain/release_assets.json" > /dev/null 2>&1; then
      sbom_release=true
    fi
  fi

  local security_analysis='{}'
  if api_ok "$repo_dir/info.json"; then
    security_analysis=$(jq '{
      advanced_security: (.security_and_analysis.advanced_security.status // "unknown"),
      secret_scanning: (.security_and_analysis.secret_scanning.status // "unknown"),
      secret_scanning_push_protection: (.security_and_analysis.secret_scanning_push_protection.status // "unknown"),
      dependabot_security_updates: (.security_and_analysis.dependabot_security_updates.status // "unknown")
    }' "$repo_dir/info.json")
  fi

  local codeowners=false
  api_ok "$repo_dir/codeowners.json" && codeowners=true
  local security_policy=false
  api_ok "$repo_dir/security_policy.json" && security_policy=true
  local dependabot_alerts_enabled=false
  api_ok "$repo_dir/dependabot_alerts_enabled.json" && dependabot_alerts_enabled=true

  jq -n \
    --arg name "$repo_name" \
    --argjson info "$(api_ok "$repo_dir/info.json" && cat "$repo_dir/info.json" || echo '{}')" \
    --argjson protection "$protection" \
    --argjson rulesets "$rulesets" \
    --argjson alerts "$alerts" \
    --argjson supply_chain "$supply_chain" \
    --argjson security_analysis "$security_analysis" \
    --argjson codeowners "$codeowners" \
    --argjson security_policy "$security_policy" \
    --argjson dependabot_alerts_enabled "$dependabot_alerts_enabled" \
    --argjson signed_release "$signed_release" \
    --argjson sbom_release "$sbom_release" \
    '{
      name: $name,
      archived: ($info.archived // false),
      fork: ($info.fork // false),
      private: ($info.private // true),
      empty: (($info.size // 0) == 0 and ($info.default_branch // "") == ""),
      default_branch: ($info.default_branch // null),
      pushed_at: ($info.pushed_at // null),
      web_commit_signoff_required: ($info.web_commit_signoff_required // false),
      branch_protection: $protection,
      rulesets: $rulesets,
      protected: ($protection.present or ($rulesets.active_branch_rulesets > 0)),
      security_analysis: $security_analysis,
      dependabot_alerts_enabled: $dependabot_alerts_enabled,
      codeowners: $codeowners,
      security_policy: $security_policy,
      alerts: $alerts,
      supply_chain: ($supply_chain + {
        signed_release_assets: $signed_release,
        sbom_release_assets: $sbom_release,
        sbom: ($supply_chain.sbom or $sbom_release),
        signing: ($supply_chain.signing or $signed_release)
      })
    }'
}

# Count open alerts by severity and flag anything past a remediation deadline.
# FedRAMP and PCI-DSS both score on how long a finding has been open, not just
# on how many exist, so age is captured here rather than thrown away.
summarize_alerts() {
  local file="$1"
  local kind="$2"
  local now_epoch="$3"

  if ! api_ok "$file"; then
    jq -n --arg status "$(api_status "$file")" \
      '{available: false, http_status: $status, open: 0, critical: 0, high: 0, medium: 0, low: 0, past_due: 0, oldest_open_days: null}'
    return
  fi

  jq --arg kind "$kind" --argjson now "$now_epoch" '
    def severity:
      if $kind == "dependabot" then (.security_advisory.severity // .security_vulnerability.severity // "unknown")
      elif $kind == "code_scanning" then (.rule.security_severity_level // .rule.severity // "unknown")
      else "high"  # every leaked secret is treated as high severity
      end;
    def is_open: ((.state // "open") | ascii_downcase) == "open";
    def age_days: (((.created_at // empty) | fromdateiso8601 | ($now - .) / 86400) | floor);
    # Remediation windows: FedRAMP RA-5 / PCI 6.3.1 style.
    def deadline: if severity == "critical" then 15
                  elif severity == "high" then 30
                  elif severity == "medium" then 90
                  else 180 end;
    [.[] | select(is_open)] as $open
    | {
        available: true,
        http_status: "200",
        open: ($open | length),
        critical: ([$open[] | select(severity == "critical")] | length),
        high: ([$open[] | select(severity == "high")] | length),
        medium: ([$open[] | select(severity == "medium")] | length),
        low: ([$open[] | select(severity == "low" or severity == "note" or severity == "warning")] | length),
        past_due: ([$open[] | select((age_days // 0) > deadline)] | length),
        oldest_open_days: ([$open[] | age_days] | max // null)
      }
  ' "$file"
}

# Function to process a single repository (for parallel execution)
process_repository() {
  local repo_name="$1"
  local org_name="$2"
  local output_dir="$3"

  local repo_dir="$output_dir/repositories/$repo_name"
  mkdir -p "$repo_dir/branches" "$repo_dir/workflows" "$repo_dir/supply_chain/workflow_analysis"

  # Repository details. security_and_analysis on this payload is the source of
  # truth for per-repo GHAS state, so it is fetched once and reused rather than
  # requested twice as it used to be.
  api_call_with_retry "repos/$org_name/$repo_name" "$repo_dir/info.json"

  local default_branch
  default_branch=$(jq -r '.default_branch // empty' "$repo_dir/info.json" 2>/dev/null || echo "")

  api_call_with_retry "repos/$org_name/$repo_name/branches" "$repo_dir/branches/all_branches.json"

  # An empty repository has no default branch and cannot be protected; asking
  # for protection would only produce a misleading 404.
  if [ -n "$default_branch" ]; then
    api_call_with_retry "repos/$org_name/$repo_name/branches/$default_branch/protection" \
      "$repo_dir/branches/default_protection.json"
  else
    api_error_payload 0 "Repository has no default branch (empty repository)" \
      > "$repo_dir/branches/default_protection.json"
  fi

  api_call_with_retry "repos/$org_name/$repo_name/rulesets" "$repo_dir/rulesets.json"

  # Only open alerts count against a control. Asking the API to filter also
  # avoids paging through years of already-remediated findings.
  api_call_paginated "repos/$org_name/$repo_name/dependabot/alerts?state=open" \
    "$repo_dir/dependabot_alerts.json"
  api_call_paginated "repos/$org_name/$repo_name/code-scanning/alerts?state=open" \
    "$repo_dir/code_scanning_alerts.json"
  api_call_paginated "repos/$org_name/$repo_name/secret-scanning/alerts?state=open" \
    "$repo_dir/secret_scanning_alerts.json"

  # Push protection bypass requests (GHAS + secret scanning).
  api_call_paginated "repos/$org_name/$repo_name/bypass-requests/secret-scanning" \
    "$repo_dir/push_protection_bypasses.json"

  api_call_with_retry "repos/$org_name/$repo_name/actions/workflows" "$repo_dir/workflows/workflows.json"
  api_call_with_retry "repos/$org_name/$repo_name/actions/permissions" "$repo_dir/workflows/actions_permissions.json"
  api_call_with_retry "repos/$org_name/$repo_name/actions/permissions/workflow" \
    "$repo_dir/workflows/default_workflow_permissions.json"

  # Dependabot alert enablement (204 when on, 404 when off).
  api_call_with_retry "repos/$org_name/$repo_name/vulnerability-alerts" \
    "$repo_dir/dependabot_alerts_enabled.json"

  api_call_with_retry "repos/$org_name/$repo_name/contents/SECURITY.md" "$repo_dir/security_policy.json"

  for path in ".github/CODEOWNERS" "CODEOWNERS" "docs/CODEOWNERS"; do
    api_call_with_retry "repos/$org_name/$repo_name/contents/$path" "$repo_dir/codeowners.json" || true
    if api_ok "$repo_dir/codeowners.json"; then
      break
    fi
  done

  # Workflow contents drive the supply-chain findings. Archived repositories
  # cannot change, so their workflows are still worth reading, but the number
  # of files per repository is capped to keep API spend predictable.
  : > "$repo_dir/supply_chain/workflow_findings.json"
  if api_ok "$repo_dir/workflows/workflows.json"; then
    local workflow_path workflow_file findings
    while IFS= read -r workflow_path; do
      [ -n "$workflow_path" ] || continue
      workflow_file="$repo_dir/supply_chain/workflow_analysis/$(basename "$workflow_path").json"
      api_call_with_retry "repos/$org_name/$repo_name/contents/$workflow_path" "$workflow_file" || continue
      api_ok "$workflow_file" || continue
      findings=$(jq -r '.content // ""' "$workflow_file" | tr -d '\n' | b64_decode | analyze_workflow_yaml)
      jq -c --arg path "$workflow_path" '. + {path: $path}' <<< "$findings" \
        >> "$repo_dir/supply_chain/workflow_findings.json"
    done < <(jq -r --argjson cap "${MAX_WORKFLOWS_PER_REPO:-25}" \
      '[.workflows[]? | select(.state == "active") | .path] | .[:$cap] | .[]' \
      "$repo_dir/workflows/workflows.json" 2>/dev/null)
  fi

  api_call_with_retry "repos/$org_name/$repo_name/releases/latest" "$repo_dir/supply_chain/latest_release.json"
  if api_ok "$repo_dir/supply_chain/latest_release.json"; then
    local release_id
    release_id=$(jq -r '.id // empty' "$repo_dir/supply_chain/latest_release.json")
    if [ -n "$release_id" ]; then
      api_call_paginated "repos/$org_name/$repo_name/releases/$release_id/assets" \
        "$repo_dir/supply_chain/release_assets.json"
    fi
  fi

  # AUDIT_NOW_EPOCH pins the clock so an evidence set can be re-scored later and
  # produce the same finding ages it produced on the day of the run.
  summarize_repository "$repo_dir" "$repo_name" "${AUDIT_NOW_EPOCH:-$(date +%s)}" \
    > "$repo_dir/analysis.json"

  update_progress
}

# Export functions for parallel execution
export -f process_repository
export -f summarize_repository
export -f summarize_alerts
export -f analyze_workflow_yaml
export -f api_call_with_retry
export -f api_call_paginated
export -f api_error_payload
export -f api_ok
export -f api_status
export -f b64_decode
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

# Report rendering helpers

# ✓ when the measurement clears the bar, ⚠ when it is within 20% of it,
# ✗ otherwise.
status_for() {
  local value="$1" required="$2"
  if [ "$value" -ge "$required" ]; then
    echo "✓"
  elif [ "$value" -ge $(( required * 8 / 10 )) ]; then
    echo "⚠"
  else
    echo "✗"
  fi
}

# ✓/✗ for a boolean control.
bool_status() {
  case "$1" in
    true|Yes|yes|enabled) echo "✓" ;;
    *) echo "✗" ;;
  esac
}

# "Not assessed" is a distinct outcome from "failed". A control the token could
# not see must never be reported as either a pass or a finding.
evidence_status() {
  local available="$1" pass="$2"
  if [ "$available" != "true" ]; then
    echo "?"
  elif [ "$pass" = "true" ]; then
    echo "✓"
  else
    echo "✗"
  fi
}

# Main execution

# 1. Organization Information
echo "Gathering organization information..."
api_call_with_retry "orgs/$ORG_NAME" "$OUTPUT_DIR/organization_info.json"

# Check if organization exists
if ! api_ok "$OUTPUT_DIR/organization_info.json"; then
  echo "Error: Unable to access organization '$ORG_NAME' (HTTP $(api_status "$OUTPUT_DIR/organization_info.json"))." >&2
  echo "       Check the org slug, your token scopes (repo, read:org, admin:org_hook, security_events)," >&2
  echo "       and that the token's SSO authorization covers this organization." >&2
  exit 1
fi

# 2. Organization Security Settings
echo "Gathering organization security settings..."
mkdir -p "$OUTPUT_DIR/org_security"

# The org payload already contains the 2FA and default security settings, so it
# is reused rather than fetched a second time.
cp "$OUTPUT_DIR/organization_info.json" "$OUTPUT_DIR/org_security/org_details.json"

api_call_paginated "orgs/$ORG_NAME/members" "$OUTPUT_DIR/org_security/members.json"
api_call_paginated "orgs/$ORG_NAME/security-managers" "$OUTPUT_DIR/org_security/security_managers.json"
api_call_paginated "orgs/$ORG_NAME/teams" "$OUTPUT_DIR/org_security/teams.json"
api_call_paginated "orgs/$ORG_NAME/hooks" "$OUTPUT_DIR/org_security/webhooks.json"
api_call_paginated "orgs/$ORG_NAME/installations" "$OUTPUT_DIR/org_security/github_apps.json"

# Audit log streaming is Enterprise Cloud only; a 404 here is a real finding
# rather than a tooling error, so the status is preserved for the report.
api_call_with_retry "orgs/$ORG_NAME/audit-log?per_page=10" "$OUTPUT_DIR/org_security/audit_log_sample.json"

# Organization-wide security policy lives in the .github repository.
api_call_with_retry "repos/$ORG_NAME/.github/contents/SECURITY.md" "$OUTPUT_DIR/org_security/security_policy.json"

# 3. Repository Processing
echo "Gathering repository list..."
api_call_paginated "orgs/$ORG_NAME/repos" "$OUTPUT_DIR/repositories.json"

total_repos=$(jq 'length' "$OUTPUT_DIR/repositories.json")
echo "$total_repos" > "$OUTPUT_DIR/.total"
echo "Found $total_repos repositories"

jq -r '.[].name' "$OUTPUT_DIR/repositories.json" > "$OUTPUT_DIR/repo_list.txt"

mkdir -p "$OUTPUT_DIR/repositories"
export OUTPUT_DIR

if [ "$total_repos" -gt 0 ]; then
  echo "Processing repositories ($MAX_PARALLEL_JOBS workers)..."
  if [ "$RUNNER" = "parallel" ]; then
    # --will-cite suppresses the interactive citation notice on first run.
    parallel --will-cite -j "$MAX_PARALLEL_JOBS" \
      process_repository {} "$ORG_NAME" "$OUTPUT_DIR" < "$OUTPUT_DIR/repo_list.txt"
  else
    # shellcheck disable=SC2016  # $1..$3 are for the inner shell, not this one
    xargs -P "$MAX_PARALLEL_JOBS" -I {} \
      bash -c 'process_repository "$1" "$2" "$3"' _ {} "$ORG_NAME" "$OUTPUT_DIR" \
      < "$OUTPUT_DIR/repo_list.txt"
  fi
  echo
fi

# 4. Aggregate evidence into a machine-readable summary
echo "Aggregating findings..."

# One JSON Lines file keeps the aggregation independent of ARG_MAX, which
# matters for organizations with thousands of repositories.
: > "$OUTPUT_DIR/repository_analysis.jsonl"
while IFS= read -r repo_name; do
  analysis="$OUTPUT_DIR/repositories/$repo_name/analysis.json"
  if [ -f "$analysis" ]; then
    jq -c '.' "$analysis" >> "$OUTPUT_DIR/repository_analysis.jsonl"
  fi
done < "$OUTPUT_DIR/repo_list.txt"

org_details="$OUTPUT_DIR/org_security/org_details.json"
security_managers_count=0
if api_ok "$OUTPUT_DIR/org_security/security_managers.json"; then
  # An empty array means the role exists but nobody holds it, which is not the
  # same as the control being satisfied.
  security_managers_count=$(jq 'if type == "array" then length else 0 end' \
    "$OUTPUT_DIR/org_security/security_managers.json")
fi

audit_log_available=false
api_ok "$OUTPUT_DIR/org_security/audit_log_sample.json" && audit_log_available=true
org_security_policy=false
api_ok "$OUTPUT_DIR/org_security/security_policy.json" && org_security_policy=true

# The scoring model is intentionally explicit: every point is attributable to a
# named control so a reviewer can argue with the weighting instead of guessing
# at it. Weights sum to 100; risk score is 100 minus the points earned.
jq -s \
  --slurpfile org "$org_details" \
  --arg org_name "$ORG_NAME" \
  --arg framework "$FRAMEWORK" \
  --arg generated_at "$AUDIT_STARTED_AT" \
  --arg tool_version "$AUDIT_TOOL_VERSION" \
  --argjson security_managers "$security_managers_count" \
  --argjson audit_log_available "$audit_log_available" \
  --argjson org_security_policy "$org_security_policy" \
  --argjson include_archived "$([ "$INCLUDE_ARCHIVED" = "true" ] && echo true || echo false)" '
  def pct($n; $d): if $d == 0 then 0 else (($n * 100 / $d) | floor) end;

  . as $repos
  | ($org[0] // {}) as $o
  # Archived repositories are read-only and empty ones have nothing to protect;
  # scoring them drags coverage down for no achievable remediation.
  | [$repos[] | select(($include_archived or (.archived | not)) and (.empty | not))] as $scored
  | ($scored | length) as $n
  | {
      protected: [$scored[] | select(.protected)] | length,
      strong_review: [$scored[] | select(
          .branch_protection.present and
          (.branch_protection.required_reviews >= 1) and
          .branch_protection.require_code_owner_reviews)] | length,
      rulesets: [$scored[] | select(.rulesets.active_branch_rulesets > 0)] | length,
      code_scanning: [$scored[] | select(.security_analysis.advanced_security == "enabled")] | length,
      secret_scanning: [$scored[] | select(.security_analysis.secret_scanning == "enabled")] | length,
      push_protection: [$scored[] | select(.security_analysis.secret_scanning_push_protection == "enabled")] | length,
      dependabot_updates: [$scored[] | select(.security_analysis.dependabot_security_updates == "enabled")] | length,
      dependabot_alerts: [$scored[] | select(.dependabot_alerts_enabled)] | length,
      codeowners: [$scored[] | select(.codeowners)] | length,
      security_policy: [$scored[] | select(.security_policy)] | length,
      sbom: [$scored[] | select(.supply_chain.sbom)] | length,
      signing: [$scored[] | select(.supply_chain.signing)] | length,
      attestation: [$scored[] | select(.supply_chain.attestation)] | length,
      actions_total: ([$scored[] | .supply_chain.actions_total] | add // 0),
      actions_pinned: ([$scored[] | .supply_chain.actions_pinned_to_sha] | add // 0)
    } as $c
  | {
      dependabot: {
        open: ([$scored[] | .alerts.dependabot.open] | add // 0),
        critical: ([$scored[] | .alerts.dependabot.critical] | add // 0),
        high: ([$scored[] | .alerts.dependabot.high] | add // 0),
        past_due: ([$scored[] | .alerts.dependabot.past_due] | add // 0),
        repos_without_visibility: [$scored[] | select(.alerts.dependabot.available | not)] | length
      },
      code_scanning: {
        open: ([$scored[] | .alerts.code_scanning.open] | add // 0),
        critical: ([$scored[] | .alerts.code_scanning.critical] | add // 0),
        high: ([$scored[] | .alerts.code_scanning.high] | add // 0),
        past_due: ([$scored[] | .alerts.code_scanning.past_due] | add // 0),
        repos_without_visibility: [$scored[] | select(.alerts.code_scanning.available | not)] | length
      },
      secret_scanning: {
        open: ([$scored[] | .alerts.secret_scanning.open] | add // 0),
        past_due: ([$scored[] | .alerts.secret_scanning.past_due] | add // 0),
        repos_without_visibility: [$scored[] | select(.alerts.secret_scanning.available | not)] | length
      },
      # A repository counts as blind if any one of the three feeds is missing:
      # partial visibility is still an incomplete vulnerability picture.
      repositories_without_visibility: [$scored[] | select(
        (.alerts.dependabot.available | not) or
        (.alerts.code_scanning.available | not) or
        (.alerts.secret_scanning.available | not))] | length
    } as $alerts
  | {
      two_factor: (if ($o.two_factor_requirement_enabled // false) then 15 else 0 end),
      branch_protection: ((pct($c.protected; $n) * 20 / 100) | floor),
      review_quality: ((pct($c.strong_review; $n) * 10 / 100) | floor),
      secret_protection: ((pct($c.push_protection; $n) * 15 / 100) | floor),
      code_scanning: ((pct($c.code_scanning; $n) * 10 / 100) | floor),
      dependency_monitoring: ((pct($c.dependabot_alerts; $n) * 5 / 100) | floor),
      # Overdue findings are the only negative-facing term: full marks only when
      # nothing has blown its remediation window.
      remediation_timeliness: (
        ($alerts.dependabot.past_due + $alerts.code_scanning.past_due + $alerts.secret_scanning.past_due) as $overdue
        | if $overdue == 0 then 10 elif $overdue <= 5 then 5 elif $overdue <= 20 then 2 else 0 end),
      ownership: ((pct($c.codeowners; $n) * 5 / 100) | floor),
      action_pinning: ((pct($c.actions_pinned; $c.actions_total) * 5 / 100) | floor),
      provenance: ((pct($c.sbom; $n) * 3 / 100) + (pct($c.signing; $n) * 2 / 100) | floor)
    } as $earned
  | ($earned | to_entries | map(.value) | add) as $points
  | (100 - $points) as $risk_score
  | {
      organization: $org_name,
      framework: $framework,
      generated_at: $generated_at,
      tool_version: $tool_version,
      repositories: {
        total: ($repos | length),
        scored: $n,
        archived: ([$repos[] | select(.archived)] | length),
        empty: ([$repos[] | select(.empty)] | length),
        private: ([$repos[] | select(.private)] | length)
      },
      organization_controls: {
        two_factor_required: ($o.two_factor_requirement_enabled // false),
        security_managers: $security_managers,
        default_repository_permission: ($o.default_repository_permission // "unknown"),
        members_can_create_public_repositories: ($o.members_can_create_public_repositories // null),
        web_commit_signoff_required: ($o.web_commit_signoff_required // false),
        advanced_security_default_for_new_repos: ($o.advanced_security_enabled_for_new_repositories // null),
        secret_scanning_default_for_new_repos: ($o.secret_scanning_enabled_for_new_repositories // null),
        push_protection_default_for_new_repos: ($o.secret_scanning_push_protection_enabled_for_new_repositories // null),
        audit_log_accessible: $audit_log_available,
        security_policy_published: $org_security_policy
      },
      coverage: {
        branch_protection: pct($c.protected; $n),
        rulesets: pct($c.rulesets; $n),
        review_with_code_owners: pct($c.strong_review; $n),
        code_scanning: pct($c.code_scanning; $n),
        secret_scanning: pct($c.secret_scanning; $n),
        push_protection: pct($c.push_protection; $n),
        dependabot_alerts: pct($c.dependabot_alerts; $n),
        dependabot_security_updates: pct($c.dependabot_updates; $n),
        codeowners: pct($c.codeowners; $n),
        security_policy: pct($c.security_policy; $n),
        sbom: pct($c.sbom; $n),
        signing: pct($c.signing; $n),
        attestation: pct($c.attestation; $n),
        actions_pinned_to_sha: pct($c.actions_pinned; $c.actions_total)
      },
      counts: $c,
      alerts: $alerts,
      score: {
        risk_score: $risk_score,
        points_earned: $points,
        compliance_level: (if $risk_score <= 20 then "High" elif $risk_score <= 50 then "Medium" else "Low" end),
        breakdown: $earned
      }
    }
' "$OUTPUT_DIR/repository_analysis.jsonl" > "$OUTPUT_DIR/summary.json"

# Pull the values the report templates use back out of the summary, so the
# markdown and the JSON can never disagree.
read_summary() { jq -r "$1" "$OUTPUT_DIR/summary.json"; }

total_repos=$(read_summary '.repositories.total')
scored_repos=$(read_summary '.repositories.scored')
archived_repos=$(read_summary '.repositories.archived')
two_factor_required=$(read_summary '.organization_controls.two_factor_required')
security_managers_count=$(read_summary '.organization_controls.security_managers')
has_security_managers=$([ "$security_managers_count" -gt 0 ] && echo "Yes" || echo "No")
audit_log_available=$(read_summary '.organization_controls.audit_log_accessible')
org_security_policy=$(read_summary '.organization_controls.security_policy_published')

protected_percentage=$(read_summary '.coverage.branch_protection')
rulesets_percentage=$(read_summary '.coverage.rulesets')
review_percentage=$(read_summary '.coverage.review_with_code_owners')
ghas_percentage=$(read_summary '.coverage.code_scanning')
secret_scanning_percentage=$(read_summary '.coverage.secret_scanning')
push_protection_percentage=$(read_summary '.coverage.push_protection')
codeowners_percentage=$(read_summary '.coverage.codeowners')
sbom_percentage=$(read_summary '.coverage.sbom')
signing_percentage=$(read_summary '.coverage.signing')
attestation_percentage=$(read_summary '.coverage.attestation')
pinning_percentage=$(read_summary '.coverage.actions_pinned_to_sha')

total_dependabot_alerts=$(read_summary '.alerts.dependabot.open')
dependabot_critical=$(read_summary '.alerts.dependabot.critical')
dependabot_high=$(read_summary '.alerts.dependabot.high')
total_code_scanning_alerts=$(read_summary '.alerts.code_scanning.open')
code_scanning_critical=$(read_summary '.alerts.code_scanning.critical')
code_scanning_high=$(read_summary '.alerts.code_scanning.high')
total_secret_scanning_alerts=$(read_summary '.alerts.secret_scanning.open')
past_due_alerts=$(read_summary '.alerts.dependabot.past_due + .alerts.code_scanning.past_due + .alerts.secret_scanning.past_due')
alerts_not_visible=$(read_summary '.alerts.repositories_without_visibility')

risk_score=$(read_summary '.score.risk_score')
compliance_level=$(read_summary '.score.compliance_level')

if [ "$total_repos" -eq 0 ]; then
  echo "Warning: No repositories found for organization $ORG_NAME"
fi

# 5. Generate the compliance report
echo "Generating $FRAMEWORK compliance report..."

# Framework-specific report generation functions

# Every report opens with the same provenance block. Keeping it in one place
# means the scope caveats cannot drift between frameworks.
report_header() {
  local title="$1"

  cat > "$REPORT_FILE" << EOF
# $title for $ORG_NAME

**Generated**: $AUDIT_STARTED_AT (UTC) by github_compliance_audit.sh v$AUDIT_TOOL_VERSION

## Executive Summary

| | |
|---|---|
| Organization | $ORG_NAME |
| Repositories discovered | $total_repos |
| Repositories scored | $scored_repos (archived: $archived_repos, excluded unless \`INCLUDE_ARCHIVED=true\`) |
| Risk score | **$risk_score/100** (lower is better) |
| Compliance level | **$compliance_level** |

### Scope and evidence quality

- Coverage percentages are calculated over the $scored_repos scored repositories.
- \`?\` marks a control that could not be assessed with this token rather than one that failed.
EOF

  if [ "$alerts_not_visible" -gt 0 ]; then
    cat >> "$REPORT_FILE" << EOF
- **Repositories that returned no alert data: $alerts_not_visible.** Dependabot, code scanning,
  or secret scanning is disabled there, or the token lacks \`security_events\`. Treat their
  vulnerability posture as unknown, not clean.
EOF
  fi

  if [ "$audit_log_available" != "true" ]; then
    cat >> "$REPORT_FILE" << EOF
- **The organization audit log was not readable.** It requires GitHub Enterprise Cloud plus
  an owner-scoped token, so audit trail controls below are reported as not assessed.
EOF
  fi

  echo >> "$REPORT_FILE"
}

# Generate SOC2 report
generate_soc2_report() {
  report_header "GitHub SOC 2 Type II Compliance Report"

  cat >> "$REPORT_FILE" << EOF
### SOC 2 Trust Service Criteria (TSC) Assessment

#### Security (Common Criteria)

| Criteria | Description | Status | Evidence |
|----------|-------------|--------|----------|
| CC6.1 | Logical and Physical Access Controls | $(status_for "$protected_percentage" 90) | Branch protection or ruleset: $protected_percentage% |
| CC6.2 | Prior to Issuing System Credentials | $(bool_status "$has_security_managers") | Security managers assigned: $security_managers_count |
| CC6.3 | Role-Based Access Control | $(status_for "$codeowners_percentage" 90) | CODEOWNERS: $codeowners_percentage% |
| CC6.6 | Logical Access Security Measures | $(status_for "$ghas_percentage" 90) | Code scanning coverage: $ghas_percentage% |
| CC6.7 | System User Authentication | $(bool_status "$two_factor_required") | Organization 2FA requirement: $two_factor_required |
| CC6.8 | Unauthorised Software Prevention | $(status_for "$pinning_percentage" 90) | Actions pinned to a commit SHA: $pinning_percentage% |

#### System Operations

| Criteria | Description | Status | Evidence |
|----------|-------------|--------|----------|
| CC7.1 | Detection and Monitoring | $(status_for "$secret_scanning_percentage" 90) | Secret scanning coverage: $secret_scanning_percentage%, $total_secret_scanning_alerts open alerts |
| CC7.2 | System Monitoring | $(status_for "$ghas_percentage" 90) | Code scanning coverage: $ghas_percentage% |
| CC7.3 | Evaluating Security Events | $(evidence_status "$audit_log_available" "$audit_log_available") | Audit log readable: $audit_log_available |
| CC7.4 | Responding to Security Incidents | $(bool_status "$org_security_policy") | Organization SECURITY.md published: $org_security_policy |
| CC8.1 | Change Management | $(status_for "$review_percentage" 90) | Required review with code owners: $review_percentage% |

### Compliance Gaps

EOF

  # Add SOC2-specific gaps
  [ "$two_factor_required" != "true" ] && echo "- **CC6.7**: Enable mandatory 2FA for all users" >> "$REPORT_FILE"
  [ "$protected_percentage" -lt 90 ] && echo "- **CC6.1**: Increase branch protection coverage to 90%+ (currently $protected_percentage%)" >> "$REPORT_FILE"
  [ "$codeowners_percentage" -lt 90 ] && echo "- **CC6.3**: Implement CODEOWNERS in 90%+ of repositories (currently $codeowners_percentage%)" >> "$REPORT_FILE"
  [ "$review_percentage" -lt 90 ] && echo "- **CC8.1**: Require code owner review on protected branches (currently $review_percentage%)" >> "$REPORT_FILE"
  [ "$past_due_alerts" -gt 0 ] && echo "- **CC7.1**: $past_due_alerts findings are past their remediation window" >> "$REPORT_FILE"

  cat >> "$REPORT_FILE" << EOF

### Recommendations

1. **Access Control**: Achieve 100% 2FA enforcement and 95%+ branch protection
2. **Monitoring**: Enable code and secret scanning everywhere, and stream audit logs to retained storage
3. **Incident Response**: Document and test security incident procedures
4. **Change Management**: Implement repository rulesets for all critical repositories

EOF
}

# Generate HIPAA report
generate_hipaa_report() {
  report_header "GitHub HIPAA Security Rule Compliance Report"

  cat >> "$REPORT_FILE" << EOF
### HIPAA Security Rule Assessment

> The Security Rule governs ePHI. GitHub is in scope as a system that supports
> applications handling ePHI; it is not itself a covered data store unless ePHI
> has been committed to a repository. Confirm scope before relying on this table.

#### Administrative Safeguards (45 CFR § 164.308)

| Standard | Implementation Specification | Status | Evidence |
|----------|----------------------------|--------|----------|
| 164.308(a)(1)(ii)(A) | Risk Analysis | $(status_for "$ghas_percentage" 100) | Code scanning coverage: $ghas_percentage% |
| 164.308(a)(1)(ii)(B) | Risk Management | $(evidence_status true "$([ "$past_due_alerts" -eq 0 ] && echo true || echo false)") | $total_dependabot_alerts open dependency alerts, $past_due_alerts past due |
| 164.308(a)(3) | Workforce Security | $(bool_status "$two_factor_required") | 2FA enforcement: $two_factor_required |
| 164.308(a)(4) | Information Access Management | $(status_for "$protected_percentage" 100) | Branch protection or ruleset: $protected_percentage% |
| 164.308(a)(5) | Security Awareness and Training | $(bool_status "$org_security_policy") | Organization SECURITY.md published: $org_security_policy |
| 164.308(a)(6) | Security Incident Procedures | $(bool_status "$org_security_policy") | Documented reporting path |

#### Technical Safeguards (45 CFR § 164.312)

| Standard | Implementation Specification | Status | Evidence |
|----------|----------------------------|--------|----------|
| 164.312(a)(1) | Access Control | $(status_for "$protected_percentage" 100) | Branch protection or ruleset: $protected_percentage% |
| 164.312(a)(2)(i) | Unique User Identification | $(bool_status "$two_factor_required") | 2FA enforced for all members |
| 164.312(a)(2)(iv) | Encryption and Decryption | ✓ | Provided by GitHub (encryption at rest) |
| 164.312(b) | Audit Controls | $(evidence_status "$audit_log_available" "$audit_log_available") | Audit log readable: $audit_log_available |
| 164.312(c)(1) | Integrity | $(status_for "$signing_percentage" 95) | Artifact signing or attestation: $signing_percentage% |
| 164.312(e)(1) | Transmission Security | ✓ | Provided by GitHub (TLS in transit) |

### Critical HIPAA Gaps

EOF

  # HIPAA requires 100% compliance for certain controls
  [ "$two_factor_required" != "true" ] && echo "- **CRITICAL**: Enable mandatory 2FA (164.308(a)(3))" >> "$REPORT_FILE"
  [ "$protected_percentage" -lt 100 ] && echo "- **CRITICAL**: Achieve 100% branch protection (164.308(a)(4))" >> "$REPORT_FILE"
  [ "$signing_percentage" -lt 95 ] && echo "- **CRITICAL**: Implement artifact signing for integrity (164.312(c))" >> "$REPORT_FILE"
  [ "$audit_log_available" != "true" ] && echo "- **CRITICAL**: Obtain and retain organization audit logs (164.312(b))" >> "$REPORT_FILE"
  [ "$alerts_not_visible" -gt 0 ] && echo "- **CRITICAL**: $alerts_not_visible repositories have no vulnerability visibility (164.308(a)(1)(ii)(A))" >> "$REPORT_FILE"

  cat >> "$REPORT_FILE" << EOF

### Required Actions for HIPAA Compliance

1. **Immediate**: Enable 2FA and achieve 100% branch protection
2. **Next**: Implement comprehensive audit logging with a defined retention period
3. **Then**: Deploy artifact signing and integrity controls
4. **Ongoing**: Regular risk assessments and workforce training

EOF
}

# Generate ISO 27001 report
generate_iso27001_report() {
  report_header "GitHub ISO 27001:2022 Compliance Report"

  cat >> "$REPORT_FILE" << EOF
### ISO 27001:2022 Annex A Controls Assessment

> Annex A was renumbered in the 2022 revision. The identifiers below follow
> ISO/IEC 27001:2022, not the 2013 A.5-A.18 structure.

#### A.5 - Organizational Controls

| Control | Description | Status | Evidence |
|---------|-------------|--------|----------|
| A.5.1 | Policies for information security | $(bool_status "$org_security_policy") | Organization SECURITY.md published: $org_security_policy |
| A.5.2 | Information security roles and responsibilities | $(bool_status "$has_security_managers") | Security managers assigned: $security_managers_count |
| A.5.9 | Inventory of information and other associated assets | ✓ | $total_repos repositories inventoried in this evidence set |
| A.5.15 | Access control | $(status_for "$protected_percentage" 80) | Branch protection or ruleset: $protected_percentage% |
| A.5.17 | Authentication information | $(bool_status "$two_factor_required") | 2FA required: $two_factor_required |

#### A.8 - Technological Controls

| Control | Description | Status | Evidence |
|---------|-------------|--------|----------|
| A.8.2 | Privileged access rights | $(status_for "$codeowners_percentage" 80) | CODEOWNERS: $codeowners_percentage% |
| A.8.8 | Management of technical vulnerabilities | $(status_for "$ghas_percentage" 80) | Code scanning: $ghas_percentage%, $total_dependabot_alerts open dependency alerts, $past_due_alerts past due |
| A.8.15 | Logging | $(evidence_status "$audit_log_available" "$audit_log_available") | Audit log readable: $audit_log_available |
| A.8.25 | Secure development life cycle | $(status_for "$review_percentage" 80) | Required review with code owners: $review_percentage% |
| A.8.28 | Secure coding | $(status_for "$pinning_percentage" 80) | Actions pinned to a commit SHA: $pinning_percentage% |
| A.8.30 | Outsourced development | $(status_for "$sbom_percentage" 60) | SBOM generation: $sbom_percentage% |
| A.8.32 | Change management | $(status_for "$rulesets_percentage" 50) | Repository rulesets: $rulesets_percentage% |

### ISO 27001 Compliance Gaps

EOF

  # Add ISO 27001 specific gaps
  [ "$two_factor_required" != "true" ] && echo "- **A.5.17**: Enable mandatory 2FA" >> "$REPORT_FILE"
  [ "$protected_percentage" -lt 80 ] && echo "- **A.5.15**: Increase branch protection to 80%+ (currently $protected_percentage%)" >> "$REPORT_FILE"
  [ "$sbom_percentage" -lt 60 ] && echo "- **A.8.30**: Implement SBOM generation (currently $sbom_percentage%)" >> "$REPORT_FILE"
  [ "$pinning_percentage" -lt 80 ] && echo "- **A.8.28**: Pin third-party Actions to commit SHAs (currently $pinning_percentage%)" >> "$REPORT_FILE"

  cat >> "$REPORT_FILE" << EOF

### ISO 27001 Implementation Roadmap

1. **Establish the ISMS foundation**
   - Enable 2FA and branch protection
   - Document security policies and procedures
   - Assign security roles and responsibilities

2. **Implement technical controls**
   - Deploy code and secret scanning across all repositories
   - Configure vulnerability management with defined remediation windows
   - Establish incident response procedures

3. **Continuous improvement**
   - Regular security assessments
   - Metrics and KPI tracking
   - Internal audit program

EOF
}

# Generate PCI-DSS report
generate_pcidss_report() {
  report_header "GitHub PCI-DSS v4.0 Compliance Report"

  cat >> "$REPORT_FILE" << EOF
### PCI-DSS v4.0 Requirements Assessment

> Only the requirements that a source control platform can evidence are listed.
> Requirements 1-4 are largely network and cardholder data controls that GitHub
> does not implement on your behalf; they are excluded rather than auto-passed.

#### Requirement 6: Develop and Maintain Secure Systems and Software

| Requirement | Description | Status | Evidence |
|-------------|-------------|--------|----------|
| 6.2.1 | Software developed securely | $(status_for "$ghas_percentage" 100) | Code scanning coverage: $ghas_percentage% |
| 6.2.4 | Prevention of common coding vulnerabilities | $(evidence_status true "$([ "$code_scanning_critical" -eq 0 ] && [ "$code_scanning_high" -eq 0 ] && echo true || echo false)") | Open code scanning: $code_scanning_critical critical, $code_scanning_high high |
| 6.3.1 | Security vulnerabilities identified and managed | $(evidence_status "$([ "$alerts_not_visible" -eq 0 ] && echo true || echo false)" "$([ "$past_due_alerts" -eq 0 ] && echo true || echo false)") | $total_dependabot_alerts open ($dependabot_critical critical, $dependabot_high high), $past_due_alerts past due |
| 6.3.2 | Inventory of bespoke and third-party software | $(status_for "$sbom_percentage" 100) | SBOM generation: $sbom_percentage% |
| 6.3.3 | Security patches installed | $(evidence_status true "$([ "$past_due_alerts" -eq 0 ] && echo true || echo false)") | $past_due_alerts findings past their remediation window |
| 6.5.1 | Change control procedures | $(status_for "$review_percentage" 100) | Required review with code owners: $review_percentage% |

#### Requirement 7-8: Access Control and Authentication

| Requirement | Description | Status | Evidence |
|-------------|-------------|--------|----------|
| 7.2.1 | Access control model defined | $(status_for "$codeowners_percentage" 100) | CODEOWNERS: $codeowners_percentage% |
| 7.2.5 | Application and system accounts managed | $(bool_status "$has_security_managers") | Security managers assigned: $security_managers_count |
| 8.3.1 | Strong authentication for all access | $(bool_status "$two_factor_required") | MFA enforced: $two_factor_required |
| 8.4.2 | MFA for all access into the CDE | $(bool_status "$two_factor_required") | Organization-wide 2FA requirement |

#### Requirement 10: Log and Monitor All Access

| Requirement | Description | Status | Evidence |
|-------------|-------------|--------|----------|
| 10.2.1 | Audit logs enabled and active | $(evidence_status "$audit_log_available" "$audit_log_available") | Audit log readable: $audit_log_available |
| 10.3.2 | Audit logs protected from modification | $(evidence_status "$audit_log_available" "$audit_log_available") | GitHub-managed, immutable to org members |
| 10.5.1 | Audit log history retained | ? | Retention depends on log streaming configuration; verify manually |

#### Requirement 11-12: Testing and Policy

| Requirement | Description | Status | Evidence |
|-------------|-------------|--------|----------|
| 11.3.1 | Internal vulnerability scans | $(status_for "$ghas_percentage" 100) | Code scanning coverage: $ghas_percentage% |
| 12.1.1 | Information security policy maintained | $(bool_status "$org_security_policy") | Organization SECURITY.md published: $org_security_policy |
| 12.10.1 | Incident response plan exists | $(bool_status "$org_security_policy") | Documented reporting path |

### PCI-DSS v4.0 Critical Failures

EOF

  # PCI-DSS has zero tolerance for certain requirements
  [ "$two_factor_required" != "true" ] && echo "- **FAIL - Req 8.3.1**: MFA not enforced" >> "$REPORT_FILE"
  [ "$review_percentage" -lt 100 ] && echo "- **FAIL - Req 6.5.1**: Code owner review not enforced on all repositories (currently $review_percentage%)" >> "$REPORT_FILE"
  [ "$past_due_alerts" -gt 0 ] && echo "- **FAIL - Req 6.3.3**: $past_due_alerts findings past their remediation window" >> "$REPORT_FILE"
  [ "$ghas_percentage" -lt 100 ] && echo "- **FAIL - Req 6.2.1**: Code scanning not enabled on all repositories (currently $ghas_percentage%)" >> "$REPORT_FILE"
  [ "$alerts_not_visible" -gt 0 ] && echo "- **UNKNOWN - Req 6.3.1**: $alerts_not_visible repositories provided no vulnerability data" >> "$REPORT_FILE"

  cat >> "$REPORT_FILE" << EOF

### Required for PCI-DSS Compliance

1. **IMMEDIATE ACTION REQUIRED**:
   - Enable mandatory 2FA for all users
   - Achieve 100% branch protection with enforced code review
   - Remediate findings within their defined windows
   - Enable code and secret scanning across the cardholder data environment

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
  report_header "GitHub Multi-Framework Compliance Report"

  cat >> "$REPORT_FILE" << EOF
### Framework Readiness Summary

Readiness reflects only the configuration signals this tool can measure. It is an
input to an assessment, never a substitute for one.

| Framework | Branch protection | Review enforcement | Scanning | Overdue findings | Readiness |
|-----------|-------------------|--------------------|----------|------------------|-----------|
| FedRAMP / NIST | $(status_for "$protected_percentage" 80) $protected_percentage% | $(status_for "$review_percentage" 80) $review_percentage% | $(status_for "$ghas_percentage" 80) $ghas_percentage% | $(evidence_status true "$([ "$past_due_alerts" -eq 0 ] && echo true || echo false)") $past_due_alerts | $(framework_readiness 80 80 80) |
| SOC 2 | $(status_for "$protected_percentage" 90) $protected_percentage% | $(status_for "$review_percentage" 90) $review_percentage% | $(status_for "$ghas_percentage" 90) $ghas_percentage% | $(evidence_status true "$([ "$past_due_alerts" -eq 0 ] && echo true || echo false)") $past_due_alerts | $(framework_readiness 90 90 90) |
| HIPAA | $(status_for "$protected_percentage" 100) $protected_percentage% | $(status_for "$review_percentage" 100) $review_percentage% | $(status_for "$ghas_percentage" 100) $ghas_percentage% | $(evidence_status true "$([ "$past_due_alerts" -eq 0 ] && echo true || echo false)") $past_due_alerts | $(framework_readiness 100 100 100) |
| ISO 27001 | $(status_for "$protected_percentage" 80) $protected_percentage% | $(status_for "$review_percentage" 80) $review_percentage% | $(status_for "$ghas_percentage" 80) $ghas_percentage% | $(evidence_status true "$([ "$past_due_alerts" -eq 0 ] && echo true || echo false)") $past_due_alerts | $(framework_readiness 80 80 80) |
| PCI-DSS | $(status_for "$protected_percentage" 100) $protected_percentage% | $(status_for "$review_percentage" 100) $review_percentage% | $(status_for "$ghas_percentage" 100) $ghas_percentage% | $(evidence_status true "$([ "$past_due_alerts" -eq 0 ] && echo true || echo false)") $past_due_alerts | $(framework_readiness 100 100 100) |

### Universal Security Controls Assessment

| Control Area | Current State | FedRAMP | SOC 2 | HIPAA | ISO 27001 | PCI-DSS |
|-------------|--------------|---------|-------|-------|-----------|---------|
| Multi-factor authentication | $two_factor_required | Required | Required | Required | Required | Required |
| Branch protection or ruleset | $protected_percentage% | 80%+ | 90%+ | 100% | 80%+ | 100% |
| Code owner review required | $review_percentage% | 80%+ | 90%+ | 100% | 80%+ | 100% |
| Code scanning coverage | $ghas_percentage% | Required | Required | Required | Required | Required |
| Secret scanning push protection | $push_protection_percentage% | Required | Required | Required | Required | Required |
| Open findings past due | $past_due_alerts | 0 | 0 | 0 | 0 | 0 |
| Audit log accessible | $audit_log_available | Required | Required | Required | Required | Required |
| Actions pinned to a commit SHA | $pinning_percentage% | 80%+ | Recommended | Recommended | 80%+ | Recommended |
| SBOM generation | $sbom_percentage% | 50%+ | N/A | N/A | 60%+ | Required (6.3.2) |
| Artifact signing or attestation | $signing_percentage% | 50%+ | N/A | 95%+ | Recommended | Recommended |

### Open findings

| Source | Open | Critical | High | Past due | Repositories with no visibility |
|--------|------|----------|------|----------|---------------------------------|
| Dependabot | $total_dependabot_alerts | $dependabot_critical | $dependabot_high | $(read_summary '.alerts.dependabot.past_due') | $(read_summary '.alerts.dependabot.repos_without_visibility') |
| Code scanning | $total_code_scanning_alerts | $code_scanning_critical | $code_scanning_high | $(read_summary '.alerts.code_scanning.past_due') | $(read_summary '.alerts.code_scanning.repos_without_visibility') |
| Secret scanning | $total_secret_scanning_alerts | - | $total_secret_scanning_alerts | $(read_summary '.alerts.secret_scanning.past_due') | $(read_summary '.alerts.secret_scanning.repos_without_visibility') |

Remediation windows used: critical 15 days, high 30, medium 90, low 180.

### Critical Actions Required Across All Frameworks

EOF

  # Add universal critical actions
  [ "$two_factor_required" != "true" ] && echo "- **CRITICAL**: Enable mandatory 2FA organization-wide" >> "$REPORT_FILE"
  [ "$ghas_percentage" -lt 80 ] && echo "- **CRITICAL**: Enable code scanning (currently $ghas_percentage% of repositories)" >> "$REPORT_FILE"
  [ "$push_protection_percentage" -lt 80 ] && echo "- **CRITICAL**: Enable secret scanning push protection (currently $push_protection_percentage%)" >> "$REPORT_FILE"
  [ "$protected_percentage" -lt 80 ] && echo "- **HIGH**: Increase branch protection to 80%+ minimum (currently $protected_percentage%)" >> "$REPORT_FILE"
  [ "$past_due_alerts" -gt 0 ] && echo "- **HIGH**: Remediate $past_due_alerts findings that are past their window" >> "$REPORT_FILE"
  [ "$audit_log_available" != "true" ] && echo "- **HIGH**: Obtain organization audit log access and configure log streaming" >> "$REPORT_FILE"
  [ "$pinning_percentage" -lt 80 ] && echo "- **MEDIUM**: Pin third-party Actions to commit SHAs (currently $pinning_percentage%)" >> "$REPORT_FILE"

  cat >> "$REPORT_FILE" << EOF

### Score breakdown

Every point below is attributable to a measured control. Total earned:
$(read_summary '.score.points_earned')/100, giving a risk score of $risk_score.

| Control | Points earned | Maximum |
|---------|---------------|---------|
| Multi-factor authentication | $(read_summary '.score.breakdown.two_factor') | 15 |
| Branch protection coverage | $(read_summary '.score.breakdown.branch_protection') | 20 |
| Review quality (code owners) | $(read_summary '.score.breakdown.review_quality') | 10 |
| Secret scanning push protection | $(read_summary '.score.breakdown.secret_protection') | 15 |
| Code scanning coverage | $(read_summary '.score.breakdown.code_scanning') | 10 |
| Dependency monitoring | $(read_summary '.score.breakdown.dependency_monitoring') | 5 |
| Remediation timeliness | $(read_summary '.score.breakdown.remediation_timeliness') | 10 |
| Code ownership | $(read_summary '.score.breakdown.ownership') | 5 |
| Action pinning | $(read_summary '.score.breakdown.action_pinning') | 5 |
| SBOM and provenance | $(read_summary '.score.breakdown.provenance') | 5 |

### Detailed Framework Assessments

Re-run with a framework argument for the full control table:
\`fedramp\`, \`nist\`, \`soc2\`, \`hipaa\`, \`iso27001\`, \`pci-dss\`.

### Audit Metadata

- **Audit date**: $AUDIT_STARTED_AT (UTC)
- **Tool version**: $AUDIT_TOOL_VERSION
- **Repositories discovered / scored**: $total_repos / $scored_repos
- **Machine-readable summary**: \`summary.json\`
- **Evidence manifest**: \`evidence_manifest.txt\` (SHA-256 of every collected file)
- **Output directory**: $OUTPUT_DIR

EOF
}

# Coarse readiness verdict from the three coverage measures a framework leans on.
framework_readiness() {
  local protection_bar="$1" review_bar="$2" scanning_bar="$3"

  if [ "$two_factor_required" = "true" ] &&
     [ "$protected_percentage" -ge "$protection_bar" ] &&
     [ "$review_percentage" -ge "$review_bar" ] &&
     [ "$ghas_percentage" -ge "$scanning_bar" ] &&
     [ "$past_due_alerts" -eq 0 ]; then
    echo "Signals met"
  else
    echo "Gaps identified"
  fi
}

# Generate FedRAMP/NIST report (original)
generate_fedramp_nist_report() {
  report_header "GitHub FedRAMP / NIST Compliance Report"

  cat >> "$REPORT_FILE" << EOF
### Key Security Metrics

| Security Control | Coverage |
|-----------------|----------|
| Two-factor authentication required | $two_factor_required (organization-wide) |
| Branch protection or active ruleset | $protected_percentage% |
| Required review with code owners | $review_percentage% |
| Repository rulesets | $rulesets_percentage% |
| Code scanning | $ghas_percentage% |
| Secret scanning | $secret_scanning_percentage% |
| Secret scanning push protection | $push_protection_percentage% |
| CODEOWNERS present | $codeowners_percentage% |
| Actions pinned to a commit SHA | $pinning_percentage% |
| SBOM generation | $sbom_percentage% |
| Artifact signing | $signing_percentage% |
| Build provenance attestation | $attestation_percentage% |

### Open Findings

| Source | Open | Critical | High | Past due |
|--------|------|----------|------|----------|
| Dependabot | $total_dependabot_alerts | $dependabot_critical | $dependabot_high | $(read_summary '.alerts.dependabot.past_due') |
| Code scanning | $total_code_scanning_alerts | $code_scanning_critical | $code_scanning_high | $(read_summary '.alerts.code_scanning.past_due') |
| Secret scanning | $total_secret_scanning_alerts | - | $total_secret_scanning_alerts | $(read_summary '.alerts.secret_scanning.past_due') |

## Detailed Compliance Assessment

### NIST SP 800-53 Rev 5 Controls

#### Access Control (AC) Family
| Control | Description | Status | Evidence |
|---------|-------------|--------|-----------|
| AC-2 | Account Management | $(bool_status "$has_security_managers") | Security managers assigned: $security_managers_count |
| AC-3 | Access Enforcement | $(status_for "$protected_percentage" 80) | Branch protection or ruleset: $protected_percentage% |
| AC-5 | Separation of Duties | $(status_for "$review_percentage" 80) | Code owner review required: $review_percentage% |
| AC-6 | Least Privilege | $(status_for "$codeowners_percentage" 80) | CODEOWNERS: $codeowners_percentage% |

#### Identification and Authentication (IA) Family
| Control | Description | Status | Evidence |
|---------|-------------|--------|-----------|
| IA-2 | Identification and Authentication | $(bool_status "$two_factor_required") | 2FA required: $two_factor_required |
| IA-2(1) | Multi-factor Authentication | $(bool_status "$two_factor_required") | Organization-wide 2FA requirement |
| IA-5 | Authenticator Management | $(bool_status "$two_factor_required") | Strong authentication required |

#### Audit and Accountability (AU) Family
| Control | Description | Status | Evidence |
|---------|-------------|--------|-----------|
| AU-2 | Event Logging | $(evidence_status "$audit_log_available" "$audit_log_available") | Audit log readable: $audit_log_available |
| AU-9 | Protection of Audit Information | $(evidence_status "$audit_log_available" "$audit_log_available") | GitHub-managed audit log |
| AU-11 | Audit Record Retention | ? | Depends on log streaming; verify manually |

#### Risk Assessment (RA) Family
| Control | Description | Status | Evidence |
|---------|-------------|--------|-----------|
| RA-5 | Vulnerability Monitoring and Scanning | $(status_for "$ghas_percentage" 80) | Code scanning: $ghas_percentage%, $alerts_not_visible repositories with no visibility |
| RA-5(2) | Update Vulnerabilities to Be Scanned | $(evidence_status true "$([ "$past_due_alerts" -eq 0 ] && echo true || echo false)") | $past_due_alerts findings past their remediation window |

#### System and Information Integrity (SI) Family
| Control | Description | Status | Evidence |
|---------|-------------|--------|-----------|
| SI-2 | Flaw Remediation | $(evidence_status true "$([ "$past_due_alerts" -eq 0 ] && echo true || echo false)") | $total_dependabot_alerts open dependency findings, $past_due_alerts past due |
| SI-3 | Malicious Code Protection | $(status_for "$ghas_percentage" 80) | Code scanning coverage: $ghas_percentage% |
| SI-4 | System Monitoring | $(status_for "$secret_scanning_percentage" 80) | Secret scanning coverage: $secret_scanning_percentage% |
| SI-7 | Software, Firmware, and Information Integrity | $(status_for "$signing_percentage" 50) | Artifact signing: $signing_percentage% |

#### Configuration Management (CM) Family
| Control | Description | Status | Evidence |
|---------|-------------|--------|-----------|
| CM-2 | Baseline Configuration | $(status_for "$protected_percentage" 80) | Protected branches: $protected_percentage% |
| CM-3 | Configuration Change Control | $(status_for "$rulesets_percentage" 50) | Repository rulesets: $rulesets_percentage% |
| CM-5 | Access Restrictions for Change | $(status_for "$review_percentage" 80) | Review enforcement: $review_percentage% |
| CM-7 | Least Functionality | $(status_for "$pinning_percentage" 80) | Actions pinned to a commit SHA: $pinning_percentage% |

### NIST SP 800-161 Rev 1 Update 1 Supply Chain Controls

#### Supply Chain Risk Management (SR) Family
| Control | Description | Status | Evidence |
|---------|-------------|--------|-----------|
| SR-3 | Supply Chain Controls and Processes | $(status_for "$protected_percentage" 80) | Development controls enforced: $protected_percentage% |
| SR-4 | Provenance | $(status_for "$sbom_percentage" 50) | SBOM generation: $sbom_percentage%, attestation: $attestation_percentage% |
| SR-5 | Acquisition Strategies, Tools, and Methods | $(status_for "$pinning_percentage" 80) | Actions pinned to a commit SHA: $pinning_percentage% |
| SR-10 | Inspection of Systems or Components | $(status_for "$ghas_percentage" 80) | Automated scanning coverage: $ghas_percentage% |
| SR-11 | Component Authenticity | $(status_for "$signing_percentage" 50) | Artifact signing: $signing_percentage% |

### Critical Findings and Recommendations

#### Critical issues (immediate action required)
EOF

  if [ "$two_factor_required" != "true" ]; then
    echo "- **Enable mandatory 2FA**: the organization does not require two-factor authentication" >> "$REPORT_FILE"
  fi
  if [ "$ghas_percentage" -lt 50 ]; then
    echo "- **Enable code scanning**: only $ghas_percentage% of scored repositories have it on" >> "$REPORT_FILE"
  fi
  if [ "$protected_percentage" -lt 50 ]; then
    echo "- **Implement branch protection**: only $protected_percentage% of repositories are protected" >> "$REPORT_FILE"
  fi
  if [ "$past_due_alerts" -gt 0 ]; then
    echo "- **Remediate overdue findings**: $past_due_alerts findings exceed their RA-5 window" >> "$REPORT_FILE"
  fi
  if [ "$alerts_not_visible" -gt 0 ]; then
    echo "- **Restore vulnerability visibility**: $alerts_not_visible repositories returned no alert data" >> "$REPORT_FILE"
  fi

  cat >> "$REPORT_FILE" << EOF

#### High priority improvements
EOF

  if [ "$sbom_percentage" -lt 50 ]; then
    echo "- Generate SBOMs for all repositories (currently $sbom_percentage%)" >> "$REPORT_FILE"
  fi
  if [ "$signing_percentage" -lt 50 ]; then
    echo "- Implement artifact signing (currently $signing_percentage%)" >> "$REPORT_FILE"
  fi
  if [ "$attestation_percentage" -lt 50 ]; then
    echo "- Add build provenance attestation to release workflows (currently $attestation_percentage%)" >> "$REPORT_FILE"
  fi
  if [ "$rulesets_percentage" -lt 50 ]; then
    echo "- Configure repository rulesets for org-wide enforcement (currently $rulesets_percentage%)" >> "$REPORT_FILE"
  fi
  if [ "$pinning_percentage" -lt 80 ]; then
    echo "- Pin third-party Actions to full commit SHAs (currently $pinning_percentage%)" >> "$REPORT_FILE"
  fi

  cat >> "$REPORT_FILE" << EOF

#### Recommended enhancements
- Implement automated compliance scanning in CI/CD pipelines
- Configure audit log streaming for long-term retention
- Document and test incident response procedures
- Establish automated dependency update policies

### Next Steps

1. **First**
   - Enable mandatory 2FA for all organization members
   - Configure branch protection on all active repositories
   - Review and remediate critical security alerts

2. **Then**
   - Enable code and secret scanning across all repositories
   - Deploy SBOM generation workflows
   - Configure artifact signing and provenance attestation for releases

3. **Sustaining**
   - Achieve 100% branch protection coverage
   - Implement organization rulesets for fine-grained controls
   - Establish continuous compliance monitoring against this evidence set

### Audit Details
- **Audit date**: $AUDIT_STARTED_AT (UTC)
- **Tool version**: $AUDIT_TOOL_VERSION
- **Repositories discovered / scored**: $total_repos / $scored_repos
- **Concurrent workers**: $MAX_PARALLEL_JOBS
- **Output directory**: $OUTPUT_DIR

For detailed findings per repository, review \`summary.json\` and the JSON evidence tree.
EOF
}

# Assign report output path per framework
case "$FRAMEWORK" in
  all)
    REPORT_FILE="$OUTPUT_DIR/multi_framework_compliance_report.md"
    ;;
  fedramp|nist)
    REPORT_FILE="$OUTPUT_DIR/fedramp_nist_compliance_report.md"
    ;;
  soc2)
    REPORT_FILE="$OUTPUT_DIR/soc2_compliance_report.md"
    ;;
  hipaa)
    REPORT_FILE="$OUTPUT_DIR/hipaa_compliance_report.md"
    ;;
  iso27001)
    REPORT_FILE="$OUTPUT_DIR/iso27001_compliance_report.md"
    ;;
  pci-dss)
    REPORT_FILE="$OUTPUT_DIR/pci_dss_compliance_report.md"
    ;;
  *)
    echo "Error: Unhandled framework '$FRAMEWORK' when assigning REPORT_FILE"
    exit 1
    ;;
esac

# Generate report based on selected framework
if [ "$FRAMEWORK" = "all" ]; then
  # Generate combined report for all frameworks
  generate_combined_report
else
  # Generate specific framework report
  generate_framework_report "$FRAMEWORK"
fi

# An evidence package that cannot be shown to be unmodified is weak evidence.
# The manifest lets an assessor verify the tree has not been edited after the
# fact, and lets you diff two runs to prove remediation actually happened.
echo "Writing evidence manifest..."
if command -v sha256sum > /dev/null 2>&1; then
  HASH_CMD="sha256sum"
elif command -v shasum > /dev/null 2>&1; then
  HASH_CMD="shasum -a 256"
else
  HASH_CMD=""
fi

if [ -n "$HASH_CMD" ]; then
  (
    cd "$OUTPUT_DIR" || exit 0
    # shellcheck disable=SC2086  # HASH_CMD may be "shasum -a 256"
    find . -type f ! -name 'evidence_manifest.txt' ! -name '.progress' ! -name '.total' \
      -print0 | sort -z | xargs -0 $HASH_CMD
  ) > "$OUTPUT_DIR/evidence_manifest.txt" 2>/dev/null || true
fi

rm -f "$OUTPUT_DIR/.progress" "$OUTPUT_DIR/.total"
rm -f "${TMPDIR:-/tmp}/gh_compliance_audit_headers_$$"

echo "$FRAMEWORK compliance audit completed!"
echo "Report available at: $REPORT_FILE"
echo "Machine-readable summary: $OUTPUT_DIR/summary.json"
echo "Risk Score: $risk_score/100 (Compliance Level: $compliance_level)"

# A non-zero exit lets CI gate on posture without parsing the report.
if [ "$compliance_level" = "Low" ]; then
  exit 2
fi
exit 0