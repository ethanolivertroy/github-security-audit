#!/usr/bin/env bash
# End-to-end tests for github_compliance_audit.sh against a mock GitHub API.
#
# No network access and no GitHub account required: tests/mock_api/curl is put
# ahead of the real curl on PATH and serves the fixture tree in tests/fixtures.
#
# Several assertions search reports for literal '$name' strings that must not
# appear; those single quotes are deliberate.
# shellcheck disable=SC2016
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
AUDIT_SCRIPT="$REPO_ROOT/github_compliance_audit.sh"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

PASS=0
FAIL=0

pass() { printf '  ok   %s\n' "$1"; PASS=$((PASS + 1)); }
fail() { printf '  FAIL %s\n     expected: %s\n     actual:   %s\n' "$1" "$2" "$3"; FAIL=$((FAIL + 1)); }

assert_eq() {
  local label="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    pass "$label"
  else
    fail "$label" "$expected" "$actual"
  fi
}

assert_contains() {
  local label="$1" needle="$2" file="$3"
  if grep -qF -- "$needle" "$file"; then
    pass "$label"
  else
    fail "$label" "file contains '$needle'" "not found in $file"
  fi
}

assert_not_contains() {
  local label="$1" needle="$2" file="$3"
  if grep -qF -- "$needle" "$file"; then
    fail "$label" "file does not contain '$needle'" "found in $file"
  else
    pass "$label"
  fi
}

run_audit() {
  local org="$1" framework="$2" out="$3"
  shift 3

  env PATH="$SCRIPT_DIR/mock_api:$PATH" \
    AUDIT_RUNNER="${AUDIT_RUNNER:-}" \
    MOCK_API_DIR="$SCRIPT_DIR/fixtures/$org" \
    GITHUB_TOKEN="mock-token" \
    GITHUB_API_URL="https://api.github.com" \
    OUTPUT_DIR="$out" \
    MAX_PARALLEL_JOBS=4 \
    RETRY_ATTEMPTS=1 \
    RETRY_DELAY=0 \
    AUDIT_NOW_EPOCH=1785024000 \
    "$@" \
    bash "$AUDIT_SCRIPT" "$org" "$framework"
}

echo "== usage and validation =="

output="$(bash "$AUDIT_SCRIPT" 2>&1)"; status=$?
assert_eq "no arguments exits 1" "1" "$status"
case "$output" in
  *Usage:*) pass "no arguments prints usage" ;;
  *) fail "no arguments prints usage" "usage text" "$output" ;;
esac

output="$(bash "$AUDIT_SCRIPT" --help 2>&1)"; status=$?
assert_eq "--help exits 0" "0" "$status"

output="$(bash "$AUDIT_SCRIPT" some-org not-a-framework 2>&1)"; status=$?
assert_eq "invalid framework exits 1" "1" "$status"

echo
echo "== full audit against mock API =="

OUT="$WORK_DIR/audit"
run_audit acme-corp all "$OUT" > "$WORK_DIR/audit.log" 2>&1
audit_status=$?

if [ ! -f "$OUT/summary.json" ]; then
  echo "  FAIL audit did not produce summary.json (exit $audit_status)"
  sed 's/^/       /' "$WORK_DIR/audit.log"
  exit 1
fi
pass "audit completes and writes summary.json"

s() { jq -r "$1" "$OUT/summary.json"; }

# Exit code 2 is reserved for a Low compliance level so CI can gate on posture.
if [ "$(s '.score.compliance_level')" = "Low" ]; then
  assert_eq "low posture exits 2" "2" "$audit_status"
else
  assert_eq "acceptable posture exits 0" "0" "$audit_status"
fi

echo
echo "== repository scoping =="
assert_eq "all repositories discovered" "5" "$(s '.repositories.total')"
assert_eq "archived and empty excluded from scoring" "3" "$(s '.repositories.scored')"
assert_eq "archived counted" "1" "$(s '.repositories.archived')"
assert_eq "empty counted" "1" "$(s '.repositories.empty')"

echo
echo "== branch protection and rulesets =="
# payments-api via branch protection, web-frontend via an active ruleset.
assert_eq "ruleset-only repo counts as protected" "66" "$(s '.coverage.branch_protection')"
assert_eq "active branch rulesets counted" "33" "$(s '.coverage.rulesets')"
assert_eq "code owner review coverage" "33" "$(s '.coverage.review_with_code_owners')"
assert_eq "required reviews read from protection" "2" \
  "$(jq -r '.branch_protection.required_reviews' "$OUT/repositories/payments-api/analysis.json")"
assert_eq "enforce_admins read from protection" "true" \
  "$(jq -r '.branch_protection.enforce_admins' "$OUT/repositories/payments-api/analysis.json")"

echo
echo "== organization controls =="
assert_eq "2FA requirement detected" "true" "$(s '.organization_controls.two_factor_required')"
assert_eq "security managers counted, not just present" "1" "$(s '.organization_controls.security_managers')"
# The fixture returns 403 for the audit log, which must not read as a pass.
assert_eq "inaccessible audit log is not a pass" "false" "$(s '.organization_controls.audit_log_accessible')"
assert_eq "absent org security policy is not a pass" "false" "$(s '.organization_controls.security_policy_published')"

echo
echo "== alerts =="
assert_eq "open dependabot alerts totalled" "4" "$(s '.alerts.dependabot.open')"
assert_eq "critical severity counted" "1" "$(s '.alerts.dependabot.critical')"
assert_eq "high severity counted" "1" "$(s '.alerts.dependabot.high')"
assert_eq "overdue findings flagged" "2" "$(s '.alerts.dependabot.past_due')"
# legacy-billing returns 403 for code scanning: unknown, not clean.
assert_eq "repos without alert visibility tracked" "1" \
  "$(s '.alerts.code_scanning.repos_without_visibility')"
assert_eq "partial blindness rolls up to the repository" "1" \
  "$(s '.alerts.repositories_without_visibility')"
assert_eq "secret scanning alerts counted" "1" "$(s '.alerts.secret_scanning.open')"

echo
echo "== supply chain analysis =="
assert_eq "sha-pinned actions counted" "4" "$(s '.counts.actions_pinned')"
# legacy-billing has two unpinned actions and one local action (not counted).
assert_eq "unpinnable local actions excluded" "6" "$(s '.counts.actions_total')"
assert_eq "pinning percentage" "66" "$(s '.coverage.actions_pinned_to_sha')"
assert_eq "sbom detected from workflow contents" "33" "$(s '.coverage.sbom')"
assert_eq "attestation detected from workflow contents" "33" "$(s '.coverage.attestation')"
assert_eq "signing detected from release assets" "33" "$(s '.coverage.signing')"
assert_eq "codeowners found at both .github and root" "66" "$(s '.coverage.codeowners')"

echo
echo "== scoring =="
risk="$(s '.score.risk_score')"
if [ "$risk" -gt 0 ] && [ "$risk" -lt 100 ]; then
  pass "risk score in range (got $risk)"
else
  fail "risk score in range" "0 < score < 100" "$risk"
fi
assert_eq "score breakdown sums to points earned" "true" \
  "$(jq -r '([.score.breakdown | to_entries[] | .value] | add) == .score.points_earned' "$OUT/summary.json")"
assert_eq "2FA earns its full weight" "15" "$(s '.score.breakdown.two_factor')"

echo
echo "== report output =="
REPORT="$OUT/multi_framework_compliance_report.md"
assert_contains "report generated" "Multi-Framework Compliance Report" "$REPORT"
assert_contains "report warns about unreadable audit log" "audit log was not readable" "$REPORT"
assert_contains "report warns about invisible alerts" "returned no alert data: 1" "$REPORT"
assert_contains "report shows score breakdown" "Score breakdown" "$REPORT"
assert_not_contains "no unexpanded variables in report" '$total_repos' "$REPORT"
assert_not_contains "no raw jq paths in report" '.coverage.' "$REPORT"

echo
echo "== evidence integrity =="
assert_contains "manifest lists the summary" "summary.json" "$OUT/evidence_manifest.txt"
if [ -f "$OUT/.progress" ] || [ -f "$OUT/.total" ]; then
  fail "scratch files cleaned up" "no .progress/.total" "present"
else
  pass "scratch files cleaned up"
fi

echo
echo "== token handling =="
# A token must never reach the process table.
if grep -q 'mock-token' "$WORK_DIR/audit.log"; then
  fail "token not echoed to output" "no token in logs" "token found"
else
  pass "token not echoed to output"
fi

echo
echo "== single framework reports =="
for framework in fedramp soc2 hipaa iso27001 pci-dss; do
  out="$WORK_DIR/audit-$framework"
  run_audit acme-corp "$framework" "$out" > "$WORK_DIR/$framework.log" 2>&1
  report="$(find "$out" -maxdepth 1 -name '*_compliance_report.md' 2>/dev/null | head -n1)"
  if [ -n "$report" ] && [ -s "$report" ]; then
    if grep -q '\$(' "$report" || grep -q '\$[a-z_]*_percentage' "$report"; then
      fail "$framework report renders" "no unexpanded shell" "found in $report"
    else
      pass "$framework report renders"
    fi
  else
    fail "$framework report renders" "a non-empty report" "none produced"
  fi
done

echo
echo "== concurrency backends =="
# Both backends must produce byte-identical findings; only the scheduler differs.
for backend in parallel xargs; do
  if [ "$backend" = "parallel" ] && ! command -v parallel > /dev/null 2>&1; then
    printf '  skip GNU parallel not installed\n'
    continue
  fi
  out="$WORK_DIR/audit-$backend"
  AUDIT_RUNNER="$backend" run_audit acme-corp all "$out" > "$WORK_DIR/$backend.log" 2>&1
  if [ -f "$out/summary.json" ]; then
    assert_eq "$backend backend produces the same coverage" \
      "$(jq -Sc '.coverage' "$OUT/summary.json")" \
      "$(jq -Sc '.coverage' "$out/summary.json")"
  else
    fail "$backend backend completes" "summary.json" "audit aborted"
  fi
done

echo
echo "== empty organization =="
OUT_EMPTY="$WORK_DIR/audit-empty"
run_audit empty-org all "$OUT_EMPTY" > "$WORK_DIR/empty.log" 2>&1
if [ -f "$OUT_EMPTY/summary.json" ]; then
  assert_eq "empty org scores zero repositories" "0" \
    "$(jq -r '.repositories.total' "$OUT_EMPTY/summary.json")"
  assert_eq "empty org does not divide by zero" "0" \
    "$(jq -r '.coverage.branch_protection' "$OUT_EMPTY/summary.json")"
else
  fail "empty org handled" "summary.json" "audit aborted"
  sed 's/^/       /' "$WORK_DIR/empty.log"
fi

echo
echo "== inaccessible organization =="
OUT_MISSING="$WORK_DIR/audit-missing"
run_audit no-such-org all "$OUT_MISSING" > "$WORK_DIR/missing.log" 2>&1
status=$?
assert_eq "unknown org exits 1" "1" "$status"
assert_contains "unknown org explains why" "Unable to access organization" "$WORK_DIR/missing.log"

echo
printf '\n%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
