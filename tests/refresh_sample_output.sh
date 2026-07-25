#!/usr/bin/env bash
# Regenerates sample_output/ from the test fixtures.
#
# The published sample is produced by the same code path as a real run, so it
# cannot drift from the report format the script actually emits. Run this after
# changing collection, scoring, or report templates.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$REPO_ROOT"
rm -rf sample_output
mkdir -p sample_output

env PATH="$SCRIPT_DIR/mock_api:$PATH" \
  MOCK_API_DIR="$SCRIPT_DIR/fixtures/acme-corp" \
  GITHUB_TOKEN="sample-token" \
  OUTPUT_DIR="sample_output" \
  MAX_PARALLEL_JOBS=4 \
  AUDIT_NOW_EPOCH=1785024000 \
  bash ./github_compliance_audit.sh acme-corp all || true

# A fixed timestamp keeps the committed sample free of churn on every refresh.
find sample_output -name '*.md' -type f -exec \
  perl -pi -e 's/\*\*Generated\*\*: \S+ \(UTC\)/**Generated**: 2026-07-25T12:00:00Z (UTC)/;
               s/\*\*Audit date\*\*: \S+ \(UTC\)/**Audit date**: 2026-07-25T12:00:00Z (UTC)/' {} +
perl -pi -e 's/"generated_at": "[^"]*"/"generated_at": "2026-07-25T12:00:00Z"/' \
  sample_output/summary.json

# The manifest hashes the report and summary, so it has to be rebuilt after the
# timestamps are normalised.
if command -v sha256sum > /dev/null 2>&1; then
  HASH_CMD="sha256sum"
else
  HASH_CMD="shasum -a 256"
fi
(
  cd sample_output
  find . -type f ! -name 'evidence_manifest.txt' -print0 | sort -z | xargs -0 $HASH_CMD
) > sample_output/evidence_manifest.txt

echo "sample_output/ refreshed from tests/fixtures/acme-corp"
