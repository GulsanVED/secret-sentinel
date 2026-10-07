#!/usr/bin/env bash
# Secret Sentinel — the scan step for GitHub Actions.
#
# Runs both scans on the checked-out repo and decides the scope from the event:
#
#   pull_request        code: files the PR changes   history: the PR's commits
#   push                code: files the push changes history: the pushed commits
#   new branch push,    code: every file             history: every commit on
#   schedule, manual                                  every branch
#
# Writes SARIF, JSON reports and result.json (one summary of the run, read by
# the dashboard and the PR comment) to $SENTINEL_RESULTS_DIR (default
# ./sentinel-results), prints
# annotations and a job summary, sends email/Slack when configured, and exits
# non-zero when either scan finds a NEW secret at/above $SENTINEL_FAIL_ON.
#
# Needs: python3 (3.9+), git, and a checkout with full history (fetch-depth: 0).
#
# Environment (all optional):
#   SENTINEL_FAIL_ON      none|low|medium|high|critical   (default: high)
#   SENTINEL_FULL_HISTORY true = always scan all history (e.g. on a schedule)
#   PUSH_BEFORE_SHA       github.event.before       (set by the workflow)
#   PR_BASE_SHA           github.event.pull_request.base.sha
#   SMTP_HOST, ALERT_EMAIL_TO, ...   -> email alerts   (see .env.example)
#   SLACK_WEBHOOK_URL                -> Slack alerts
#   SENTINEL_URL, SENTINEL_TOKEN     -> notify a running dashboard
set -uo pipefail

sentinel_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target="$(cd "${1:-.}" && pwd)"
fail_on="${SENTINEL_FAIL_ON:-high}"
out="${SENTINEL_RESULTS_DIR:-$target/sentinel-results}"
mkdir -p "$out"

has_commit() { [ -n "$1" ] && git -C "$target" cat-file -e "$1^{commit}" 2>/dev/null; }

# ---- scope ------------------------------------------------------------------
base=""
case "${GITHUB_EVENT_NAME:-}" in
  pull_request|pull_request_target|merge_group)
    # actions/checkout checks out the PR's merge commit: its first parent is the
    # base branch, so base..HEAD is exactly what the PR brings in.
    if git -C "$target" rev-parse -q --verify "HEAD^2" >/dev/null; then
      base="$(git -C "$target" rev-parse HEAD^1)"
    else
      base="${PR_BASE_SHA:-}"
    fi
    ;;
  push)
    base="${PUSH_BEFORE_SHA:-}"
    ;;
esac
if [ "${SENTINEL_FULL_HISTORY:-false}" = "true" ]; then
  base=""
fi
if [ -n "$base" ] && ! has_commit "$base"; then
  # all-zero sha (new branch) or a force-push whose old head is gone
  echo "::notice::base commit ${base:0:12} not available — scanning everything"
  base=""
fi

diff_args=(); range_args=()
if [ -n "$base" ]; then
  diff_args=(--diff-base "$base")
  range_args=(--range "$base..HEAD")
  echo "Scope: changes since ${base:0:12}"
else
  echo "Scope: full tree and full history"
fi

# ---- alert channels -----------------------------------------------------------
alert_args=()
if [ -n "${SMTP_HOST:-}" ] && [ -n "${ALERT_EMAIL_TO:-}" ]; then alert_args+=(--email); fi
if [ -n "${SLACK_WEBHOOK_URL:-}" ]; then alert_args+=(--slack); fi
notify_args=()
if [ -n "${SENTINEL_URL:-}" ]; then notify_args=(--notify-url "${SENTINEL_URL%/}/webhook/ci"); fi

common=(--fail-on "$fail_on")
if [ -n "${GITHUB_REPOSITORY:-}" ]; then
  common+=(--label "$GITHUB_REPOSITORY" --repo-url "${GITHUB_SERVER_URL:-https://github.com}/$GITHUB_REPOSITORY")
fi
if [ -n "${GITHUB_SHA:-}" ]; then common+=(--commit "$GITHUB_SHA"); fi

# ---- scans --------------------------------------------------------------------
echo "::group::Scan code"
python3 "$sentinel_dir/ci_scan.py" scan-path "$target" "${diff_args[@]}" "${common[@]}" \
  "${alert_args[@]}" "${notify_args[@]}" --sarif "$out/code.sarif" --json-out "$out/code.json"
code_rc=$?
echo "::endgroup::"

echo "::group::Scan git history"
python3 "$sentinel_dir/ci_scan.py" scan-history "$target" "${range_args[@]}" "${common[@]}" \
  "${alert_args[@]}" --sarif "$out/history.sarif" --json-out "$out/history.json"
history_rc=$?
echo "::endgroup::"

echo "code scan exit: $code_rc, history scan exit: $history_rc"
# One result file per run, for the dashboard's CI runs tab and the PR comment.
scope="full scan"
[ -n "$base" ] && scope="changes since ${base:0:12}"
python3 "$sentinel_dir/ci/ci_result.py" "$out" "$code_rc" "$history_rc" "$scope" \
  || echo "::warning::could not write result.json"
if [ "$code_rc" -eq 2 ] || [ "$history_rc" -eq 2 ]; then
  echo "::error::Secret scan could not run — see the log above."
  exit 2
fi
if [ "$code_rc" -ne 0 ] || [ "$history_rc" -ne 0 ]; then
  echo "::error::Secrets found at or above '$fail_on'. Rotate them, then remove them or add them to .sentinelignore / the baseline."
  exit 1
fi
echo "No new secrets at or above '$fail_on'."
