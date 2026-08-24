#!/bin/bash
# Scheduled integrity check for one or more repositories that share an upstream.
#
# install.sh schedules a single repository per launchd label, which is enough
# for most cases. This exists for the case it does not cover: a dependency whose
# calls are spread across more than one checkout -- typically an application
# plus the client library that builds its requests -- where one label per
# repository would have each overwrite the other.
#
# Each run re-indexes before checking, so a newly added call is picked up on the
# same pass rather than the next one.
#
# Configure with environment variables, or edit the defaults:
#
#   AIT_REPOS     space-separated repository paths to check
#   AIT_ACCOUNT   the gh account whose token to use (see below)
#   AIT_UPSTREAM  owner/name of the upstream, verified before any check runs
#   AIT_TOOL      path to the api-integrity-tool binary
#
# Install (macOS):
#   cp scripts/scheduled-check.sh ~/.local/bin/scheduled-check
#   chmod +x ~/.local/bin/scheduled-check
#   # then a launchd plist with StartInterval and this script as ProgramArguments
set -uo pipefail

# launchd does not run a login shell, so PATH is minimal and gh would not be
# found without this.
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:$HOME/.local/bin"

AIT_TOOL="${AIT_TOOL:-$HOME/.local/bin/api-integrity-tool}"
AIT_REPOS="${AIT_REPOS:-}"
AIT_ACCOUNT="${AIT_ACCOUNT:-}"
AIT_UPSTREAM="${AIT_UPSTREAM:-}"

if [[ -z "$AIT_REPOS" ]]; then
	echo "$(date '+%F %T') AIT_REPOS is not set; nothing to check."
	exit 2
fi

# The token is fetched at run time rather than baked into the plist, so it is
# never written to disk and picks up a re-auth automatically.
#
# Naming the account is not optional when more than one is configured. Bare
# `gh auth token` returns whichever account is *currently active*, so switching
# to a personal account silently hands the check a credential with no access to
# a private upstream -- and a check that cannot read the upstream reports no
# changes, which is indistinguishable from good news.
if [[ -z "${GITHUB_TOKEN:-}" ]]; then
	if [[ -n "$AIT_ACCOUNT" ]]; then
		GITHUB_TOKEN="$(gh auth token --user "$AIT_ACCOUNT" 2>/dev/null || true)"
	else
		GITHUB_TOKEN="$(gh auth token 2>/dev/null || true)"
	fi
	export GITHUB_TOKEN
fi
if [[ -z "${GITHUB_TOKEN:-}" ]]; then
	echo "$(date '+%F %T') no GitHub token${AIT_ACCOUNT:+ for $AIT_ACCOUNT}; run 'gh auth login'. Skipping."
	exit 0
fi

# Fail loudly rather than monitoring nothing.
if [[ -n "$AIT_UPSTREAM" ]]; then
	if ! GH_TOKEN="$GITHUB_TOKEN" gh api "repos/$AIT_UPSTREAM" --jq .full_name >/dev/null 2>&1; then
		echo "$(date '+%F %T') this token cannot read $AIT_UPSTREAM; not running."
		exit 1
	fi
fi

status=0
for repo in $AIT_REPOS; do
	if [[ ! -d "$repo" ]]; then
		echo "$(date '+%F %T') $repo does not exist; skipping."
		continue
	fi
	echo "=== $(date '+%F %T') $(basename "$repo") ==="
	"$AIT_TOOL" scan     --repo-path "$repo"                2>&1 | sed 's/^/  /'
	"$AIT_TOOL" check    --repo-path "$repo"                2>&1 | sed 's/^/  /' || status=$?
	"$AIT_TOOL" coverage --repo-path "$repo" --undocumented 2>&1 | sed 's/^/  /'
	echo ""
done
exit $status
