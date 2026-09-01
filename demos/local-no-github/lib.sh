# Shared settings and helpers for the demo scripts. Sourced, not run.
set -uo pipefail

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Everything the demo creates lives here, so cleanup is one rm and nothing
# outside this directory is ever touched.
WORK="${AIT_DEMO_WORK:-$DEMO_DIR/.work}"
CONSUMER="$WORK/storefront"
STATE_FILE="$WORK/upstream-state"
PORT="${AIT_DEMO_PORT:-8788}"
PID_FILE="$WORK/upstream.pid"
LOG_FILE="$WORK/upstream.log"

UPSTREAM_OWNER=acmepay
UPSTREAM_NAME=api-spec
UPSTREAM_REPO="github.com/$UPSTREAM_OWNER/$UPSTREAM_NAME"
SPEC_PATH="specs/payments.yml"
VENDOR_HOST="api.acmepay.io"

# The tool insists on a token being present. Nothing authenticates against the
# local stand-in, so the value is irrelevant -- but its absence is not.
export GITHUB_TOKEN="${GITHUB_TOKEN:-local-demo-no-auth}"

# Prefer an installed binary, fall back to building from this checkout, so the
# demo works before ./install.sh has ever been run.
find_tool() {
	if [[ -n "${AIT:-}" ]]; then
		# No validation here: `exit` inside $(...) only leaves the subshell, so
		# a bad value would be swallowed. It is checked after assignment.
		echo "$AIT"; return
	fi
	if command -v api-integrity-tool >/dev/null 2>&1; then
		command -v api-integrity-tool; return
	fi
	if [[ -x "$HOME/.local/bin/api-integrity-tool" ]]; then
		echo "$HOME/.local/bin/api-integrity-tool"; return
	fi
	local built="$WORK/api-integrity-tool"
	if [[ ! -x "$built" ]]; then
		mkdir -p "$WORK"
		echo "==> building the tool from this checkout" >&2
		( cd "$DEMO_DIR/../.." && go build -o "$built" ./cmd/api-integrity-tool ) || {
			echo "could not build the tool; run ./install.sh first" >&2
			exit 1
		}
	fi
	echo "$built"
}
AIT="$(find_tool)"
if [[ -z "$AIT" || ! -x "$AIT" ]]; then
	echo "no usable api-integrity-tool binary (got '${AIT:-}')" >&2
	echo "run ./install.sh, or set AIT=/path/to/api-integrity-tool" >&2
	exit 1
fi

ait() { "$AIT" "$@" --repo-path "$CONSUMER"; }

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
note() { printf '    %s\n' "$*"; }
run()  { printf '\n\033[2m$ %s\033[0m\n' "$*"; "$@"; }

require_setup() {
	if [[ ! -d "$CONSUMER" ]]; then
		echo "run ./01-setup.sh first" >&2
		exit 1
	fi
}

upstream_running() {
	curl -fsS -m 2 "http://127.0.0.1:$PORT/repos/$UPSTREAM_OWNER/$UPSTREAM_NAME" >/dev/null 2>&1
}

require_upstream() {
	if ! upstream_running; then
		echo "the local upstream is not answering on port $PORT; run ./01-setup.sh" >&2
		exit 1
	fi
}
