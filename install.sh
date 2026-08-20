#!/bin/bash
# Build api-integrity-tool and install it, optionally registering it as an MCP
# server for Claude Code and scheduling periodic upstream checks.
#
# The tool indexes the outbound API calls a repository makes, links each API
# host to the upstream repository behind it, and reports upstream changes that
# would break those calls.
set -euo pipefail

cd "$(dirname "$0")"

BIN_NAME="api-integrity-tool"
DEFAULT_PREFIX="/usr/local/bin"
FALLBACK_PREFIX="$HOME/.local/bin"
LAUNCH_LABEL="com.stephen.api-integrity-tool.check"
PLIST_DEST="$HOME/Library/LaunchAgents/${LAUNCH_LABEL}.plist"
MIN_GO_MINOR=27

PREFIX=""
DO_MCP=""
DO_SCHEDULE=""
SCHEDULE_INTERVAL=21600   # 6 hours
SCHEDULE_REPO=""
UNINSTALL=""

usage() {
	cat <<'USAGE'
usage: ./install.sh [options]

  --prefix DIR         install into DIR (default: /usr/local/bin, falling back
                       to ~/.local/bin when that is not writable)
  --mcp                register the MCP server with Claude Code
  --no-mcp             skip MCP registration without being asked
  --schedule REPO      install a launchd job that periodically checks REPO
  --interval SECONDS   how often the scheduled check runs (default: 21600)
  --uninstall          remove the binary, the launchd job and the MCP entry
  -h, --help           show this message

With no options, and attached to a terminal, the script asks about MCP
registration and scheduling. Non-interactively it installs the binary only.
USAGE
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--prefix) PREFIX="${2:?--prefix needs a directory}"; shift 2 ;;
		--mcp) DO_MCP="yes"; shift ;;
		--no-mcp) DO_MCP="no"; shift ;;
		--schedule) DO_SCHEDULE="${2:?--schedule needs a repository path}"; SCHEDULE_REPO="$2"; shift 2 ;;
		--interval) SCHEDULE_INTERVAL="${2:?--interval needs seconds}"; shift 2 ;;
		--uninstall) UNINSTALL="yes"; shift ;;
		-h|--help) usage; exit 0 ;;
		*) echo "unknown option: $1" >&2; usage; exit 1 ;;
	esac
done

# ---------------------------------------------------------------- uninstall

if [[ -n "$UNINSTALL" ]]; then
	echo "==> Uninstalling $BIN_NAME"
	if [[ -f "$PLIST_DEST" ]]; then
		launchctl bootout "gui/$(id -u)" "$PLIST_DEST" 2>/dev/null || true
		rm -f "$PLIST_DEST"
		echo "    removed the scheduled check"
	fi
	if command -v claude >/dev/null 2>&1; then
		claude mcp remove api-integrity 2>/dev/null && echo "    removed the MCP registration" || true
	fi
	removed=""
	for dir in "$DEFAULT_PREFIX" "$FALLBACK_PREFIX" ${PREFIX:+"$PREFIX"}; do
		if [[ -f "$dir/$BIN_NAME" ]]; then
			rm -f "$dir/$BIN_NAME" 2>/dev/null || sudo rm -f "$dir/$BIN_NAME"
			echo "    removed $dir/$BIN_NAME"
			removed="yes"
		fi
	done
	[[ -n "$removed" ]] || echo "    no installed binary found"
	echo ""
	echo "Per-repository state in .api-integrity/ was left alone; delete those"
	echo "directories yourself if you want them gone."
	exit 0
fi

# ------------------------------------------------------------------- checks

echo "==> Checking prerequisites"
if ! command -v go >/dev/null 2>&1; then
	echo "Go is required but was not found on PATH." >&2
	echo "Install it from https://go.dev/dl/ and run this again." >&2
	exit 1
fi

GO_VERSION="$(go env GOVERSION 2>/dev/null || echo unknown)"
GO_MINOR="$(printf '%s' "$GO_VERSION" | sed -n 's/^go1\.\([0-9]*\).*/\1/p')"
if [[ -z "$GO_MINOR" ]] || (( GO_MINOR < MIN_GO_MINOR )); then
	echo "Go 1.${MIN_GO_MINOR} or newer is required (go.mod declares it); found ${GO_VERSION}." >&2
	echo "With GOTOOLCHAIN=auto the Go tool can fetch it for you; otherwise upgrade Go." >&2
	exit 1
fi
echo "    ${GO_VERSION}"

# ------------------------------------------------------------------- prompts

# Only ask when a human is actually there. Prompting from a pipe or a CI job
# hangs the run, so the non-interactive path picks documented defaults instead.
if [[ -z "$DO_MCP" ]]; then
	if [[ -t 0 && -t 1 ]]; then
		if command -v claude >/dev/null 2>&1; then
			read -r -p "Register as an MCP server for Claude Code? [Y/n]: " reply
			case "${reply:-y}" in [nN]*) DO_MCP="no" ;; *) DO_MCP="yes" ;; esac
		else
			DO_MCP="no"
		fi
	else
		echo "    no terminal attached; skipping MCP registration (use --mcp to force it)"
		DO_MCP="no"
	fi
fi

if [[ -z "$DO_SCHEDULE" && -t 0 && -t 1 ]]; then
	read -r -p "Install a scheduled upstream check for a repository? [path, or empty to skip]: " reply
	if [[ -n "${reply:-}" ]]; then
		DO_SCHEDULE="yes"
		SCHEDULE_REPO="$reply"
	fi
fi

# --------------------------------------------------------------------- build

echo "==> Building $BIN_NAME"
# CGO is off deliberately: the whole program is pure Go, and a static binary is
# far easier to install and cross-compile.
CGO_ENABLED=0 go build -trimpath -o "$BIN_NAME" ./cmd/api-integrity-tool
echo "    built $(./"$BIN_NAME" version)"

echo "==> Running tests"
if go test ./... >/tmp/api-integrity-install-test.log 2>&1; then
	echo "    all packages pass"
else
	echo "    tests FAILED; see /tmp/api-integrity-install-test.log" >&2
	echo "    refusing to install a build whose tests do not pass" >&2
	exit 1
fi

# ------------------------------------------------------------------- install

if [[ -z "$PREFIX" ]]; then
	if [[ -w "$DEFAULT_PREFIX" ]]; then
		PREFIX="$DEFAULT_PREFIX"
	else
		PREFIX="$FALLBACK_PREFIX"
		echo "==> $DEFAULT_PREFIX is not writable; using $PREFIX"
	fi
fi

echo "==> Installing to $PREFIX"
mkdir -p "$PREFIX"
if ! install -m 0755 "$BIN_NAME" "$PREFIX/$BIN_NAME" 2>/dev/null; then
	echo "    need elevated permissions to write $PREFIX"
	sudo install -m 0755 "$BIN_NAME" "$PREFIX/$BIN_NAME"
fi
INSTALLED="$PREFIX/$BIN_NAME"
echo "    installed $INSTALLED"

case ":$PATH:" in
	*":$PREFIX:"*) ;;
	*)
		echo ""
		echo "    NOTE: $PREFIX is not on your PATH. Add this to your shell profile:"
		echo "      export PATH=\"$PREFIX:\$PATH\""
		;;
esac

# --------------------------------------------------------------- MCP register

if [[ "$DO_MCP" == "yes" ]]; then
	echo "==> Registering the MCP server"
	if command -v claude >/dev/null 2>&1; then
		if claude mcp add api-integrity -- "$INSTALLED" mcp 2>/dev/null; then
			echo "    registered as \"api-integrity\""
		else
			echo "    could not register automatically. Add it yourself with:"
			echo "      claude mcp add api-integrity -- $INSTALLED mcp"
		fi
	else
		echo "    the claude CLI was not found; register it later with:"
		echo "      claude mcp add api-integrity -- $INSTALLED mcp"
	fi
fi

# ------------------------------------------------------------------ schedule

if [[ -n "$DO_SCHEDULE" && -n "$SCHEDULE_REPO" ]]; then
	REPO_ABS="$(cd "$SCHEDULE_REPO" 2>/dev/null && pwd || true)"
	if [[ -z "$REPO_ABS" ]]; then
		echo "==> Skipping the scheduled check: $SCHEDULE_REPO is not a directory" >&2
	else
		echo "==> Installing a scheduled check every $((SCHEDULE_INTERVAL / 60)) minutes"
		mkdir -p "$HOME/Library/LaunchAgents"
		cat > "$PLIST_DEST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>${LAUNCH_LABEL}</string>
	<key>ProgramArguments</key>
	<array>
		<string>${INSTALLED}</string>
		<string>check</string>
		<string>--repo-path</string>
		<string>${REPO_ABS}</string>
	</array>
	<key>StartInterval</key>
	<integer>${SCHEDULE_INTERVAL}</integer>
	<key>RunAtLoad</key>
	<false/>
	<key>StandardOutPath</key>
	<string>${REPO_ABS}/.api-integrity/check.log</string>
	<key>StandardErrorPath</key>
	<string>${REPO_ABS}/.api-integrity/check.err.log</string>
</dict>
</plist>
PLIST
		mkdir -p "$REPO_ABS/.api-integrity"
		launchctl bootout "gui/$(id -u)" "$PLIST_DEST" 2>/dev/null || true
		launchctl bootstrap "gui/$(id -u)" "$PLIST_DEST"
		echo "    scheduled; logs at $REPO_ABS/.api-integrity/check.log"
		echo "    a scheduled check needs a GitHub token in the launchd environment:"
		echo "      launchctl setenv GITHUB_TOKEN \"\$(gh auth token)\""
	fi
fi

# ---------------------------------------------------------------- next steps

echo ""
echo "==> Done. Next steps, from inside a repository you want to watch:"
echo ""
echo "      $BIN_NAME scan            # index its outbound API calls"
echo "      $BIN_NAME list            # see what it found"
echo "      $BIN_NAME link-hosts      # link API hosts to upstream repositories"
echo "      $BIN_NAME check           # look for breaking upstream changes"
echo "      $BIN_NAME --view-results  # open the dashboard on :6969"
echo ""
echo "    Run \`$BIN_NAME doctor\` to check configuration and credentials."

if ! "$INSTALLED" doctor --repo-path "$PWD" 2>/dev/null | grep -q "github token: found"; then
	echo ""
	echo "    NOTE: no GitHub token was found. Everything except \`check\` works"
	echo "          without one. To enable upstream checks, run:"
	echo "            gh auth login"
	echo "          or export GITHUB_TOKEN=..."
fi
