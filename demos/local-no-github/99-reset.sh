#!/usr/bin/env bash
# Stop the upstream and delete everything the demo created.
source "$(dirname "$0")/lib.sh"

if [[ -f "$PID_FILE" ]]; then
	kill "$(cat "$PID_FILE")" 2>/dev/null || true
fi
# Belt and braces: only ever this demo's own server, matched by its path.
pkill -f "fake-upstream.py --port $PORT" 2>/dev/null || true

if [[ -d "$WORK" ]]; then
	rm -rf "$WORK"
	echo "removed $WORK"
else
	echo "nothing to clean"
fi
