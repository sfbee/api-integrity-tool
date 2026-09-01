#!/usr/bin/env bash
# Build the demo from scratch: a consumer repository, and a local stand-in for
# the vendor's GitHub repository. Safe to re-run -- it starts clean each time.
source "$(dirname "$0")/lib.sh"

say "Cleaning any previous run"
"$DEMO_DIR/99-reset.sh" >/dev/null 2>&1 || true
mkdir -p "$WORK"

say "Creating the consumer repository at $CONSUMER"
mkdir -p "$CONSUMER"
cp "$DEMO_DIR/fixture/app.go" "$DEMO_DIR/fixture/go.mod" "$CONSUMER/"
git -C "$CONSUMER" init -q
git -C "$CONSUMER" config user.email demo@localhost
git -C "$CONSUMER" config user.name "Demo"

# Only a version. The upstream is linked with `link` in step 3, which is the
# part of the workflow worth showing -- a scan finds hosts, and deciding which
# repository is behind one is a judgement the tool cannot make for you.
cat > "$CONSUMER/.api-integrity.yml" <<YAML
version: 1

github:
  # Point at the local stand-in instead of api.github.com. Nothing in this demo
  # reaches the network.
  base_url: http://127.0.0.1:$PORT
YAML

# A scan writes an untracked .api-integrity/ into the working tree; excluding it
# keeps `git status` honest and stops a stray `git add -A` committing it.
printf '.api-integrity/\n' >> "$CONSUMER/.git/info/exclude"
git -C "$CONSUMER" add -A
git -C "$CONSUMER" commit -qm "Storefront service calling the AcmePay API"
note "committed $(git -C "$CONSUMER" rev-parse --short HEAD)"

say "Starting the local upstream on port $PORT"
echo before > "$STATE_FILE"
python3 "$DEMO_DIR/bin/fake-upstream.py" \
	--port "$PORT" --owner "$UPSTREAM_OWNER" --name "$UPSTREAM_NAME" \
	--spec-path "$SPEC_PATH" \
	--before "$DEMO_DIR/fixture/specs/v1.yml" \
	--after "$DEMO_DIR/fixture/specs/v2.yml" \
	--state "$STATE_FILE" > "$LOG_FILE" 2>&1 &
echo $! > "$PID_FILE"

for _ in $(seq 30); do
	upstream_running && break
	sleep 0.2
done
if ! upstream_running; then
	echo "the upstream failed to start; see $LOG_FILE" >&2
	exit 1
fi
note "serving $UPSTREAM_REPO, currently at API 1.4.0"
note "using tool: $AIT"

say "Ready"
note "next: ./02-scan.sh"
