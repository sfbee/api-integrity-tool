#!/usr/bin/env bash
# Publish the vendor's 2.0.0 contract, which breaks the consumer four ways.
source "$(dirname "$0")/lib.sh"
require_setup
require_upstream

say "The vendor ships API 2.0.0"
echo after > "$STATE_FILE"
note "/v1/balance            renamed to /v1/balances"
note "POST /v1/charges       gains a required 'idempotency_key'"
note "PUT /v1/customers/{id} withdrawn"
note "/v1/refunds            now documented (good news)"

if ! curl -fsS -m 2 "http://127.0.0.1:$PORT/repos/$UPSTREAM_OWNER/$UPSTREAM_NAME" \
	| grep -q '2026-01-02'; then
	echo "the upstream did not advance; see $LOG_FILE" >&2
	exit 1
fi
note ""
note "pushed_at moved, so the change-driven check will not skip it."
note ""
note "next: ./06-check.sh"
