#!/usr/bin/env bash
# Record where the upstream is now, so a later change has something to diff.
source "$(dirname "$0")/lib.sh"
require_setup
require_upstream

say "First check: records the current upstream state"
run ait check

say "Coverage against the published contract"
run ait coverage

note ""
note "'No new findings' is correct -- there is nothing to compare against yet."
note "Coverage already has something to say: /v1/refunds works today but no"
note "specification promises it will keep working."
note ""
note "next: ./05-break.sh"
