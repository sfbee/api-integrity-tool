#!/usr/bin/env bash
# The payoff: detect the change and grade it.
source "$(dirname "$0")/lib.sh"
require_setup
require_upstream

say "Checking the upstream"
run ait check --fail-on breaking
code=$?

say "Coverage after the change"
run ait coverage

note ""
note "check exited $code."
if (( code == 0 )); then
	note ""
	note "Zero, because --fail-on gates on findings this run *discovered*, and"
	note "these were already recorded. Re-running is not a fresh verdict."
	note "This is the trap when wiring it into CI: a job that clones fresh every"
	note "time never fails, because its first check is always a baseline."
	note "Add --force to re-analyse the window, or gate on standing state:"
	note "  findings --format json | jq -e '[.[]|select(.status==\"open\" and .severity==\"breaking\")]|length==0'"
else
	note "Non-zero means a finding at breaking or above was discovered, which is"
	note "how you gate CI."
fi
note ""
note "Coverage moved in both directions: /v1/refunds became documented so its"
note "finding was retracted, while /v1/balance is now an undocumented call."
note ""
note "next: ./07-explain.sh, or ./99-reset.sh to start over"
