#!/usr/bin/env bash
# Why each finding got the severity it did.
source "$(dirname "$0")/lib.sh"
require_setup

say "Every finding, with evidence"
run ait findings

say "The indexed calls behind them"
run ait list

note ""
note "Severity is confidence-weighted: signal prior x match quality x file"
note "weight x how much the tool trusts the call. An exact path found by parsing"
note "Go rates 0.90 and breaking; the same signal on a templated path rates"
note "lower. Grading everything breaking would make the word useless."
