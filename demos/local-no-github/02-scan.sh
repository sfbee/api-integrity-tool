#!/usr/bin/env bash
# Index the outbound API calls the consumer makes.
#
# This step finds calls. It does not look at the upstream at all, and it never
# reports a breaking change -- that is `check`, in step 6.
source "$(dirname "$0")/lib.sh"
require_setup

say "Indexing the consumer's outbound calls"
run ait scan

say "What it found"
run ait list

note ""
note "Unparameterised paths score 'high'; templated ones 'medium'."
note "That difference decides severity later."
note ""
note "next: ./03-link.sh"
