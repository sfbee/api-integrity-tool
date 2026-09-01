#!/usr/bin/env bash
# Attach the host to the repository that publishes its contract.
#
# A scan finds hosts. Which repository sits behind one is a judgement only you
# can make, and this is where you make it.
source "$(dirname "$0")/lib.sh"
require_setup

say "Hosts found by the scan, before linking"
run ait hosts

say "What still needs an upstream"
run ait link-hosts

note ""
note "The suggestion is guessed from the hostname and is wrong here -- which is"
note "the normal case. A vendor's API rarely lives at a repo named after its domain."

say "Linking it explicitly"
run ait link "$VENDOR_HOST" --repo "$UPSTREAM_REPO" --ref main --role spec_only \
	--note "vendor publishes the contract here"

say "Confirm"
run ait upstreams
run ait link-hosts

note ""
note "SOURCE says 'cli': this link lives in local state. Declaring it under"
note "upstreams: in .api-integrity.yml instead would show 'config' -- use that"
note "when the decision should be shared with the team through version control."
note ""
note "next: ./04-baseline.sh"
