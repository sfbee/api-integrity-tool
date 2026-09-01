#!/usr/bin/env bash
# Run the whole demo end to end, pausing between steps.
#
# Pass --no-pause to run straight through, e.g. to capture output.
source "$(dirname "$0")/lib.sh"

pause=true
[[ "${1:-}" == "--no-pause" ]] && pause=false

for step in 01-setup 02-scan 03-link 04-baseline 05-break 06-check 07-explain; do
	"$DEMO_DIR/$step.sh" || true
	if $pause && [[ -t 0 ]]; then
		printf '\n\033[2m-- enter to continue --\033[0m'
		read -r _
	fi
done

say "Done"
note "./99-reset.sh to clean up"
