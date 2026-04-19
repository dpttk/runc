#!/bin/sh
# Test stub for bpftool. The real tool does heavy BPF map work on
# bpffs; for integration tests we just record the argv we were called
# with and pretend to succeed so scan-cap-trace-{start,stop} can run
# their full code path on hosts without bpffs (e.g. CI build agents).
set -e
log="${RUNC_STUB_BPFTOOL_LOG:-/tmp/runc-stub-bpftool.log}"
printf '%s\n' "$*" >>"$log"

# Pretend "map create" produced the pinned file so any later "ls"-style
# checks (none today, but cheap to keep) do not fail.
if [ "$1" = map ] && [ "$2" = create ]; then
	# argv 3 is the pin path
	pin=$3
	mkdir -p "$(dirname "$pin")"
	: >"$pin"
fi
exit 0
