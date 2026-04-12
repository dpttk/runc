#!/bin/sh
# Test stub: same argv contract as oci-seccomp-bpf-hook for prestart (-s).
# Consumes OCI hook JSON on stdin; writes a minimal seccomp JSON into the bundle.
set -e
case "$1" in
-s) ;;
*) exit 2 ;;
esac
state=$(cat)
# bundle path appears as "bundle":"..." in hook state JSON (runc).
bundle=$(printf '%s' "$state" | sed -n 's/.*"bundle":"\([^"]*\)".*/\1/p' | head -n1)
if [ -z "$bundle" ]; then
	bundle=$(pwd)
fi
gen="$bundle/generated"
mkdir -p "$gen"
# Minimal valid-ish profile for integration tests (allow-all default).
printf '%s\n' '{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[]}' >"$gen/seccomp.json"
