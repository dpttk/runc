#!/bin/sh
# Test stub for capable-bpfcc (BCC). Mimics just enough of the real
# tool's argv contract for runc --security-scan integration tests:
#   * --help advertises --cgroupmap so capableSupportsCgroupmap() succeeds
#   * accepts --cgroupmap PATH and ignores its content
#   * blocks until SIGTERM, then exits 0 (so scan-cap-trace-stop's
#     barrier-and-kill path completes cleanly)
set -e

case "$1" in
-h|--help)
	cat <<'EOF'
stub capable-bpfcc
options:
  --cgroupmap CGROUPMAP   trace cgroups in this BPF map only
  -p PID                  trace this PID only
EOF
	exit 0
	;;
esac

trap 'exit 0' TERM INT
echo "stub-capable: started with args: $*" >&2
while true; do
	sleep 0.2
done
