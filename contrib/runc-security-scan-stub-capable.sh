#!/bin/sh
# Test stub for capable-bpfcc (BCC). Mimics just enough of the real
# tool's argv contract for runc --security-scan integration tests:
#   * --help advertises --cgroupmap so capableSupportsCgroupmap() succeeds
#   * accepts --cgroupmap PATH and ignores its content
#   * emits two fake CAP_* events on stdout so finalize has something
#     to narrow config.json down to. The two pid columns differ to
#     simulate the cgroup-wide trace observing both the container's
#     init process and a child it spawned; the real tool would do this
#     by hooking cap_capable across every task in the cgroup.
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
echo "12:00:00 0 100 init   10 CAP_NET_BIND_SERVICE 1"
echo "12:00:01 0 200 child  21 CAP_SYS_ADMIN 1"
while true; do
	sleep 0.2
done
