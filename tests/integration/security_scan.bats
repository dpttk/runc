#!/usr/bin/env bats

load helpers

function setup() {
	setup_busybox
}

function teardown() {
	teardown_bundle
}

@test "runc run --security-scan with stub seccomp/capable/bpftool writes generated artifacts" {
	[ $EUID -ne 0 ] && skip "requires root (OCI hooks)"
	# Default spec has terminal=true; without a real TTY (e.g. sudo from CI),
	# runc needs either -d --console-socket or terminal=false.
	update_config '.process.args = ["/bin/true"] | .process.terminal = false'
	local seccomp_stub="${INTEGRATION_ROOT}/../../contrib/runc-security-scan-stub-seccomp-hook.sh"
	local capable_stub="${INTEGRATION_ROOT}/../../contrib/runc-security-scan-stub-capable.sh"
	local bpftool_stub="${INTEGRATION_ROOT}/../../contrib/runc-security-scan-stub-bpftool.sh"
	chmod +x "$seccomp_stub" "$capable_stub" "$bpftool_stub"
	# Route the per-container BPF map pin into a tmp dir so the test
	# does not depend on bpffs being mounted on the build agent. The
	# scanner forwards RUNC_SCAN_PIN_ROOT into Hook.Env automatically.
	export RUNC_SCAN_PIN_ROOT="$BATS_TEST_TMPDIR/scan-pin"
	export RUNC_STUB_BPFTOOL_LOG="$BATS_TEST_TMPDIR/bpftool.log"
	mkdir -p "$RUNC_SCAN_PIN_ROOT"
	runc run --security-scan \
		--scan-seccomp-hook "$seccomp_stub" \
		--scan-capable "$capable_stub" \
		--scan-bpftool "$bpftool_stub" \
		test_sec_scan
	[ "$status" -eq 0 ]
	[ -s "$ROOT/bundle/generated/seccomp.json" ]
	[ -s "$ROOT/bundle/generated/capabilities-from-proc-status.txt" ]
	[ -s "$ROOT/bundle/generated/apparmor-README.txt" ]
	[ -f "$ROOT/bundle/generated/apparmor.profile" ]
	[[ "$(head -n1 "$ROOT/bundle/generated/apparmor.profile")" == "#include <tunables/global>" ]]
	# capable-bpfcc.log must mention our stub started, proving the
	# trace hook was wired and ran with --cgroupmap (see the stub).
	[ -s "$ROOT/bundle/generated/capable-bpfcc.log" ]
	grep -q "cgroupmap=" "$ROOT/bundle/generated/capable-bpfcc.log"
	# Finalize contract: the pre-scan spec is preserved and the on-disk
	# config picked up seccomp + apparmor from the generated artefacts.
	[ -s "$ROOT/bundle/generated/spec.original.json" ]
	jq -e '.linux.seccomp.defaultAction' "$ROOT/bundle/config.json" >/dev/null
	[[ "$(jq -r '.process.apparmorProfile' "$ROOT/bundle/config.json")" == runc_scan_* ]]
}

@test "runc run --security-scan narrows config.json to traced caps including children" {
	[ $EUID -ne 0 ] && skip "requires root (OCI hooks)"
	update_config '.process.args = ["/bin/true"] | .process.terminal = false'
	local seccomp_stub="${INTEGRATION_ROOT}/../../contrib/runc-security-scan-stub-seccomp-hook.sh"
	local capable_stub="${INTEGRATION_ROOT}/../../contrib/runc-security-scan-stub-capable.sh"
	local bpftool_stub="${INTEGRATION_ROOT}/../../contrib/runc-security-scan-stub-bpftool.sh"
	chmod +x "$seccomp_stub" "$capable_stub" "$bpftool_stub"
	export RUNC_SCAN_PIN_ROOT="$BATS_TEST_TMPDIR/scan-pin"
	export RUNC_STUB_BPFTOOL_LOG="$BATS_TEST_TMPDIR/bpftool.log"
	mkdir -p "$RUNC_SCAN_PIN_ROOT"
	runc run --security-scan \
		--scan-seccomp-hook "$seccomp_stub" \
		--scan-capable "$capable_stub" \
		--scan-bpftool "$bpftool_stub" \
		test_sec_scan_caps
	[ "$status" -eq 0 ]
	# The stub emits two distinct CAP_* events from two different pids
	# to simulate cgroup-wide tracing seeing both init and a child it
	# spawned; finalize must aggregate both into the narrowed set.
	local bounding
	bounding="$(jq -r '.process.capabilities.bounding | sort | join(",")' "$ROOT/bundle/config.json")"
	[ "$bounding" = "CAP_NET_BIND_SERVICE,CAP_SYS_ADMIN" ]
}

@test "runc run --security-scan rejects missing capable-bpfcc" {
	[ $EUID -ne 0 ] && skip "requires root (OCI hooks)"
	update_config '.process.args = ["/bin/true"] | .process.terminal = false'
	local seccomp_stub="${INTEGRATION_ROOT}/../../contrib/runc-security-scan-stub-seccomp-hook.sh"
	chmod +x "$seccomp_stub"
	runc run --security-scan \
		--scan-seccomp-hook "$seccomp_stub" \
		--scan-capable /no/such/capable \
		test_sec_scan_no_capable
	[ "$status" -ne 0 ]
	[[ "$output" == *"capable-bpfcc"* ]]
}
