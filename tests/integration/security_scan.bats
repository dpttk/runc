#!/usr/bin/env bats

load helpers

function setup() {
	setup_busybox
}

function teardown() {
	teardown_bundle
}

@test "runc run --security-scan with stub seccomp hook writes generated artifacts" {
	[ $EUID -ne 0 ] && skip "requires root (OCI hooks)"
	update_config '.process.args = ["/bin/true"]'
	local stub="${INTEGRATION_ROOT}/../../contrib/runc-security-scan-stub-seccomp-hook.sh"
	chmod +x "$stub"
	runc run --security-scan --scan-seccomp-hook "$stub" test_sec_scan
	[ "$status" -eq 0 ]
	[ -s "$ROOT/bundle/generated/seccomp.json" ]
	[ -s "$ROOT/bundle/generated/capabilities-from-proc-status.txt" ]
	[ -s "$ROOT/bundle/generated/apparmor-README.txt" ]
}
