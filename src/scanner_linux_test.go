package main

import (
	"strings"
	"testing"

	"github.com/opencontainers/runtime-spec/specs-go"
)

func TestSecurityScanAppArmorProfileName(t *testing.T) {
	t.Parallel()
	if g := securityScanAppArmorProfileName("my-ct"); g != "runc_scan_my_ct" {
		t.Fatalf("my-ct: got %q want runc_scan_my_ct", g)
	}
	if g := securityScanAppArmorProfileName(""); g != "runc_scan_x" {
		t.Fatalf("empty: got %q want runc_scan_x", g)
	}
	if g := securityScanAppArmorProfileName("!!!"); g != "runc_scan_x" {
		t.Fatalf("no alnum: got %q want runc_scan_x", g)
	}
	long := strings.Repeat("a", 300)
	g := securityScanAppArmorProfileName(long)
	if len(g) != 200 {
		t.Fatalf("truncation: len %d want 200", len(g))
	}
	if !strings.HasPrefix(g, "runc_scan_") {
		t.Fatalf("prefix: %q", g)
	}
}

func TestRelaxSpecForScanClearsPolicy(t *testing.T) {
	t.Parallel()
	spec := &specs.Spec{
		Linux: &specs.Linux{
			Seccomp: &specs.LinuxSeccomp{DefaultAction: specs.ActErrno},
		},
		Process: &specs.Process{
			SelinuxLabel:    "system_u:system_r:container_t:s0",
			NoNewPrivileges: true,
		},
	}
	relaxSpecForScan(spec)
	if spec.Linux.Seccomp != nil {
		t.Fatalf("seccomp must be nil after relax, got %+v", spec.Linux.Seccomp)
	}
	if spec.Process.SelinuxLabel != "" {
		t.Fatalf("selinuxLabel must be empty after relax, got %q", spec.Process.SelinuxLabel)
	}
	if spec.Process.NoNewPrivileges {
		t.Fatal("noNewPrivileges must be false after relax")
	}
}

func TestRelaxSpecForScanIsIdempotent(t *testing.T) {
	t.Parallel()
	spec := &specs.Spec{Process: &specs.Process{}}
	relaxSpecForScan(spec)
	relaxSpecForScan(spec)
	if spec.Process.NoNewPrivileges {
		t.Fatal("idempotent relax should keep nnp=false")
	}
}

func TestGrantAllCapsForScanFillsAllBuckets(t *testing.T) {
	t.Parallel()
	all := allKnownCapabilityNames()
	if len(all) == 0 {
		t.Skip("kernel reports no capabilities; nothing to assert")
	}
	for _, name := range all {
		if !strings.HasPrefix(name, "CAP_") {
			t.Fatalf("allKnownCapabilityNames returned non-CAP entry %q", name)
		}
	}
	spec := &specs.Spec{Process: &specs.Process{
		Capabilities: &specs.LinuxCapabilities{Bounding: []string{"CAP_KILL"}},
	}}
	grantAllCapsForScan(spec)
	caps := spec.Process.Capabilities
	if len(caps.Bounding) != len(all) || len(caps.Effective) != len(all) ||
		len(caps.Permitted) != len(all) || len(caps.Inheritable) != len(all) ||
		len(caps.Ambient) != len(all) {
		t.Fatalf("expected all five buckets to hold %d caps, got %d/%d/%d/%d/%d",
			len(all),
			len(caps.Bounding), len(caps.Effective), len(caps.Permitted),
			len(caps.Inheritable), len(caps.Ambient))
	}
}

func TestGrantAllCapsForScanInitialisesProcess(t *testing.T) {
	t.Parallel()
	if len(allKnownCapabilityNames()) == 0 {
		t.Skip("kernel reports no capabilities; nothing to assert")
	}
	spec := &specs.Spec{}
	grantAllCapsForScan(spec)
	if spec.Process == nil || spec.Process.Capabilities == nil {
		t.Fatal("expected Process.Capabilities to be initialised")
	}
}

func TestBuildAppArmorProfileSourceContainsName(t *testing.T) {
	t.Parallel()
	name := "runc_scan_test"
	src := buildAppArmorProfileSource(name)
	if !strings.Contains(src, "profile "+name) {
		t.Fatalf("missing profile line: %s", src)
	}
	if !strings.Contains(src, "complain") {
		t.Fatal("expected complain in flags")
	}
}

