package main

import (
	"strings"
	"testing"
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

