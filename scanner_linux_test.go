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

func TestBuildCapHookScriptPrintfFormat(t *testing.T) {
	t.Parallel()
	sh := buildCapHookScript("/tmp/bundle")
	// Go fmt.Sprintf turns %% into % in the emitted shell; shell must see printf '%s'.
	if !strings.Contains(sh, `printf '%s' "$state"`) {
		t.Fatalf("missing shell printf for state; script:\n%s", sh)
	}
	if !strings.Contains(sh, `printf 'security-scan: /proc/%s/status not readable\n' "$pid"`) {
		t.Fatalf("missing shell printf for pid in error path; script:\n%s", sh)
	}
	if strings.Contains(sh, `printf '%%s'`) {
		t.Fatalf("literal %%s must not appear in shell output (would be a Go fmt bug); script:\n%s", sh)
	}
}
