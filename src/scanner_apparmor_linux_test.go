package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const sampleAuditLog = `Jan 14 12:00:00 host kernel: audit: type=1400 audit(1736942412.534:11): apparmor="DENIED" operation="open" profile="runc_scan_x" name="/etc/hostname" pid=10 comm="cat" requested_mask="r" denied_mask="r" fsuid=0 ouid=0
Jan 14 12:00:01 host kernel: audit: type=1400 audit(1736942413.000:12): apparmor="DENIED" operation="open" profile="runc_scan_x" name="/etc/hostname" pid=11 comm="cat" requested_mask="r" denied_mask="r"
Jan 14 12:00:02 host kernel: audit: type=1400 audit(1736942414.000:13): apparmor="DENIED" operation="capable" profile="runc_scan_x" pid=12 comm="cat" capability=12 capname="net_admin"
Jan 14 12:00:03 host kernel: audit: type=1400 audit(1736942415.000:14): apparmor="DENIED" operation="mknod" profile="runc_scan_x" name="/var/run/foo" pid=13 comm="cat" requested_mask="c" denied_mask="c"
Jan 14 12:00:04 host kernel: audit: type=1400 audit(1736942416.000:15): apparmor="DENIED" operation="open" profile="runc_scan_other" name="/etc/shadow" pid=99 comm="cat" requested_mask="r" denied_mask="r"
Jan 14 12:00:05 host kernel: audit: type=1400 audit(1736942417.000:16): apparmor="DENIED" operation="mount" profile="runc_scan_x" name="/proc" pid=14 comm="mount"
unrelated kernel line should be ignored
`

func TestParseApparmorDenialsFiltersByProfile(t *testing.T) {
	t.Parallel()
	got := parseApparmorDenials(strings.NewReader(sampleAuditLog), "runc_scan_x")
	if len(got) != 5 {
		t.Fatalf("expected 5 records for runc_scan_x, got %d: %+v", len(got), got)
	}
	for _, r := range got {
		if r.Profile != "runc_scan_x" {
			t.Fatalf("leaked record for profile %q", r.Profile)
		}
	}
}

func TestBuildAppArmorRulesFromDenials(t *testing.T) {
	t.Parallel()
	records := parseApparmorDenials(strings.NewReader(sampleAuditLog), "runc_scan_x")
	got := buildAppArmorRulesFromDenials(records)
	want := []string{
		"  # unhandled: operation=mount name=/proc",
		"  /etc/hostname r,",
		"  /var/run/foo w,",
		"  capability net_admin,",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rules mismatch:\n got:  %#v\n want: %#v", got, want)
	}
}

func TestCanonicalAppArmorFileMode(t *testing.T) {
	t.Parallel()
	cases := []struct {
		req, denied, op string
		want            string
	}{
		{"r", "r", "open", "r"},
		{"w", "", "open", "w"},
		{"rw", "", "open", "rw"},
		{"", "r", "", "r"},
		{"", "", "open", "r"},
		{"", "", "mknod", "w"},
		{"a", "", "open", "w"},
		{"x", "", "exec", "ix"},
		{"", "", "exec", "ix"},
		{"", "", "mount", ""},
	}
	for _, c := range cases {
		if got := canonicalAppArmorFileMode(c.req, c.denied, c.op); got != c.want {
			t.Errorf("canonicalAppArmorFileMode(%q,%q,%q)=%q want %q", c.req, c.denied, c.op, got, c.want)
		}
	}
}

func TestQuoteAppArmorPath(t *testing.T) {
	t.Parallel()
	if got := quoteAppArmorPath("/etc/passwd"); got != "/etc/passwd" {
		t.Errorf("simple path: got %q", got)
	}
	if got := quoteAppArmorPath("/tmp/x y"); got != `"/tmp/x y"` {
		t.Errorf("spaced path: got %q", got)
	}
}

func TestAppendAuditRulesToProfileInsertsBlock(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	p := filepath.Join(tmpDir, "apparmor.profile")
	body := `#include <tunables/global>

profile runc_scan_x flags=(complain) {
  #include <abstractions/base>
}
`
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	rules := []string{"  /etc/hostname r,", "  capability net_admin,"}
	if err := appendAuditRulesToProfile(p, rules); err != nil {
		t.Fatalf("append: %v", err)
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	s := string(got)
	if !strings.Contains(s, apparmorAuditMarkerBegin) {
		t.Fatalf("missing begin marker:\n%s", s)
	}
	if !strings.Contains(s, apparmorAuditMarkerEnd) {
		t.Fatalf("missing end marker:\n%s", s)
	}
	if !strings.Contains(s, "/etc/hostname r,") || !strings.Contains(s, "capability net_admin,") {
		t.Fatalf("missing rules:\n%s", s)
	}
	if strings.Count(s, apparmorAuditMarkerBegin) != 1 {
		t.Fatalf("expected exactly one begin marker, got:\n%s", s)
	}
}

func TestAppendAuditRulesToProfileIsIdempotent(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	p := filepath.Join(tmpDir, "apparmor.profile")
	body := `profile runc_scan_x flags=(complain) {
  #include <abstractions/base>
}
`
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := appendAuditRulesToProfile(p, []string{"  /a r,"}); err != nil {
		t.Fatalf("first append: %v", err)
	}
	if err := appendAuditRulesToProfile(p, []string{"  /b r,"}); err != nil {
		t.Fatalf("second append: %v", err)
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	s := string(got)
	if strings.Count(s, apparmorAuditMarkerBegin) != 1 {
		t.Fatalf("expected exactly one block after second append:\n%s", s)
	}
	if strings.Contains(s, "/a r,") {
		t.Fatalf("old rules survived second append:\n%s", s)
	}
	if !strings.Contains(s, "/b r,") {
		t.Fatalf("new rules missing:\n%s", s)
	}
}

func TestAppendAuditRulesToProfileEmptyIsNoop(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	p := filepath.Join(tmpDir, "apparmor.profile")
	body := "profile runc_scan_x flags=(complain) {\n}\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := appendAuditRulesToProfile(p, nil); err != nil {
		t.Fatalf("append nil: %v", err)
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != body {
		t.Fatalf("expected unchanged file, got:\n%s", got)
	}
}
