package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/urfave/cli"
)

func TestParseCapsFromFile(t *testing.T) {
	t.Parallel()
	tmp := filepath.Join(t.TempDir(), "log")
	body := `12:00:00 0 100 cmd 21 CAP_SYS_ADMIN 1
12:00:01 0 100 cmd 21 CAP_SYS_ADMIN 1
12:00:02 0 100 cmd 6 CAP_NET_BIND_SERVICE 1
some other text mentioning CAP_KILL inline
`
	if err := os.WriteFile(tmp, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := parseCapsFromFile(tmp)
	want := []string{"CAP_KILL", "CAP_NET_BIND_SERVICE", "CAP_SYS_ADMIN"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestParseCapsFromFileMissing(t *testing.T) {
	t.Parallel()
	if got := parseCapsFromFile(filepath.Join(t.TempDir(), "nope.log")); got != nil {
		t.Fatalf("expected nil for missing file, got %v", got)
	}
}

// runFinalizeWithDir invokes finalizeSecurityScan with the cli flag set
// and Getwd pointed at the supplied bundle. The chdir is restored even
// on test failure so other parallel-safe tests are not perturbed.
func runFinalizeWithDir(t *testing.T, bundleDir string) error {
	t.Helper()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(bundleDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.Bool("security-scan", true, "")
	if err := fs.Parse([]string{"--security-scan"}); err != nil {
		t.Fatalf("flagset parse: %v", err)
	}
	ctx := cli.NewContext(nil, fs, nil)
	return finalizeSecurityScan(ctx, CT_ACT_RUN)
}

func writeBundle(t *testing.T, capsBounding []string, traceLog string) string {
	t.Helper()
	bundle := t.TempDir()
	if err := os.MkdirAll(filepath.Join(bundle, "generated"), 0o755); err != nil {
		t.Fatalf("mkdir generated: %v", err)
	}
	spec := specs.Spec{Process: &specs.Process{}}
	if capsBounding != nil {
		spec.Process.Capabilities = &specs.LinuxCapabilities{
			Bounding:    append([]string(nil), capsBounding...),
			Effective:   append([]string(nil), capsBounding...),
			Permitted:   append([]string(nil), capsBounding...),
			Inheritable: append([]string(nil), capsBounding...),
			Ambient:     append([]string(nil), capsBounding...),
		}
	}
	raw, err := json.MarshalIndent(&spec, "", "\t")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(bundle, specConfig), raw, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if traceLog != "" {
		if err := os.WriteFile(filepath.Join(bundle, "generated", scanCapTraceLogFile), []byte(traceLog), 0o644); err != nil {
			t.Fatalf("write trace log: %v", err)
		}
	}
	return bundle
}

func readBoundingCaps(t *testing.T, bundle string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(bundle, specConfig))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var s specs.Spec
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("parse config: %v", err)
	}
	if s.Process == nil || s.Process.Capabilities == nil {
		return nil
	}
	out := append([]string(nil), s.Process.Capabilities.Bounding...)
	sort.Strings(out)
	return out
}

// Tests that drive finalizeSecurityScan must run serially: the helper
// rebinds process-wide os.Getwd via os.Chdir, so t.Parallel() across
// them races on a shared cwd. Pure-function tests above stay parallel.

func TestFinalizeNarrowsToObservedSet(t *testing.T) {
	traceLog := "12:00:00 0 1 cmd 6 CAP_NET_BIND_SERVICE 1\n"
	bundle := writeBundle(t, []string{"CAP_KILL", "CAP_NET_ADMIN", "CAP_NET_BIND_SERVICE"}, traceLog)

	if err := runFinalizeWithDir(t, bundle); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	got := readBoundingCaps(t, bundle)
	want := []string{"CAP_NET_BIND_SERVICE"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected narrowing to %v, got %v", want, got)
	}
}

func TestFinalizeWritesEmptyOnEmptyTrace(t *testing.T) {
	bundle := writeBundle(t, []string{"CAP_NET_ADMIN"}, "")

	if err := runFinalizeWithDir(t, bundle); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	got := readBoundingCaps(t, bundle)
	if len(got) != 0 {
		t.Fatalf("expected empty cap set, got %v", got)
	}
}

func TestFinalizeNoOpWhenAlreadyExact(t *testing.T) {
	traceLog := "12:00:00 0 1 cmd 6 CAP_NET_BIND_SERVICE 1\n"
	bundle := writeBundle(t, []string{"CAP_NET_BIND_SERVICE"}, traceLog)

	cfg := filepath.Join(bundle, specConfig)
	beforeStat, err := os.Stat(cfg)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if err := runFinalizeWithDir(t, bundle); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	afterStat, err := os.Stat(cfg)
	if err != nil {
		t.Fatalf("stat after: %v", err)
	}
	if !beforeStat.ModTime().Equal(afterStat.ModTime()) {
		t.Fatalf("config.json was rewritten when discovered set already matched")
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readSpec(t *testing.T, bundle string) specs.Spec {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(bundle, specConfig))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var s specs.Spec
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("parse config: %v", err)
	}
	return s
}

func TestFinalizeWritesBackup(t *testing.T) {
	bundle := writeBundle(t, []string{"CAP_KILL"}, "")
	originalRaw, err := os.ReadFile(filepath.Join(bundle, specConfig))
	if err != nil {
		t.Fatalf("read original: %v", err)
	}

	if err := runFinalizeWithDir(t, bundle); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	backup := filepath.Join(bundle, "generated", scanSpecOriginalFile)
	got, err := os.ReadFile(backup)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if !bytes.Equal(got, originalRaw) {
		t.Fatalf("backup content drifted from original config")
	}
}

func TestFinalizeBackupIsIdempotent(t *testing.T) {
	bundle := writeBundle(t, []string{"CAP_KILL"}, "")

	if err := runFinalizeWithDir(t, bundle); err != nil {
		t.Fatalf("first finalize: %v", err)
	}
	backup := filepath.Join(bundle, "generated", scanSpecOriginalFile)
	sentinel := []byte("frozen-pre-scan\n")
	if err := os.WriteFile(backup, sentinel, 0o644); err != nil {
		t.Fatalf("rewrite backup: %v", err)
	}
	if err := runFinalizeWithDir(t, bundle); err != nil {
		t.Fatalf("second finalize: %v", err)
	}
	got, err := os.ReadFile(backup)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if !bytes.Equal(got, sentinel) {
		t.Fatalf("backup overwritten on second finalize: %q", string(got))
	}
}

func TestFinalizeAppliesSeccomp(t *testing.T) {
	bundle := writeBundle(t, []string{"CAP_KILL"}, "")
	seccomp := `{
  "defaultAction": "SCMP_ACT_ERRNO",
  "syscalls": [
    {"names": ["read","write"], "action": "SCMP_ACT_ALLOW"}
  ]
}`
	writeFile(t, filepath.Join(bundle, "generated", scanSeccompFile), seccomp)

	if err := runFinalizeWithDir(t, bundle); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	s := readSpec(t, bundle)
	if s.Linux == nil || s.Linux.Seccomp == nil {
		t.Fatalf("expected linux.seccomp to be populated, got %+v", s.Linux)
	}
	if s.Linux.Seccomp.DefaultAction != "SCMP_ACT_ERRNO" {
		t.Fatalf("unexpected defaultAction: %q", s.Linux.Seccomp.DefaultAction)
	}
	if len(s.Linux.Seccomp.Syscalls) != 1 || len(s.Linux.Seccomp.Syscalls[0].Names) != 2 {
		t.Fatalf("syscall groups not preserved: %+v", s.Linux.Seccomp.Syscalls)
	}
}

func TestFinalizeIgnoresEmptySeccomp(t *testing.T) {
	bundle := writeBundle(t, []string{"CAP_KILL"}, "")
	writeFile(t, filepath.Join(bundle, "generated", scanSeccompFile), "")

	if err := runFinalizeWithDir(t, bundle); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	s := readSpec(t, bundle)
	if s.Linux != nil && s.Linux.Seccomp != nil {
		t.Fatalf("expected no seccomp wired from empty file, got %+v", s.Linux.Seccomp)
	}
}

func TestFinalizeRejectsSeccompWithoutDefaultAction(t *testing.T) {
	bundle := writeBundle(t, []string{"CAP_KILL"}, "")
	writeFile(t, filepath.Join(bundle, "generated", scanSeccompFile), `{"syscalls": []}`)

	if err := runFinalizeWithDir(t, bundle); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	s := readSpec(t, bundle)
	if s.Linux != nil && s.Linux.Seccomp != nil {
		t.Fatalf("expected no seccomp wired without defaultAction")
	}
}

func TestFinalizeAppliesAppArmorProfileName(t *testing.T) {
	bundle := writeBundle(t, []string{"CAP_KILL"}, "")
	profile := `#include <tunables/global>

profile runc_scan_my_ct flags=(complain, attach_disconnected, mediate_deleted) {
  #include <abstractions/base>
}
`
	writeFile(t, filepath.Join(bundle, "generated", scanAppArmorFile), profile)

	if err := runFinalizeWithDir(t, bundle); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	s := readSpec(t, bundle)
	if s.Process == nil || s.Process.ApparmorProfile != "runc_scan_my_ct" {
		t.Fatalf("expected apparmorProfile=runc_scan_my_ct, got %+v", s.Process)
	}
}

func TestFinalizeKeepsComplainWithoutAuditMarker(t *testing.T) {
	bundle := writeBundle(t, []string{"CAP_KILL"}, "")
	profile := `#include <tunables/global>

profile runc_scan_x flags=(complain, attach_disconnected, mediate_deleted) {
  #include <abstractions/base>
}
`
	profilePath := filepath.Join(bundle, "generated", scanAppArmorFile)
	writeFile(t, profilePath, profile)

	if err := runFinalizeWithDir(t, bundle); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	got, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatalf("read profile: %v", err)
	}
	if !strings.Contains(string(got), "flags=(complain") {
		t.Fatalf("expected profile to stay in complain mode without audit marker, got:\n%s", got)
	}
}

func TestFinalizeFlipsComplainOnAuditMarker(t *testing.T) {
	bundle := writeBundle(t, []string{"CAP_KILL"}, "")
	profile := `#include <tunables/global>

profile runc_scan_x flags=(complain, attach_disconnected, mediate_deleted) {
  #include <abstractions/base>
  # --- BEGIN runc-scan audit-collected rules ---
  /etc/hostname r,
  # --- END runc-scan audit-collected rules ---
}
`
	profilePath := filepath.Join(bundle, "generated", scanAppArmorFile)
	writeFile(t, profilePath, profile)

	if err := runFinalizeWithDir(t, bundle); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	got, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatalf("read profile: %v", err)
	}
	if strings.Contains(string(got), "complain") {
		t.Fatalf("expected complain to be removed after audit marker, got:\n%s", got)
	}
	if !strings.Contains(string(got), "flags=(attach_disconnected, mediate_deleted)") {
		t.Fatalf("expected remaining flags to be preserved, got:\n%s", got)
	}
}

func TestFinalizeFlipDropsEmptyFlagsClause(t *testing.T) {
	t.Parallel()
	raw := []byte("profile runc_scan_x flags=(complain) {\n}\n")
	got, changed := flipApparmorComplainToEnforce(raw)
	if !changed {
		t.Fatalf("expected change when only flag was complain")
	}
	want := "profile runc_scan_x {\n}\n"
	if string(got) != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
