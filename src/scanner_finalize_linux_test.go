package main

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"sort"
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

func TestFinalizeNarrowsToObservedSet(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
