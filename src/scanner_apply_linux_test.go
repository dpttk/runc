package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/opencontainers/runtime-spec/specs-go"
)

func writeProfile(t *testing.T, bundle string, body string) {
	t.Helper()
	gen := filepath.Join(bundle, "generated")
	if err := os.MkdirAll(gen, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gen, scanAppArmorFile), []byte(body), 0o644); err != nil {
		t.Fatalf("write profile: %v", err)
	}
}

func TestScanProfileLoadDecisionMatch(t *testing.T) {
	t.Parallel()
	bundle := t.TempDir()
	writeProfile(t, bundle, "profile runc_scan_xx flags=(complain) {\n}\n")
	spec := &specs.Spec{Process: &specs.Process{ApparmorProfile: "runc_scan_xx"}}

	path, name, ok := scanProfileLoadDecision(spec, bundle)
	if !ok {
		t.Fatalf("expected load decision true")
	}
	if name != "runc_scan_xx" {
		t.Fatalf("name: got %q", name)
	}
	if filepath.Base(path) != scanAppArmorFile {
		t.Fatalf("path: got %q", path)
	}
}

func TestScanProfileLoadDecisionMismatchedName(t *testing.T) {
	t.Parallel()
	bundle := t.TempDir()
	writeProfile(t, bundle, "profile runc_scan_other flags=(complain) {\n}\n")
	spec := &specs.Spec{Process: &specs.Process{ApparmorProfile: "runc_scan_xx"}}

	if _, _, ok := scanProfileLoadDecision(spec, bundle); ok {
		t.Fatalf("expected no load when spec name does not match file header")
	}
}

func TestScanProfileLoadDecisionNoFile(t *testing.T) {
	t.Parallel()
	bundle := t.TempDir()
	spec := &specs.Spec{Process: &specs.Process{ApparmorProfile: "runc_scan_xx"}}

	if _, _, ok := scanProfileLoadDecision(spec, bundle); ok {
		t.Fatalf("expected no load when file is missing")
	}
}

func TestScanProfileLoadDecisionNonScanProfile(t *testing.T) {
	t.Parallel()
	bundle := t.TempDir()
	writeProfile(t, bundle, "profile docker-default flags=(complain) {\n}\n")
	spec := &specs.Spec{Process: &specs.Process{ApparmorProfile: "docker-default"}}

	if _, _, ok := scanProfileLoadDecision(spec, bundle); ok {
		t.Fatalf("expected no load for non-runc_scan_ profile")
	}
}

func TestScanProfileLoadDecisionEmptySpec(t *testing.T) {
	t.Parallel()
	bundle := t.TempDir()
	writeProfile(t, bundle, "profile runc_scan_xx flags=(complain) {\n}\n")

	if _, _, ok := scanProfileLoadDecision(nil, bundle); ok {
		t.Fatalf("expected no load for nil spec")
	}
	if _, _, ok := scanProfileLoadDecision(&specs.Spec{}, bundle); ok {
		t.Fatalf("expected no load for spec without process")
	}
	if _, _, ok := scanProfileLoadDecision(&specs.Spec{Process: &specs.Process{}}, bundle); ok {
		t.Fatalf("expected no load for spec without apparmorProfile")
	}
}
