package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCapableSupportsCgroupmap(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	yes := filepath.Join(dir, "capable-yes")
	no := filepath.Join(dir, "capable-no")
	if err := os.WriteFile(yes, []byte("#!/bin/sh\necho 'usage: --pid PID --cgroupmap PATH'\n"), 0o755); err != nil {
		t.Fatalf("write yes: %v", err)
	}
	if err := os.WriteFile(no, []byte("#!/bin/sh\necho 'usage: --pid PID'\n"), 0o755); err != nil {
		t.Fatalf("write no: %v", err)
	}
	if !capableSupportsCgroupmap(yes) {
		t.Fatal("expected support detection true for stub mentioning --cgroupmap")
	}
	if capableSupportsCgroupmap(no) {
		t.Fatal("expected support detection false for stub without --cgroupmap")
	}
}

func TestCgroupV2InUse(t *testing.T) {
	t.Parallel()
	got := cgroupV2InUse()
	_, statErr := os.Stat("/sys/fs/cgroup/cgroup.controllers")
	if (statErr == nil) != got {
		t.Fatalf("cgroupV2InUse=%v but cgroup.controllers stat err=%v", got, statErr)
	}
}

func TestResolveContainerCgroupV2OwnPid(t *testing.T) {
	t.Parallel()
	if !cgroupV2InUse() {
		t.Skip("requires cgroup v2 host")
	}
	path, id, err := resolveContainerCgroupV2(os.Getpid())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !strings.HasPrefix(path, "/sys/fs/cgroup/") {
		t.Fatalf("expected /sys/fs/cgroup/ prefix, got %q", path)
	}
	if id == 0 {
		t.Fatal("cgroup id must be non-zero (== inode of cgroup dir)")
	}
}

func TestResolveContainerCgroupV2InvalidPid(t *testing.T) {
	t.Parallel()
	if _, _, err := resolveContainerCgroupV2(0); err == nil {
		t.Fatal("expected error for pid=0")
	}
	if _, _, err := resolveContainerCgroupV2(-5); err == nil {
		t.Fatal("expected error for negative pid")
	}
}

// stubBpftool produces a tiny bpftool replacement that records every
// invocation into a log file under tmp. Returned path is executable
// and lives until the test cleans tmp up.
func stubBpftool(t *testing.T, tmp string) string {
	t.Helper()
	logPath := filepath.Join(tmp, "bpftool.log")
	body := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' "$*" >> %q
exit 0
`, logPath)
	p := filepath.Join(tmp, "bpftool")
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
		t.Fatalf("write stub bpftool: %v", err)
	}
	return p
}

func TestCgroupFilterMapCreateAddTeardown(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" {
		t.Skip("linux-only")
	}
	tmp := t.TempDir()
	stub := stubBpftool(t, tmp)
	pinRoot := filepath.Join(tmp, "bpf")
	m := &cgroupFilterMap{
		bpftool: stub,
		pinDir:  filepath.Join(pinRoot, "deadbeef"),
		pinPath: filepath.Join(pinRoot, "deadbeef", "cgroup_filter"),
	}
	if err := m.Create(); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := os.Stat(m.pinDir); err != nil {
		t.Fatalf("pin dir not created: %v", err)
	}
	if err := m.AddCgroup(0x0102030405060708); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := m.Teardown(); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	if _, err := os.Stat(m.pinDir); !os.IsNotExist(err) {
		t.Fatalf("pin dir should be gone after teardown, stat err=%v", err)
	}

	// Verify the bpftool stub got the right argv shape.
	logBytes, err := os.ReadFile(filepath.Join(tmp, "bpftool.log"))
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	log := string(logBytes)
	if !strings.Contains(log, "map create") || !strings.Contains(log, "type hash") {
		t.Fatalf("missing map-create call in stub log:\n%s", log)
	}
	if !strings.Contains(log, "map update pinned") {
		t.Fatalf("missing map-update call in stub log:\n%s", log)
	}
	// Cgroup id 0x0102030405060708 little-endian -> "08 07 06 05 04 03 02 01".
	if !strings.Contains(log, "08 07 06 05 04 03 02 01") {
		t.Fatalf("missing little-endian cgroup-id key bytes in stub log:\n%s", log)
	}
}
