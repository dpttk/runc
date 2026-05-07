package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// BPF_FS_MAGIC matches the bpffs superblock magic so we can tell if
// /sys/fs/bpf is actually a bpf filesystem rather than the regular VFS.
// Defined as 0xcafe4a11 in include/uapi/linux/magic.h.
const bpfFsMagic = 0xcafe4a11

// scanBPFPinRoot is the directory under bpffs where the scanner pins
// per-container BPF maps. It is created lazily by runScanCapTraceStart
// and removed by runScanCapTraceStop, so a clean shutdown leaves no
// stale entries on bpffs. Tests override it via RUNC_SCAN_PIN_ROOT to
// a regular tmp dir so they can exercise the create/teardown path
// against a stub bpftool without needing bpffs.
const defaultScanBPFPinRoot = "/sys/fs/bpf/runc-scan"

// scanPinRoot returns the directory the scanner should use for pinning
// the per-container BPF maps. RUNC_SCAN_PIN_ROOT exists for the
// integration test stub setup; production code never sets it.
func scanPinRoot() string {
	if v := strings.TrimSpace(os.Getenv("RUNC_SCAN_PIN_ROOT")); v != "" {
		return v
	}
	return defaultScanBPFPinRoot
}

// cgroupV2InUse reports whether the host runs the unified cgroup v2
// hierarchy. capable-bpfcc's --cgroupmap path keys the BPF map by the
// cgroup id returned from bpf_get_current_cgroup_id(), which is only
// well-defined under v2 (where cgroup_id == inode of the cgroup dir).
// Hybrid and v1 hosts must be flagged early so we never spin up a
// tracer that silently records nothing.
func cgroupV2InUse() bool {
	_, err := os.Stat("/sys/fs/cgroup/cgroup.controllers")
	return err == nil
}

// bpffsMounted reports whether /sys/fs/bpf is actually bpffs. We do
// not auto-mount it from runc; the setup script does that once at
// host provisioning time.
func bpffsMounted() bool {
	var st syscall.Statfs_t
	if err := syscall.Statfs("/sys/fs/bpf", &st); err != nil {
		return false
	}
	return uint32(st.Type) == bpfFsMagic
}

// capableSupportsCgroupmap probes the installed capable-bpfcc binary
// for the --cgroupmap option by parsing its --help output. Older
// bpfcc-tools shipped without that option and would force us back to
// per-pid filtering; we treat absence as a hard failure of the scan
// preconditions and surface a useful upgrade hint.
func capableSupportsCgroupmap(bin string) bool {
	out, _ := exec.Command(bin, "--help").CombinedOutput()
	return strings.Contains(string(out), "--cgroupmap")
}

// resolveContainerCgroupV2 reads /proc/<pid>/cgroup, extracts the v2
// path, and returns the absolute mountpoint along with the cgroup id
// (= inode of that directory in v2). The id is the very value that
// bpf_get_current_cgroup_id() returns inside the kernel, so loading
// it into the cgroupmap is exactly what makes capable-bpfcc match
// every task that lives in the cgroup, including children spawned
// after the trace started.
func resolveContainerCgroupV2(pid int) (string, uint64, error) {
	if pid <= 0 {
		return "", 0, fmt.Errorf("invalid pid %d", pid)
	}
	body, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", 0, fmt.Errorf("read /proc/%d/cgroup: %w", pid, err)
	}
	for _, line := range strings.Split(string(body), "\n") {
		if !strings.HasPrefix(line, "0::") {
			continue
		}
		rel := strings.TrimSpace(strings.TrimPrefix(line, "0::"))
		if rel == "" {
			continue
		}
		path := filepath.Join("/sys/fs/cgroup", rel)
		var st syscall.Stat_t
		if err := syscall.Stat(path, &st); err != nil {
			return "", 0, fmt.Errorf("stat cgroup %q: %w", path, err)
		}
		return path, st.Ino, nil
	}
	return "", 0, errors.New("no cgroup v2 entry (line starting with 0::) in /proc/<pid>/cgroup")
}

// cgroupFilterMap wraps the bpftool calls that create and tear down a
// per-container pinned hash<u64, u32> map under bpffs. The map exists
// solely so capable-bpfcc --cgroupmap can match the running cgroup id;
// nothing in runc itself reads the map after creation.
type cgroupFilterMap struct {
	bpftool string // absolute path to bpftool
	pinDir  string // /sys/fs/bpf/runc-scan/<container-id>
	pinPath string // pinDir + "/cgroup_filter"
}

func newCgroupFilterMap(bpftool, containerID string) *cgroupFilterMap {
	dir := filepath.Join(scanPinRoot(), containerID)
	return &cgroupFilterMap{
		bpftool: bpftool,
		pinDir:  dir,
		pinPath: filepath.Join(dir, "cgroup_filter"),
	}
}

// Create pins a fresh hash map at m.pinPath. A stale pin from a
// previous crashed run is removed first; bpftool will refuse to
// recreate over an existing pin.
func (m *cgroupFilterMap) Create() error {
	if err := os.MkdirAll(m.pinDir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", m.pinDir, err)
	}
	_ = os.Remove(m.pinPath)
	cmd := exec.Command(m.bpftool, "map", "create", m.pinPath,
		"type", "hash",
		"key", "8",
		"value", "4",
		"entries", "8",
		"name", "runc_scan_cg")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("bpftool map create %s: %w: %s", m.pinPath, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// AddCgroup inserts a single (cgroup_id, 1) entry into the pinned map.
// Value content is irrelevant - capable-bpfcc only checks key presence.
func (m *cgroupFilterMap) AddCgroup(id uint64) error {
	keyHex := make([]string, 8)
	for i := 0; i < 8; i++ {
		keyHex[i] = fmt.Sprintf("%02x", byte(id>>uint(8*i)))
	}
	args := []string{"map", "update", "pinned", m.pinPath, "key", "hex"}
	args = append(args, keyHex...)
	args = append(args, "value", "hex", "01", "00", "00", "00")
	cmd := exec.Command(m.bpftool, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("bpftool map update %s: %w: %s", m.pinPath, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Teardown removes the pin (which automatically unpins the map once
// the kernel sees the last reference go away) and the per-container
// directory. Failures are non-fatal because poststop is best-effort.
func (m *cgroupFilterMap) Teardown() error {
	if err := os.RemoveAll(m.pinDir); err != nil {
		return fmt.Errorf("remove %s: %w", m.pinDir, err)
	}
	return nil
}
