package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

// ociHookState matches the OCI runtime spec hook input passed on stdin
// (Container State). Only the fields the scanner needs are decoded; the
// rest is ignored by encoding/json.
type ociHookState struct {
	OCIVersion string            `json:"ociVersion"`
	ID         string            `json:"id"`
	Status     string            `json:"status"`
	Pid        int               `json:"pid"`
	Bundle     string            `json:"bundle"`
	Annot      map[string]string `json:"annotations,omitempty"`
}

func readHookState() (*ociHookState, error) {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("read hook state: %w", err)
	}
	if len(raw) == 0 {
		return nil, errors.New("hook state is empty")
	}
	st := &ociHookState{}
	if err := json.Unmarshal(raw, st); err != nil {
		return nil, fmt.Errorf("parse hook state: %w", err)
	}
	if st.Bundle == "" {
		return nil, errors.New("hook state has no bundle")
	}
	return st, nil
}

func bundleGenDir(bundle string) (string, error) {
	dir := filepath.Join(bundle, "generated")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", dir, err)
	}
	return dir, nil
}

// Env vars used to pass parameters from the OCI hook spec into the
// hidden self-exec subcommands. Kept stable so config-on-disk does not
// break across runc versions.
const (
	envScanAAProfilePath = "RUNC_AA_PROFILE_PATH"
	envScanAALog         = "RUNC_AA_LOG"
	envScanCapableBin    = "RUNC_SCAN_CAPABLE"
	envScanBpftool       = "RUNC_SCAN_BPFTOOL"
	envScanContainerID   = "RUNC_SCAN_CONTAINER_ID"
)

// Filenames for the cap trace state and output kept under
// <bundle>/generated/. The pid file lets scan-cap-trace-stop find the
// process spawned by scan-cap-trace-start; the log gets the tracer's
// stdout+stderr.
const (
	scanCapTracePidFile = ".runc_cap_trace.pid"
	scanCapTraceLogFile = "capable-bpfcc.log"
)

// scanCapTraceStopTimeout bounds how long scan-cap-trace-stop blocks
// waiting for the tracer to exit after SIGTERM. The barrier matters
// because finalizeSecurityScan parses the log straight after this hook
// returns and we want a fully-flushed file.
const scanCapTraceStopTimeout = 2 * time.Second

// runScanAALoad implements the createRuntime hook that loads our
// generated AppArmor profile (complain mode) into the kernel via
// apparmor_parser -r. Failure is logged but never propagated: a missing
// parser must not block container start when the host happens to lack
// AppArmor userspace tooling.
func runScanAALoad() error {
	_, _ = io.Copy(io.Discard, os.Stdin)
	profile, logPath, err := requiredAAEnv()
	if err != nil {
		return err
	}
	logFile, err := openAALog(logPath)
	if err != nil {
		return err
	}
	defer logFile.Close()
	fmt.Fprintf(logFile, "---- load %s ----\n", time.Now().UTC().Format(time.RFC3339))

	parser, err := exec.LookPath("apparmor_parser")
	if err != nil {
		fmt.Fprintln(logFile, "apparmor_parser not found; skipping")
		return nil
	}
	cmd := exec.Command(parser, "-r", profile)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(logFile, "apparmor_parser -r failed (non-fatal): %v\n", err)
		return nil
	}
	fmt.Fprintln(logFile, "apparmor_parser -r ok")
	return nil
}

// runScanAAUnload mirrors runScanAALoad for the poststop hook and
// removes the profile from the kernel. As with load, the unload step is
// best-effort because container teardown must not be blocked.
func runScanAAUnload() error {
	_, _ = io.Copy(io.Discard, os.Stdin)
	profile, logPath, err := requiredAAEnv()
	if err != nil {
		return err
	}
	logFile, err := openAALog(logPath)
	if err != nil {
		return err
	}
	defer logFile.Close()
	fmt.Fprintf(logFile, "---- unload %s ----\n", time.Now().UTC().Format(time.RFC3339))

	parser, err := exec.LookPath("apparmor_parser")
	if err != nil {
		fmt.Fprintln(logFile, "apparmor_parser not found; skipping")
		return nil
	}
	cmd := exec.Command(parser, "-R", profile)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(logFile, "apparmor_parser -R failed (non-fatal): %v\n", err)
	}
	return nil
}

func requiredAAEnv() (profile, log string, err error) {
	profile = os.Getenv(envScanAAProfilePath)
	log = os.Getenv(envScanAALog)
	if profile == "" {
		return "", "", fmt.Errorf("%s not set", envScanAAProfilePath)
	}
	if log == "" {
		return "", "", fmt.Errorf("%s not set", envScanAALog)
	}
	return profile, log, nil
}

func openAALog(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	return f, nil
}

// runScanCapSnapshot is the poststart hook that captures the Cap* lines
// from /proc/<init>/status into <bundle>/generated/capabilities-from-
// proc-status.txt. It exits 0 even on partial failure: the snapshot is
// only one of several inputs to finalizeSecurityScan and a missing file
// just means the cap merge below will rely on the BCC trace.
func runScanCapSnapshot() error {
	st, err := readHookState()
	if err != nil {
		return err
	}
	gen, err := bundleGenDir(st.Bundle)
	if err != nil {
		return err
	}
	out := filepath.Join(gen, "capabilities-from-proc-status.txt")

	if st.Pid <= 0 {
		return os.WriteFile(out, []byte("security-scan: hook state had no pid\n"), 0o644)
	}
	statusPath := fmt.Sprintf("/proc/%d/status", st.Pid)
	body, err := os.ReadFile(statusPath)
	if err != nil {
		msg := fmt.Sprintf("security-scan: %s not readable: %v\n", statusPath, err)
		return os.WriteFile(out, []byte(msg), 0o644)
	}
	var lines []string
	sc := bufio.NewScanner(strings.NewReader(string(body)))
	for sc.Scan() {
		l := sc.Text()
		if strings.HasPrefix(l, "Cap") {
			lines = append(lines, l)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("scan status: %w", err)
	}
	payload := strings.Join(lines, "\n")
	if payload != "" {
		payload += "\n"
	}
	return os.WriteFile(out, []byte(payload), 0o644)
}

// runScanCapTraceStart is the poststart hook that builds the per-
// container BPF cgroup-filter map and spawns capable-bpfcc with
// --cgroupmap pointing at it, so the tracer captures cap_capable
// events for every task in the container's cgroup, including children
// spawned after start. The tracer host pid lands in <bundle>/generated/
// .runc_cap_trace.pid for scan-cap-trace-stop to find.
//
// All the preconditions (capable-bpfcc availability, --cgroupmap
// support, bpftool, cgroup v2, bpffs) have already been hard-checked
// by applySecurityScan before this hook was even installed; if any
// env var is missing here, that is a programming bug, not a runtime
// configuration issue, and the hook returns an error.
func runScanCapTraceStart() error {
	st, err := readHookState()
	if err != nil {
		return err
	}
	gen, err := bundleGenDir(st.Bundle)
	if err != nil {
		return err
	}
	logPath := filepath.Join(gen, scanCapTraceLogFile)
	pidPath := filepath.Join(gen, scanCapTracePidFile)

	bin := strings.TrimSpace(os.Getenv(envScanCapableBin))
	bpftool := strings.TrimSpace(os.Getenv(envScanBpftool))
	containerID := strings.TrimSpace(os.Getenv(envScanContainerID))
	switch {
	case bin == "":
		return fmt.Errorf("scan-cap-trace-start: %s not set", envScanCapableBin)
	case bpftool == "":
		return fmt.Errorf("scan-cap-trace-start: %s not set", envScanBpftool)
	case containerID == "":
		return fmt.Errorf("scan-cap-trace-start: %s not set", envScanContainerID)
	case st.Pid <= 0:
		return fmt.Errorf("scan-cap-trace-start: hook state had no pid")
	}

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open trace log: %w", err)
	}
	defer logFile.Close()

	cgPath, cgID, err := resolveContainerCgroupV2(st.Pid)
	if err != nil {
		return fmt.Errorf("scan-cap-trace-start: resolve cgroup: %w", err)
	}
	fmt.Fprintf(logFile, "---- start %s pid=%d cgroup=%s id=%d via %s ----\n",
		time.Now().UTC().Format(time.RFC3339), st.Pid, cgPath, cgID, bin)

	m := newCgroupFilterMap(bpftool, containerID)
	if err := m.Create(); err != nil {
		return fmt.Errorf("scan-cap-trace-start: %w", err)
	}
	if err := m.AddCgroup(cgID); err != nil {
		_ = m.Teardown()
		return fmt.Errorf("scan-cap-trace-start: %w", err)
	}

	cmd := exec.Command(bin, "--cgroupmap", m.pinPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		_ = m.Teardown()
		return fmt.Errorf("scan-cap-trace-start: spawn capable-bpfcc: %w", err)
	}
	tracerPid := cmd.Process.Pid
	if err := cmd.Process.Release(); err != nil {
		logrus.Warnf("scan-cap-trace-start: release tracer pid %d: %v", tracerPid, err)
	}

	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(tracerPid)+"\n"), 0o644); err != nil {
		return fmt.Errorf("write pid file: %w", err)
	}
	fmt.Fprintf(logFile, "scan-cap-trace-start: tracer pid=%d cgroupmap=%s\n", tracerPid, m.pinPath)
	return nil
}

// runScanCapTraceStop is the poststop hook that shuts down the tracer
// previously started by runScanCapTraceStart and removes its pinned
// cgroup-filter map from bpffs. It is also the barrier that
// finalizeSecurityScan relies on: by the time this hook returns, the
// tracer has exited and capable-bpfcc.log is closed, so the cap merge
// that runs straight after sees a complete file.
//
// Pid-file absence (e.g. start hook never ran, or already cleaned up)
// is treated as a no-op so we do not break container teardown when
// the tracer never came up.
func runScanCapTraceStop() error {
	st, err := readHookState()
	if err != nil {
		return err
	}
	gen, err := bundleGenDir(st.Bundle)
	if err != nil {
		return err
	}
	pidPath := filepath.Join(gen, scanCapTracePidFile)
	logPath := filepath.Join(gen, scanCapTraceLogFile)
	defer os.Remove(pidPath)

	containerID := strings.TrimSpace(os.Getenv(envScanContainerID))
	bpftool := strings.TrimSpace(os.Getenv(envScanBpftool))
	defer func() {
		if containerID == "" || bpftool == "" {
			return
		}
		if err := newCgroupFilterMap(bpftool, containerID).Teardown(); err != nil {
			appendTraceLog(logPath, fmt.Sprintf("scan-cap-trace-stop: teardown map: %v", err))
		}
	}()

	raw, err := os.ReadFile(pidPath)
	if err != nil {
		return nil
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 0 {
		appendTraceLog(logPath, fmt.Sprintf("scan-cap-trace-stop: bad pid file %q", string(raw)))
		return nil
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return nil
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		appendTraceLog(logPath, fmt.Sprintf("scan-cap-trace-stop: SIGTERM pid=%d: %v", pid, err))
		return nil
	}
	deadline := time.Now().Add(scanCapTraceStopTimeout)
	for time.Now().Before(deadline) {
		if err := proc.Signal(syscall.Signal(0)); err != nil {
			appendTraceLog(logPath, fmt.Sprintf("scan-cap-trace-stop: tracer pid=%d exited", pid))
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := proc.Signal(syscall.SIGKILL); err != nil {
		appendTraceLog(logPath, fmt.Sprintf("scan-cap-trace-stop: SIGKILL pid=%d: %v", pid, err))
	} else {
		appendTraceLog(logPath, fmt.Sprintf("scan-cap-trace-stop: SIGKILL sent to pid=%d after %s", pid, scanCapTraceStopTimeout))
	}
	return nil
}

func appendTraceLog(path, msg string) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		logrus.Warnf("scan-cap-trace: append %s: %v", path, err)
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s\n", time.Now().UTC().Format(time.RFC3339), msg)
}


// Internal OCI hook subcommands used by --security-scan. These are hidden
// from --help and are invoked as Hook.Path = <runc binary> with the runc
// argv carrying the subcommand name. Each one reads the OCI hook state
// JSON from stdin (per OCI runtime spec hooks); subcommands that don't
// need it still drain stdin so the runtime never blocks on a write.

var scanAALoadHookCommand = cli.Command{
	Name:   "scan-aa-load",
	Usage:  "internal: load AppArmor profile generated by --security-scan (createRuntime hook)",
	Hidden: true,
	Action: func(ctx *cli.Context) error {
		return runScanAALoad()
	},
}

var scanAAUnloadHookCommand = cli.Command{
	Name:   "scan-aa-unload",
	Usage:  "internal: unload AppArmor profile generated by --security-scan (poststop hook)",
	Hidden: true,
	Action: func(ctx *cli.Context) error {
		return runScanAAUnload()
	},
}

var scanCapSnapshotHookCommand = cli.Command{
	Name:   "scan-cap-snapshot",
	Usage:  "internal: snapshot /proc/<pid>/status Cap* lines for --security-scan (poststart hook)",
	Hidden: true,
	Action: func(ctx *cli.Context) error {
		return runScanCapSnapshot()
	},
}

var scanCapTraceStartHookCommand = cli.Command{
	Name:   "scan-cap-trace-start",
	Usage:  "internal: spawn external capable-bpfcc trace for --security-scan (poststart hook)",
	Hidden: true,
	Action: func(ctx *cli.Context) error {
		return runScanCapTraceStart()
	},
}

var scanCapTraceStopHookCommand = cli.Command{
	Name:   "scan-cap-trace-stop",
	Usage:  "internal: stop the capable-bpfcc trace started by --security-scan (poststop hook)",
	Hidden: true,
	Action: func(ctx *cli.Context) error {
		return runScanCapTraceStop()
	},
}
