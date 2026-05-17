package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/opencontainers/runc/libcontainer/apparmor"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

// ensureGeneratedProfiles is the counterpart to applySecurityScan for
// normal (non-scan) `runc run` and `runc create` invocations. It picks
// up artefacts a previous --security-scan run dropped under
// <bundle>/generated/ and wires them into the running kernel so the
// container starts confined without any operator action between the
// scan and the production run.
//
// Only AppArmor needs an explicit kernel load via apparmor_parser:
// finalizeSecurityScan already wrote the narrowed capability list and
// the recorded seccomp profile straight into config.json, so
// libcontainer applies those through its normal spec pipeline. The
// AppArmor profile, by contrast, is just a text file on disk until
// apparmor_parser inserts it into the kernel's policy table.
//
// All failures here are best-effort: we never block container start
// on a missing parser or a disabled LSM, only log and continue. The
// libcontainer side will surface a hard error if the spec asks for a
// profile that is not loaded by the time the init process execs.
func ensureGeneratedProfiles(spec *specs.Spec, bundleDir string) {
	path, profileName, ok := scanProfileLoadDecision(spec, bundleDir)
	if !ok {
		return
	}
	if !apparmor.IsEnabled() {
		logrus.Infof("scan-apply: %s referenced by config but AppArmor disabled on host; skipping load", profileName)
		return
	}
	parser, err := exec.LookPath("apparmor_parser")
	if err != nil {
		logrus.Warnf("scan-apply: apparmor_parser not on PATH; %s will not load", profileName)
		return
	}
	cmd := exec.Command(parser, "-r", path)
	if out, err := cmd.CombinedOutput(); err != nil {
		logrus.Warnf("scan-apply: apparmor_parser -r %s failed: %v: %s",
			path, err, strings.TrimSpace(string(out)))
		return
	}
	logrus.Infof("scan-apply: loaded AppArmor profile %s from %s", profileName, path)
}

// scanProfileLoadDecision is the side-effect-free part of
// ensureGeneratedProfiles, broken out so it can be unit-tested
// without depending on apparmor.IsEnabled or a real apparmor_parser
// on PATH. It returns the on-disk profile path, the expected profile
// name, and true when both the spec and the bundle agree that an
// auto-load is appropriate.
func scanProfileLoadDecision(spec *specs.Spec, bundleDir string) (string, string, bool) {
	if spec == nil || spec.Process == nil {
		return "", "", false
	}
	specName := strings.TrimSpace(spec.Process.ApparmorProfile)
	if specName == "" || !strings.HasPrefix(specName, "runc_scan_") {
		return "", "", false
	}
	path := filepath.Join(bundleDir, "generated", scanAppArmorFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", "", false
	}
	m := apparmorProfileLineRegexp.FindSubmatch(raw)
	if m == nil {
		return "", "", false
	}
	fileName := string(m[1])
	if fileName != specName {
		return "", "", false
	}
	return path, fileName, true
}
