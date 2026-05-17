package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

var capNameRegexp = regexp.MustCompile(`\b(CAP_[A-Z0-9_]+)\b`)

// Filenames under <bundle>/generated/ that the finalize step consumes
// or produces. Kept in one place so callers across the package use the
// same names (and tests target the same paths).
const (
	scanSpecOriginalFile  = "spec.original.json"
	scanSeccompFile       = "seccomp.json"
	scanAppArmorFile      = "apparmor.profile"
	apparmorProfileSuffix = ".profile"
)

// apparmorAuditMarkerBegin is written by the audit-collection step
// (scanner_apparmor_linux.go) into generated/apparmor.profile just
// before the rules it extracted from the kernel audit log. Its
// presence is the signal finalizeSecurityScan uses to flip the
// profile out of complain mode into enforce: a profile that never
// observed a denial is still a stub and must stay in complain so it
// does not break the container on the next run.
const apparmorAuditMarkerBegin = "# --- BEGIN runc-scan audit-collected rules ---"

// apparmorProfileLineRegexp captures the `profile NAME flags=(...)`
// header runc writes via buildAppArmorProfileSource. The capture
// groups are (1) the profile name and (2) the comma-separated flag
// list inside the parentheses, both used by the finalize step.
var apparmorProfileLineRegexp = regexp.MustCompile(`(?m)^profile\s+(\S+)(\s+flags=\(([^)]*)\))?\s*\{`)

// apparmorFlagsClauseRegexp matches the optional ` flags=(...)` clause
// (with its leading space) so we can drop the whole clause when the
// only flag was `complain`.
var apparmorFlagsClauseRegexp = regexp.MustCompile(`\s+flags=\(([^)]*)\)`)

// finalizeSecurityScan reconciles the bundle's on-disk config.json with
// the artefacts the just-finished --security-scan run produced under
// generated/. It performs three independent, set-difference-style
// narrowings:
//
//  1. process.capabilities is replaced with the set observed in
//     generated/capable-bpfcc.log. The trace is the ground truth; the
//     bundle's pre-scan caps are never unioned with it. An empty
//     trace yields an empty cap set.
//  2. linux.seccomp is replaced with the OCI profile recorded by
//     oci-seccomp-bpf-hook in generated/seccomp.json. Any seccomp
//     profile the bundle carried into the scan is gone: relax mode
//     wiped it in memory exactly so the trace would be complete.
//  3. process.apparmorProfile is set to the name of the generated
//     complain-mode profile so a subsequent normal `runc run` loads
//     it via ensureGeneratedProfiles. When the audit collector
//     appended rules to the profile, finalize also flips the file
//     out of complain mode into enforce.
//
// Before any of those rewrites it copies the untouched config.json
// to generated/spec.original.json (once; an existing backup is left
// alone) so the operator can always roll back to the pre-scan state.
//
// startContainer only invokes this when r.run returns nil, so partial
// runs do not silently overwrite config.json with an incomplete set.
func finalizeSecurityScan(ctx *cli.Context, action CtAct) error {
	if !ctx.Bool("security-scan") || action != CT_ACT_RUN {
		return nil
	}
	bundleDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("security-scan finalize: getwd: %w", err)
	}
	bundleDir, err = filepath.Abs(bundleDir)
	if err != nil {
		return fmt.Errorf("security-scan finalize: abs bundle: %w", err)
	}
	genDir := filepath.Join(bundleDir, "generated")
	cfgPath := filepath.Join(bundleDir, specConfig)

	if err := backupSpecOriginal(cfgPath, genDir); err != nil {
		return fmt.Errorf("security-scan finalize: backup: %w", err)
	}

	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		return fmt.Errorf("security-scan finalize: read config: %w", err)
	}
	var spec specs.Spec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return fmt.Errorf("security-scan finalize: parse config: %w", err)
	}

	capsChanged := narrowCapabilitiesFromTrace(&spec, genDir, cfgPath)
	secChanged, secErr := applyGeneratedSeccomp(&spec, genDir)
	if secErr != nil {
		logrus.Warnf("security-scan finalize: seccomp: %v", secErr)
	}
	aaChanged, aaErr := applyGeneratedAppArmor(&spec, genDir)
	if aaErr != nil {
		logrus.Warnf("security-scan finalize: apparmor: %v", aaErr)
	}

	if !capsChanged && !secChanged && !aaChanged {
		logrus.Infof("security-scan: %s already matches scan artefacts; leaving config untouched", cfgPath)
		return nil
	}

	outRaw, err := json.MarshalIndent(&spec, "", "\t")
	if err != nil {
		return fmt.Errorf("security-scan finalize: marshal: %w", err)
	}
	tmp := cfgPath + ".runc-scan.tmp"
	if err := os.WriteFile(tmp, append(outRaw, '\n'), 0o644); err != nil {
		return fmt.Errorf("security-scan finalize: write tmp: %w", err)
	}
	if err := os.Rename(tmp, cfgPath); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("security-scan finalize: rename: %w", err)
	}
	return nil
}

// backupSpecOriginal copies the untouched config.json to
// generated/spec.original.json, but only when no backup exists yet.
// The first finalize run sets the rollback target; subsequent runs
// must not overwrite it, otherwise a second scan would erase the
// pre-scan reference the operator relies on.
func backupSpecOriginal(cfgPath, genDir string) error {
	dst := filepath.Join(genDir, scanSpecOriginalFile)
	if _, err := os.Stat(dst); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat %s: %w", dst, err)
	}
	if err := os.MkdirAll(genDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", genDir, err)
	}
	src, err := os.Open(cfgPath)
	if err != nil {
		return fmt.Errorf("open %s: %w", cfgPath, err)
	}
	defer src.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	if _, err := io.Copy(out, src); err != nil {
		out.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("copy to %s: %w", tmp, err)
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename %s: %w", dst, err)
	}
	logrus.Infof("security-scan: backed up pre-scan config to %s", dst)
	return nil
}

// narrowCapabilitiesFromTrace replaces all five capability buckets
// with the names recorded by capable-bpfcc. Returns true when the
// spec changed; false means the on-disk bounding set already matched
// the trace and there is no need to rewrite the file for caps alone.
func narrowCapabilitiesFromTrace(spec *specs.Spec, genDir, cfgPath string) bool {
	discovered := capSet{}
	discovered.addFromList(parseCapsFromFile(filepath.Join(genDir, scanCapTraceLogFile)))

	current := capSet{}
	if spec.Process != nil && spec.Process.Capabilities != nil {
		current.addFromList(spec.Process.Capabilities.Bounding)
	}
	if discovered.equals(current) {
		logrus.Infof("security-scan: observed cap set already matches %s (%d caps)", cfgPath, discovered.len())
		return false
	}

	names := discovered.sortedNames()
	if spec.Process == nil {
		spec.Process = &specs.Process{}
	}
	if spec.Process.Capabilities == nil {
		spec.Process.Capabilities = &specs.LinuxCapabilities{}
	}
	spec.Process.Capabilities.Bounding = names
	spec.Process.Capabilities.Effective = names
	spec.Process.Capabilities.Permitted = names
	spec.Process.Capabilities.Inheritable = names
	spec.Process.Capabilities.Ambient = names
	if len(names) == 0 {
		logrus.Infof("security-scan: trace recorded no capability checks; writing empty cap set into %q", cfgPath)
	} else {
		logrus.Infof("security-scan: narrowed %q to %d observed capabilities: %s", cfgPath, len(names), strings.Join(names, ","))
	}
	return true
}

// applyGeneratedSeccomp parses generated/seccomp.json (the file
// oci-seccomp-bpf-hook wrote during the run) and copies it verbatim
// into spec.Linux.Seccomp. We do not merge with any pre-scan seccomp:
// relaxSpecForScan cleared the in-memory profile exactly so the trace
// would be complete, and unioning the cleared profile back in would
// silently re-introduce syscalls the workload never used.
//
// Missing or empty files are not an error - the bundle simply did not
// produce a seccomp artefact (e.g. because the hook was a stub or the
// run failed before the prestart fired) and the bundle's pre-scan
// seccomp profile, if any, stays as it was.
func applyGeneratedSeccomp(spec *specs.Spec, genDir string) (bool, error) {
	p := filepath.Join(genDir, scanSeccompFile)
	info, err := os.Stat(p)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("stat %s: %w", p, err)
	}
	if info.Size() == 0 {
		logrus.Warnf("security-scan: %s is empty; skipping seccomp finalize", p)
		return false, nil
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", p, err)
	}
	var sec specs.LinuxSeccomp
	if err := json.Unmarshal(raw, &sec); err != nil {
		return false, fmt.Errorf("parse %s: %w", p, err)
	}
	if sec.DefaultAction == "" {
		logrus.Warnf("security-scan: %s has no defaultAction; skipping seccomp finalize", p)
		return false, nil
	}
	if spec.Linux == nil {
		spec.Linux = &specs.Linux{}
	}
	spec.Linux.Seccomp = &sec
	logrus.Infof("security-scan: wired %s into linux.seccomp (defaultAction=%s, %d syscall groups)",
		p, sec.DefaultAction, len(sec.Syscalls))
	return true, nil
}

// applyGeneratedAppArmor wires the generated profile into the spec and,
// when the poststop audit-collection step recorded denials, flips the
// profile out of complain mode into enforce.
//
// The profile name is the source of truth: we parse it from the on-disk
// generated/apparmor.profile header rather than re-deriving it from the
// container id, because the file is what apparmor_parser will actually
// load on subsequent runs.
//
// Without collected rules the file stays in complain mode: a stub
// profile shipped to enforce would deny everything the workload tries
// to do that the audit collector never had a chance to record.
func applyGeneratedAppArmor(spec *specs.Spec, genDir string) (bool, error) {
	p := filepath.Join(genDir, scanAppArmorFile)
	raw, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("read %s: %w", p, err)
	}
	m := apparmorProfileLineRegexp.FindSubmatch(raw)
	if m == nil {
		return false, fmt.Errorf("apparmor profile %s has no recognisable header", p)
	}
	profileName := string(m[1])

	changed := false
	if spec.Process == nil {
		spec.Process = &specs.Process{}
	}
	if spec.Process.ApparmorProfile != profileName {
		spec.Process.ApparmorProfile = profileName
		changed = true
		logrus.Infof("security-scan: set process.apparmorProfile=%s", profileName)
	}

	if !bytes.Contains(raw, []byte(apparmorAuditMarkerBegin)) {
		logrus.Infof("security-scan: %s has no audit-collected rules; leaving profile in complain mode", p)
		return changed, nil
	}

	flipped, didFlip := flipApparmorComplainToEnforce(raw)
	if !didFlip {
		return changed, nil
	}
	tmp := p + ".runc-scan.tmp"
	if err := os.WriteFile(tmp, flipped, 0o644); err != nil {
		return changed, fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, p); err != nil {
		_ = os.Remove(tmp)
		return changed, fmt.Errorf("rename %s: %w", p, err)
	}
	logrus.Infof("security-scan: flipped %s out of complain mode (audit-collected rules present)", p)
	return changed, nil
}

// flipApparmorComplainToEnforce removes the `complain` token from the
// `flags=(...)` clause of every profile header. When complain was the
// only flag the whole clause (including its leading whitespace) is
// removed so the resulting header is `profile NAME {`, which
// apparmor_parser treats as enforce mode.
func flipApparmorComplainToEnforce(raw []byte) ([]byte, bool) {
	out := apparmorFlagsClauseRegexp.ReplaceAllFunc(raw, func(match []byte) []byte {
		sub := apparmorFlagsClauseRegexp.FindSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		parts := strings.Split(string(sub[1]), ",")
		var kept []string
		for _, part := range parts {
			t := strings.TrimSpace(part)
			if t == "" || t == "complain" {
				continue
			}
			kept = append(kept, t)
		}
		if len(kept) == 0 {
			return []byte("")
		}
		return []byte(" flags=(" + strings.Join(kept, ", ") + ")")
	})
	return out, !bytes.Equal(raw, out)
}

func parseCapsFromFile(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 {
		return nil
	}
	seen := capSet{}
	for _, m := range capNameRegexp.FindAllSubmatch(b, -1) {
		if len(m) < 2 {
			continue
		}
		seen.add(string(m[1]))
	}
	return seen.sortedNames()
}

type capSet map[string]struct{}

func (s capSet) add(name string) {
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	s[name] = struct{}{}
}

func (s capSet) addFromList(names []string) {
	for _, n := range names {
		s.add(n)
	}
}

func (s capSet) len() int { return len(s) }

func (s capSet) sortedNames() []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (s capSet) equals(o capSet) bool {
	if len(s) != len(o) {
		return false
	}
	for k := range s {
		if _, ok := o[k]; !ok {
			return false
		}
	}
	return true
}
