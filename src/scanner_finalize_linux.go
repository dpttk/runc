package main

import (
	"encoding/json"
	"fmt"
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

// finalizeSecurityScan rewrites bundle/config.json's process.capabilities
// with the set actually observed during the just-finished --security-scan
// run. The semantic is "narrow only": the existing capabilities in the
// on-disk spec are NEVER unioned with the trace; whatever capable-bpfcc
// recorded is the new ground truth. An empty trace yields an empty cap
// set, which is precisely the principle of least privilege when nothing
// privileged was attempted.
//
// We deliberately ignore /proc/<pid>/status (the snapshot kept under
// generated/capabilities-from-proc-status.txt). In scan mode the
// scanner already grants every CAP_* the kernel knows about, so the
// snapshot reflects what we handed out, not what was used. The status
// file remains as a diagnostic artifact only.
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

	discovered := capSet{}
	discovered.addFromList(parseCapsFromFile(filepath.Join(genDir, scanCapTraceLogFile)))

	cfgPath := filepath.Join(bundleDir, specConfig)
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		return fmt.Errorf("security-scan finalize: read config: %w", err)
	}
	var spec specs.Spec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return fmt.Errorf("security-scan finalize: parse config: %w", err)
	}
	current := capSet{}
	if spec.Process != nil && spec.Process.Capabilities != nil {
		current.addFromList(spec.Process.Capabilities.Bounding)
	}

	if discovered.equals(current) {
		logrus.Infof("security-scan: observed cap set already matches %s (%d caps); leaving config untouched", cfgPath, discovered.len())
		return nil
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
	if len(names) == 0 {
		logrus.Infof("security-scan: trace recorded no capability checks; wrote empty cap set into %q", cfgPath)
	} else {
		logrus.Infof("security-scan: narrowed %q to %d observed capabilities: %s", cfgPath, len(names), strings.Join(names, ","))
	}
	return nil
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
