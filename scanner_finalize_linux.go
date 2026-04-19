package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/moby/sys/capability"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

var capNameRegexp = regexp.MustCompile(`\b(CAP_[A-Z0-9_]+)\b`)

// finalizeSecurityScan updates bundle/config.json with a merged capability set
// after a completed container run (no runc transport error) when --security-scan
// was used, if the merged set exceeds the reduced default baseline and differs
// from config on disk. startContainer only calls this when r.run returns nil error.
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
	discovered.addFromList(parseCapsFromFile(filepath.Join(genDir, "capable-bpfcc.log")))
	discovered.addFromList(parseCapsFromStatusFile(filepath.Join(genDir, "capabilities-from-proc-status.txt")))

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
	minimal := capSetFromList(DefaultMinimalCapabilities())
	if current.len() == 0 {
		current = minimal.clone()
	}

	// Do not shrink below what is already in config; merge traced caps in.
	out := minimal.clone()
	out.merge(discovered)
	out.merge(current)

	if out.equals(minimal) {
		return nil
	}
	if out.equals(current) {
		return nil
	}

	names := out.sortedNames()
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
	logrus.Infof("security-scan: updated %q with %d capabilities (merged trace + reduced default)", cfgPath, len(names))
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

func parseCapsFromStatusFile(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "CapBnd:") {
			return capsFromCapBndLine(line)
		}
	}
	return nil
}

func capsFromCapBndLine(line string) []string {
	i := strings.Index(line, "CapBnd:")
	if i < 0 {
		return nil
	}
	rest := line[i+len("CapBnd:"):]
	fields := strings.Fields(rest)
	lastN := 63
	if last, err := capability.LastCap(); err == nil {
		lastN = int(last)
	}
	var out []string
	for wi, f := range fields {
		v, err := strconv.ParseUint(f, 16, 64)
		if err != nil {
			continue
		}
		for bit := 0; bit < 64; bit++ {
			if v&(1<<uint(bit)) == 0 {
				continue
			}
			ci := wi*64 + bit
			if ci < 0 || ci > lastN {
				continue
			}
			out = append(out, ociCapName(capability.Cap(ci)))
		}
	}
	return out
}

type capSet map[string]struct{}

func capSetFromList(names []string) capSet {
	s := capSet{}
	s.addFromList(names)
	return s
}

func (s capSet) clone() capSet {
	t := capSet{}
	for k := range s {
		t[k] = struct{}{}
	}
	return t
}

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

func (s capSet) merge(o capSet) {
	for k := range o {
		s[k] = struct{}{}
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
