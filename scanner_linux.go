package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

const traceSyscallAnnotation = "io.containers.trace-syscall"

var defaultSeccompHookPaths = []string{
	"/usr/libexec/oci/hooks.d/oci-seccomp-bpf-hook",
	"/usr/local/libexec/oci/hooks.d/oci-seccomp-bpf-hook",
}

const appArmorReadme = `AppArmor profile generation (manual follow-up)
==============================================

This bundle was created with runc --security-scan. Automatic syscall tracing is
handled by oci-seccomp-bpf-hook (see generated/seccomp.json). AppArmor profiles
are not inferred automatically from one run.

Suggested workflow on hosts with AppArmor:

1. Pick a profile name, e.g. "runc-<container-id>".
2. Put the container (or host binary) under complain mode while exercising
   tests: use aa-genprof / aa-logprof as documented for your distribution.
3. Convert learnings into a snippet suitable for your OCI runtime (process
   or mount AppArmor profile fields).

For file-level tracing, combine audit logs with aa-logprof; optional tools
such as opensnoop (BCC) can complement syscall tracing.
`

func applySecurityScan(spec *specs.Spec, ctx *cli.Context) error {
	if !ctx.Bool("security-scan") {
		return nil
	}
	bundleDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("security-scan: getwd: %w", err)
	}
	bundleDir, err = filepath.Abs(bundleDir)
	if err != nil {
		return fmt.Errorf("security-scan: abs bundle: %w", err)
	}
	genDir := filepath.Join(bundleDir, "generated")
	if err := os.MkdirAll(genDir, 0o755); err != nil {
		return fmt.Errorf("security-scan: mkdir generated: %w", err)
	}

	hookPath := strings.TrimSpace(ctx.String("scan-seccomp-hook"))
	if hookPath == "" {
		for _, p := range defaultSeccompHookPaths {
			if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
				hookPath = p
				logrus.Infof("security-scan: using seccomp hook %q", hookPath)
				break
			}
		}
	}
	if hookPath == "" {
		return fmt.Errorf("security-scan: no oci-seccomp-bpf-hook found; install it or pass --scan-seccomp-hook PATH (e.g. contrib stub for tests)")
	}
	hookPath, err = filepath.Abs(hookPath)
	if err != nil {
		return fmt.Errorf("security-scan: abs hook path: %w", err)
	}
	st, err := os.Stat(hookPath)
	if err != nil {
		return fmt.Errorf("security-scan: stat seccomp hook: %w", err)
	}
	if st.IsDir() || st.Mode()&0o111 == 0 {
		return fmt.Errorf("security-scan: seccomp hook must be an executable file: %s", hookPath)
	}

	seccompOut := filepath.Join(genDir, "seccomp.json")
	annotation := "of:" + seccompOut
	if spec.Annotations == nil {
		spec.Annotations = map[string]string{}
	}
	if prev, ok := spec.Annotations[traceSyscallAnnotation]; ok && prev != annotation {
		logrus.Warnf("security-scan: overwriting annotation %q (was %q)", traceSyscallAnnotation, prev)
	}
	spec.Annotations[traceSyscallAnnotation] = annotation

	if spec.Hooks == nil {
		spec.Hooks = &specs.Hooks{}
	}
	secHook := specs.Hook{
		Path: hookPath,
		Args: []string{filepath.Base(hookPath), "-s"},
	}
	spec.Hooks.Prestart = append(spec.Hooks.Prestart, secHook)

	capScriptPath := filepath.Join(genDir, ".runc_cap_hook.sh")
	capBody := buildCapHookScript(bundleDir)
	if err := os.WriteFile(capScriptPath, []byte(capBody), 0o755); err != nil {
		return fmt.Errorf("security-scan: write poststart cap hook: %w", err)
	}
	spec.Hooks.Poststart = append(spec.Hooks.Poststart, specs.Hook{
		Path: capScriptPath,
		Args: []string{filepath.Base(capScriptPath)},
	})

	aaPath := filepath.Join(genDir, "apparmor-README.txt")
	if err := os.WriteFile(aaPath, []byte(appArmorReadme), 0o644); err != nil {
		return fmt.Errorf("security-scan: write apparmor readme: %w", err)
	}

	logrus.Infof("security-scan: bundle %q; artifacts under %s", bundleDir, genDir)
	return nil
}

func shellSingleQuote(s string) string {
	return `'` + strings.ReplaceAll(s, `'`, `'\''`) + `'`
}

func buildCapHookScript(bundleDir string) string {
	q := shellSingleQuote(bundleDir)
	return fmt.Sprintf(`#!/bin/sh
set -e
state=$(cat)
bundle=%s
gen="$bundle/generated"
mkdir -p "$gen"
pid=$(printf '%%s' "$state" | sed -n 's/.*"pid": *\([0-9][0-9]*\).*/\1/p' | head -n1)
if [ -z "$pid" ]; then
  printf 'security-scan: could not parse pid from hook state\n' >>"$gen/capabilities-from-proc-status.txt"
  exit 0
fi
if [ -r "/proc/$pid/status" ]; then
  grep '^Cap' "/proc/$pid/status" >"$gen/capabilities-from-proc-status.txt" || true
else
  printf 'security-scan: /proc/%%s/status not readable\n' "$pid" >"$gen/capabilities-from-proc-status.txt"
fi
`, q)
}
