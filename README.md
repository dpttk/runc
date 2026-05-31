# runc (thesis fork)

A fork of [opencontainers/runc](https://github.com/opencontainers/runc) for a bachelor's thesis: **automatic generation of container security profiles** (Linux capabilities, seccomp, AppArmor) from observed workload behavior.

Upstream runc docs: [src/README.md](src/README.md). Implementation notes by epic: [.cursor/log/](.cursor/log/).

## What this fork adds

| Area | Change |
|------|--------|
| **Default posture** | `runc spec` emits **zero** capabilities; containers start fully locked down unless you opt in |
| **Legacy caps** | `--default-capabilities` (3 caps, upstream runc) or `--default-capabilities-docker` (14 caps, historical Docker) |
| **`--security-scan`** | Learning mode: relax in-memory policy → trace → write narrowed profiles into `config.json` and `generated/` |

The two capability flags are **mutually exclusive**.

## Build

```bash
make
sudo make install   # → /usr/local/sbin/runc
```

Debian/Ubuntu build dependencies (same as upstream):

```bash
apt update && apt install -y make gcc linux-libc-dev libseccomp-dev pkg-config git
```

## Capability modes

| Mode | How | Cap count |
|------|-----|-----------|
| Default | `runc spec` / no flags | **0** |
| Upstream runc | `--default-capabilities` | 3 (`CAP_AUDIT_WRITE`, `CAP_KILL`, `CAP_NET_BIND_SERVICE`) |
| Docker legacy | `--default-capabilities-docker` | 14 |

```bash
runc spec
runc run mycontainer                              # 0 caps
runc run --default-capabilities mycontainer       # 3 caps
runc run --default-capabilities-docker mycontainer  # 14 caps
```

## Host setup for `--security-scan`

**Required:** cgroup **v2** (unified), **bpffs** (`/sys/fs/bpf`), **AppArmor** (optional — without it MAC artifacts are file-only), **oci-seccomp-bpf-hook**, **capable-bpfcc** with `--cgroupmap`, **bpftool**.

```bash
sudo script/setup-scan-host.sh
```

The script installs packages, mounts bpffs, verifies tools, and creates system user `runcscan` (uid/gid 65532) for recommended non-root scans.

**oci-seccomp-bpf-hook** is not installed by the script — install separately ([containers/oci-seccomp-bpf-hook](https://github.com/containers/oci-seccomp-bpf-hook)) or via Ansible in [dpttk/thesis-ci-repo](https://github.com/dpttk/thesis-ci-repo) (`scanner_host` role).

## Scan mode

### Run a scan

```bash
cd /path/to/bundle
sudo runc run --security-scan mycontainer
```

Optional paths (when auto-detection fails):

| Flag | Tool |
|------|------|
| `--scan-seccomp-hook PATH` | `oci-seccomp-bpf-hook` (or [contrib stub](contrib/runc-security-scan-stub-seccomp-hook.sh) for CI smoke) |
| `--scan-capable PATH` | `capable-bpfcc` with `--cgroupmap` |
| `--scan-bpftool PATH` | `bpftool` for cgroup BPF map pin/update |

**Recommendations for complete traces:**

- Set `process.user.uid` ≠ 0 (e.g. `65532` / `runcscan`) — uid 0 rarely triggers `cap_capable()` in the kernel trace
- Exercise **all** code paths the production profile must cover (startup, shutdown, cron, DNS/TLS, error branches, etc.)
- Use cgroup-wide tracing: children in the same cgroup are included via `--cgroupmap`

### Pipeline (5 phases)

1. **Relax (in memory only)** — clears `linux.seccomp`, `process.selinuxLabel`, `noNewPrivileges`; grants all known `CAP_*`; loads a complain-mode AppArmor stub `runc_scan_<id>`. On-disk `config.json` is unchanged until finalize.
2. **Hooks** — OCI hooks on the same `runc` binary (`scan-aa-*`, `scan-cap-*`) plus external prestart `oci-seccomp-bpf-hook`.
3. **Run** — workload executes; tracers record syscalls, capability checks, and AppArmor policy events.
4. **Poststop** — stop `capable-bpfcc`, unpin BPF map; collect AppArmor audit lines from `journalctl -k` (fallback `dmesg`) into `generated/apparmor.profile`.
5. **Finalize** (successful exit only) — writes narrowed policy into `config.json` and backs up the pre-scan spec once as `generated/spec.original.json`.

### Artifacts (`<bundle>/generated/`)

| File | Role |
|------|------|
| `seccomp.json` | OCI allow-list from oci-seccomp-bpf-hook → wired into `linux.seccomp` on finalize |
| `capable-bpfcc.log` | BCC trace → `process.capabilities` on finalize (replace, not merge; empty trace → empty set) |
| `apparmor.profile` | Stub + audit-collected rules; complain → enforce when rules were collected |
| `spec.original.json` | One-time backup of `config.json` before first finalize |
| `capabilities-from-proc-status.txt` | `/proc/<init>/status` snapshot — diagnostics only |
| `apparmor-load.log`, `apparmor-README.txt` | Load/unload and operator notes |
| `.runc_cap_trace.pid`, `.runc_aa_started_at` | Internal hook state |

No executable scripts are written into the bundle — hooks are hidden `runc` subcommands (`scan-aa-load`, `scan-aa-unload`, `scan-cap-snapshot`, `scan-cap-trace-start`, `scan-cap-trace-stop`).

**SELinux:** profiles are **not** generated. An existing `process.selinuxLabel` is cleared only for the scan so tracing is not masked.

### Subsystem notes

**Seccomp** — production quality when a real `oci-seccomp-bpf-hook` is used, seccomp was relaxed during the scan, and the workload exercised all required paths. The [contrib stub](contrib/runc-security-scan-stub-seccomp-hook.sh) produces an empty allow-all profile for **CI smoke only**.

**Capabilities** — cgroup-wide via `capable-bpfcc --cgroupmap` and a pinned BPF map under `/sys/fs/bpf/runc-scan/<id>/`.

**AppArmor** — complain stub with `abstractions/base`, `nameservice`, `ssl_certs`; poststop appends rules parsed from kernel audit between sentinel markers; finalize flips to **enforce** only when audit rules were collected (otherwise complain remains so the next run does not break on an empty profile).

## After the scan (normal `runc run`)

On successful `--security-scan`, `config.json` already contains:

- narrowed `process.capabilities`
- `linux.seccomp` from `generated/seccomp.json`
- `process.apparmorProfile` pointing at `runc_scan_<id>`

A subsequent **`runc run`** (without `--security-scan`) applies caps and seccomp through libcontainer as usual. AppArmor is loaded automatically via `apparmor_parser -r` when the profile name starts with `runc_scan_` and matches `generated/apparmor.profile` (`ensureGeneratedProfiles`).

To roll back: restore from `generated/spec.original.json`.

For legacy capability sets on a fresh spec: `--default-capabilities` / `--default-capabilities-docker` (incompatible with the minimal-privilege goal).

## Implementation

| Component | Files |
|-----------|-------|
| Scan orchestration | `src/scanner_linux.go` |
| Self-exec OCI hooks | `src/scanner_hooks_linux.go` |
| Cgroup BPF map | `src/scanner_bpf_linux.go` |
| Finalize (caps, seccomp, AppArmor) | `src/scanner_finalize_linux.go` |
| AppArmor audit collection | `src/scanner_apparmor_linux.go` |
| Auto-load on normal run | `src/scanner_apply_linux.go` |
| Cap defaults / CLI wiring | `src/utils_linux.go`, `libcontainer/specconv/example.go`, `src/run.go` |
| Host provisioning | `script/setup-scan-host.sh` |
| CI stubs | `contrib/runc-security-scan-stub-*.sh` |

## Tests and CI

**This repo:**

```bash
make test   # unit + integration (upstream)

# scanner smoke (root, stub hook)
sudo make localintegration TESTPATH=/security_scan.bats
```

On push/PR, [.github/workflows/publish-runc-binary.yml](.github/workflows/publish-runc-binary.yml) builds `runc`, publishes artifact `runc-<sha>`, and dispatches `runc-build-available` to the CI repo. Details: [.cursor/log/CI.md](.cursor/log/CI.md).

**E2E matrix** ([dpttk/thesis-ci-repo](https://github.com/dpttk/thesis-ci-repo)): self-hosted runner, real `oci-seccomp-bpf-hook` + BCC, bundle matrix (`busybox-default`, `juice-shop`, …), profile verification, Object Storage upload under `scans/<runc_ref>/<run_id>/<bundle>/`.

## Related repositories

| Repo | Purpose |
|------|---------|
| [dpttk/runc](https://github.com/dpttk/runc) | This fork |
| [dpttk/thesis-ci-repo](https://github.com/dpttk/thesis-ci-repo) | Scanner E2E CI, Terraform/Ansible runner, OCI bundles |
| [opencontainers/runc](https://github.com/opencontainers/runc) | Upstream |

## License

Apache 2.0 — same as upstream ([LICENSE](LICENSE)).
