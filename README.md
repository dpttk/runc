# runc (thesis fork)

A fork of [opencontainers/runc](https://github.com/opencontainers/runc) for a bachelor's thesis: **automatic generation of container security profiles** (Linux capabilities, seccomp, AppArmor) from observed workload behavior.

Upstream runc docs: [src/README.md](src/README.md). Implementation notes: [.cursor/log/](.cursor/log/).

## What this fork adds

| Area | Change |
|------|--------|
| **Default posture** | `runc spec` emits **zero** capabilities; containers start locked down unless you opt in |
| **Legacy caps** | `--default-capabilities` (3 caps, upstream) or `--default-capabilities-docker` (14 caps, Docker) — mutually exclusive |
| **`--security-scan`** | Learning mode: relax in-memory policy → trace → write narrowed profiles into `config.json` and `generated/` |

## Build

```bash
apt update && apt install -y make gcc linux-libc-dev libseccomp-dev pkg-config git
make
sudo make install   # → /usr/local/sbin/runc
```

## Capability modes

| Mode | Flag | Caps |
|------|------|------|
| Default | none | **0** |
| Upstream | `--default-capabilities` | 3 (`CAP_AUDIT_WRITE`, `CAP_KILL`, `CAP_NET_BIND_SERVICE`) |
| Docker legacy | `--default-capabilities-docker` | 14 |

```bash
runc run mycontainer                                # 0 caps
runc run --default-capabilities mycontainer         # 3 caps
runc run --default-capabilities-docker mycontainer  # 14 caps
```

## Security scan

### Host setup

Requires cgroup **v2**, **bpffs** (`/sys/fs/bpf`), **bpftool**, **capable-bpfcc** with `--cgroupmap`, **oci-seccomp-bpf-hook**, and optionally **AppArmor** (without it MAC artifacts are file-only).

```bash
sudo script/setup-scan-host.sh
```

The script installs packages, mounts bpffs, verifies tools, and creates user `runcscan` (uid/gid 65532) for non-root scans. `oci-seccomp-bpf-hook` must be installed separately ([containers/oci-seccomp-bpf-hook](https://github.com/containers/oci-seccomp-bpf-hook)).

### Run

```bash
cd /path/to/bundle
sudo runc run --security-scan mycontainer
```

Override auto-detected tool paths when needed: `--scan-seccomp-hook PATH`, `--scan-capable PATH`, `--scan-bpftool PATH` (a [contrib stub](contrib/runc-security-scan-stub-seccomp-hook.sh) exists for CI smoke).

For complete traces: run as a non-root uid (e.g. `65532`), exercise every code path the production profile must cover, and rely on cgroup-wide tracing (children in the same cgroup are included via `--cgroupmap`).

### Pipeline

1. **Relax (memory only)** — clear `linux.seccomp`, `process.selinuxLabel`, `noNewPrivileges`; grant all `CAP_*`; load complain-mode AppArmor stub `runc_scan_<id>`. On-disk `config.json` untouched until finalize.
2. **Hooks** — self-exec `runc` hooks (`scan-aa-*`, `scan-cap-*`) plus external prestart `oci-seccomp-bpf-hook`. No scripts are written into the bundle.
3. **Run** — workload executes; tracers record syscalls, capability checks, and AppArmor events.
4. **Poststop** — stop `capable-bpfcc`, unpin BPF map, collect AppArmor audit from `journalctl -k` (fallback `dmesg`).
5. **Finalize** (successful exit only) — write narrowed policy into `config.json`; back up the pre-scan spec once as `generated/spec.original.json`.

### Artifacts (`<bundle>/generated/`)

| File | Role |
|------|------|
| `seccomp.json` | OCI allow-list → `linux.seccomp` on finalize |
| `capable-bpfcc.log` | BCC trace → `process.capabilities` on finalize (replace, not merge; empty → empty) |
| `apparmor.profile` | Stub + audit rules; complain → enforce when rules were collected |
| `spec.original.json` | One-time backup of `config.json` before first finalize |
| `capabilities-from-proc-status.txt` | `/proc/<init>/status` snapshot — diagnostics only |
| `apparmor-load.log`, `apparmor-README.txt` | Load/unload logs and operator notes |
| `.runc_cap_trace.pid`, `.runc_aa_started_at` | Internal hook state |

SELinux profiles are **not** generated; an existing `process.selinuxLabel` is cleared only for the scan so tracing is not masked.

## After the scan

On success, `config.json` already has narrowed `process.capabilities`, `linux.seccomp`, and `process.apparmorProfile` set to `runc_scan_<id>`. A normal **`runc run`** then applies caps and seccomp through libcontainer; AppArmor auto-loads via `apparmor_parser -r` when the profile name starts with `runc_scan_` and matches `generated/apparmor.profile`. Roll back by restoring `generated/spec.original.json`.

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

## Tests

```bash
make test   # unit + integration (upstream)
sudo make localintegration TESTPATH=/security_scan.bats   # scanner smoke (root, stub hook)
```

## License

Apache 2.0 — same as upstream ([LICENSE](LICENSE)).
