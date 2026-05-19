# runc (thesis fork)

A fork of [opencontainers/runc](https://github.com/opencontainers/runc) for a bachelor's thesis: **zero default capabilities**, optional legacy capability sets, and a **`--security-scan`** mode for recording seccomp / AppArmor / capabilities without Kubernetes or a recorder daemon.

Upstream runc documentation: [src/README.md](src/README.md). Change log by epic: [.cursor/log/](.cursor/log/).

## Build

```bash
make
sudo make install   # → /usr/local/sbin/runc
```

Dependencies for a standard build are the same as upstream (Debian/Ubuntu):

```bash
apt update && apt install -y make gcc linux-libc-dev libseccomp-dev pkg-config git
```

## Differences from upstream

| Feature | Behavior |
|---------|----------|
| `runc spec` | Empty `process.capabilities` (0 caps) |
| `--default-capabilities` | 3 caps (like old upstream `runc spec`) |
| `--default-capabilities-docker` | 14 caps (historical Docker) |
| `--security-scan` | Learning mode: relax → trace → artifacts in `generated/` + cap narrowing in `config.json` |

The `--default-capabilities` and `--default-capabilities-docker` flags are mutually exclusive.

## Host setup for `--security-scan`

Required: **cgroup v2**, **bpffs** (`/sys/fs/bpf`), **AppArmor** (optional, but without it the MAC artifact is file-only), **oci-seccomp-bpf-hook**, **capable-bpfcc** with `--cgroupmap`, **bpftool**.

```bash
sudo script/setup-scan-host.sh
```

The script installs packages, mounts bpffs, verifies tools, and creates user `runcscan` (uid 65532) for the recommended non-root scan.

**oci-seccomp-bpf-hook** is not included in the script — install it separately (see [thesis-ci-repo](https://github.com/) Ansible `scanner_host` or build from [containers/oci-seccomp-bpf-hook](https://github.com/containers/oci-seccomp-bpf-hook)).

## Scan mode

### Running a scan

```bash
cd /path/to/bundle
sudo runc run --security-scan mycontainer
```

Additional flags (if auto-detection fails):

- `--scan-seccomp-hook PATH` — `oci-seccomp-bpf-hook` (or stub from `contrib/` for tests)
- `--scan-capable PATH` — `capable-bpfcc` with `--cgroupmap` support
- `--scan-bpftool PATH` — `bpftool` for cgroup BPF map

Recommendations for high-quality cap tracing:

- `process.user.uid` ≠ 0 (e.g. 65532 / `runcscan`)
- Run **all** workload scenarios that should be covered by the profile (CI probe, e2e, manual tests)
- Root inside the container is not forbidden, but the kernel rarely calls `cap_capable()` for uid 0 — the trace will be incomplete

### What happens (5 phases)

1. **Relax (in memory only)** — removes `linux.seccomp`, `process.selinuxLabel`, `noNewPrivileges`; grants all known CAP_*; AppArmor is replaced with a complain profile `runc_scan_<id>`. On-disk `config.json` is not modified.
2. **Hooks** — OCI hooks on the same `runc` binary (`scan-aa-*`, `scan-cap-*`) + external prestart `oci-seccomp-bpf-hook`.
3. **Run** — the container runs, tracers write logs.
4. **Shutdown** — stop `capable-bpfcc`, unpin BPF map.
5. **Finalize** — on successful exit: **only** `process.capabilities` in `config.json` is replaced with the observed set (empty trace → empty set).

### Artifacts (`<bundle>/generated/`)

| File | Source | Usability |
|------|--------|-----------|
| `seccomp.json` | oci-seccomp-bpf-hook | **Yes** — ready OCI allow-list with full workload coverage |
| `capable-bpfcc.log` | BCC | Raw log; applied to spec after finalize |
| `apparmor.profile` | Complain template + audit | **Partial** — draft; `aa-logprof` needed for enforce |
| `capabilities-from-proc-status.txt` | snapshot | Diagnostics only, not used for finalize |
| `apparmor-load.log`, `apparmor-README.txt` | runc | Debug / instructions |

**SELinux:** profile is **not generated**. If the bundle had `process.selinuxLabel`, it is cleared only for the duration of the scan so syscalls are not masked.

### Subsystem quality

**Seccomp** — high quality when:

- a real `oci-seccomp-bpf-hook` is installed (not stub);
- seccomp is absent from the spec during the scan (relax);
- the workload exercised all required code paths.

Output is a valid `generated/seccomp.json` in OCI format. The stub from `contrib/runc-security-scan-stub-seccomp-hook.sh` produces an empty allow-all profile **for CI smoke tests only**.

**AppArmor** — **not ready for production enforce out of the box**:

- during the scan, a minimal profile with `flags=(complain,…)` and `#include <abstractions/base>` is written;
- real path/file rules accumulate in the host **audit log**, not automatically in the file;
- for enforce: `sudo aa-logprof` (or manual editing) → `apparmor_parser -r` → profile name in `process.apparmorProfile`.

**Capabilities** — the only mechanism that **automatically** updates `config.json` after a scan (replace by trace, no merge).

## Production run (enforce)

**Seccomp and AppArmor are not applied automatically during a normal `runc run`.** After scanning, the operator manually wires profiles into `config.json` (or into a CI template).

### Seccomp

Copy or embed the contents of `generated/seccomp.json` into the bundle's `linux.seccomp` (fields `defaultAction`, `syscalls`, … per [runtime-spec](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#seccomp)).

Example (structure depends on your profile):

```json
"linux": {
  "seccomp": { /* contents of generated/seccomp.json */ }
}
```

### AppArmor

1. Refine the profile (`aa-logprof` / editor).
2. Load on the host: `sudo apparmor_parser -r -W generated/apparmor.profile`
3. In `config.json`: `"process": { "apparmorProfile": "runc_scan_<id>" }` (or your own name after renaming).

The profile must be loaded in the kernel **before** `runc run`.

### Capabilities

After a successful `--security-scan`, `config.json` already contains a narrowed `process.capabilities`. Normal run:

```bash
sudo runc run mycontainer
```

For a legacy set if needed: `--default-capabilities` / `--default-capabilities-docker` (not compatible with the "minimum privileges" goal).

## Implementation (brief)

| Component | Files |
|-----------|-------|
| Scan orchestration | `src/scanner_linux.go` |
| Self-exec hooks | `src/scanner_hooks_linux.go` |
| Cgroup BPF map | `src/scanner_bpf_linux.go` |
| Finalize caps | `src/scanner_finalize_linux.go` |
| Cap defaults | `src/utils_linux.go`, `libcontainer/specconv/example.go` |
| CLI | `src/run.go` |

Hidden subcommands (invoked only as OCI hooks): `scan-aa-load`, `scan-aa-unload`, `scan-cap-snapshot`, `scan-cap-trace-start`, `scan-cap-trace-stop`.

No executable scripts are created in the bundle — only data under `generated/`.

## Tests

```bash
# unit + integration (upstream)
make test

# scanner smoke (requires root, stub hook)
sudo make localintegration TESTPATH=/security_scan.bats
```

E2E bundle matrix: `thesis-ci-repo` repository (self-hosted runner, `scripts/run-scan.sh`).

## License

Apache 2.0 — same as upstream ([LICENSE](LICENSE)).
