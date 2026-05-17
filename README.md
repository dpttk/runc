# runc (thesis fork)

Форк [opencontainers/runc](https://github.com/opencontainers/runc) для бакалаврской работы: **нулевой дефолт capabilities**, опциональные legacy-наборы и режим **`--security-scan`** для записи seccomp / AppArmor / capabilities без Kubernetes и без демона-рекордера.

Документация upstream runc: [src/README.md](src/README.md). Журнал изменений по эпикам: [.cursor/log/](.cursor/log/).

## Сборка

```bash
make
sudo make install   # → /usr/local/sbin/runc
```

Зависимости для обычной сборки — как у upstream (Debian/Ubuntu):

```bash
apt update && apt install -y make gcc linux-libc-dev libseccomp-dev pkg-config git
```

## Отличия от upstream

| Возможность | Поведение |
|-------------|-----------|
| `runc spec` | Пустой `process.capabilities` (0 caps) |
| `--default-capabilities` | 3 caps (как старый upstream `runc spec`) |
| `--default-capabilities-docker` | 14 caps (исторический Docker) |
| `--security-scan` | Режим обучения: relax → trace → артефакты в `generated/` + сужение caps в `config.json` |

Флаги `--default-capabilities` и `--default-capabilities-docker` взаимоисключающие.

## Подготовка хоста для `--security-scan`

Нужны: **cgroup v2**, **bpffs** (`/sys/fs/bpf`), **AppArmor** (опционально, но без него MAC-артефакт только файл), **oci-seccomp-bpf-hook**, **capable-bpfcc** с `--cgroupmap`, **bpftool**.

```bash
sudo script/setup-scan-host.sh
```

Скрипт ставит пакеты, монтирует bpffs, проверяет инструменты и создаёт пользователя `runcscan` (uid 65532) для рекомендуемого non-root скана.

**oci-seccomp-bpf-hook** в скрипт не входит — ставится отдельно (см. [thesis-ci-repo](https://github.com/) Ansible `scanner_host` или сборка из [containers/oci-seccomp-bpf-hook](https://github.com/containers/oci-seccomp-bpf-hook)).

## Режим сканирования

### Запуск

```bash
cd /path/to/bundle
sudo runc run --security-scan mycontainer
```

Дополнительные флаги (если автопоиск не сработал):

- `--scan-seccomp-hook PATH` — `oci-seccomp-bpf-hook` (или stub из `contrib/` для тестов)
- `--scan-capable PATH` — `capable-bpfcc` с поддержкой `--cgroupmap`
- `--scan-bpftool PATH` — `bpftool` для cgroup BPF map

Рекомендации для качественного cap-trace:

- `process.user.uid` ≠ 0 (например 65532 / `runcscan`)
- Прогнать **все** сценарии нагрузки, которые должны попасть в профиль (CI probe, e2e, ручные тесты)
- Root в контейнере не запрещён, но ядро реже вызывает `cap_capable()` для uid 0 — trace будет неполным

### Что происходит (5 фаз)

1. **Relax (только в памяти)** — снимаются `linux.seccomp`, `process.selinuxLabel`, `noNewPrivileges`; выдаются все известные CAP_*; AppArmor заменяется на complain-профиль `runc_scan_<id>`. Дисковый `config.json` не меняется.
2. **Hooks** — OCI hooks на том же бинарнике `runc` (`scan-aa-*`, `scan-cap-*`) + внешний prestart `oci-seccomp-bpf-hook`.
3. **Run** — контейнер работает, трейсеры пишут логи.
4. **Shutdown** — остановка `capable-bpfcc`, unpin BPF map.
5. **Finalize** — при успешном exit: **только** `process.capabilities` в `config.json` заменяется на наблюдённый набор (пустой trace → пустой set).

### Артефакты (`<bundle>/generated/`)

| Файл | Источник | Жизнеспособность |
|------|----------|------------------|
| `seccomp.json` | oci-seccomp-bpf-hook | **Да** — готовый OCI allow-list при полном покрытии нагрузки |
| `capable-bpfcc.log` | BCC | Сырой лог; в spec попадает после finalize |
| `apparmor.profile` | Шаблон complain + audit | **Частично** — заготовка; для enforce нужен `aa-logprof` |
| `capabilities-from-proc-status.txt` | snapshot | Только диагностика, не для finalize |
| `apparmor-load.log`, `apparmor-README.txt` | runc | Отладка / инструкция |

**SELinux:** профиль **не генерируется**. Если в bundle был `process.selinuxLabel`, он сбрасывается только на время скана, чтобы не маскировать syscalls.

### Качество подсистем

**Seccomp** — качественно, если:

- установлен настоящий `oci-seccomp-bpf-hook` (не stub);
- во время скана seccomp в spec отсутствует (relax);
- нагрузка прошла все нужные code paths.

Выход — валидный `generated/seccomp.json` в формате OCI. Stub из `contrib/runc-security-scan-stub-seccomp-hook.sh` даёт пустой allow-all профиль **только для CI smoke**.

**AppArmor** — **не готов к production enforce сразу**:

- при скане пишется минимальный профиль с `flags=(complain,…)` и `#include <abstractions/base>`;
- реальные path/file правила накапливаются в **audit log** хоста, не в файле автоматически;
- для enforce: `sudo aa-logprof` (или ручная правка) → `apparmor_parser -r` → имя профиля в `process.apparmorProfile`.

**Capabilities** — единственный механизм, который **автоматически** попадает в `config.json` после скана (replace по trace, без merge).

## Боевой запуск (enforce)

**Автоматического применения seccomp и AppArmor при обычном `runc run` нет.** После скана оператор вручную подключает профили в `config.json` (или в шаблон CI).

### Seccomp

Скопировать или встроить содержимое `generated/seccomp.json` в `linux.seccomp` bundle (поле `defaultAction`, `syscalls`, … по [runtime-spec](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#seccomp)).

Пример (структура зависит от вашего профиля):

```json
"linux": {
  "seccomp": { /* содержимое generated/seccomp.json */ }
}
```

### AppArmor

1. Доработать профиль (`aa-logprof` / редактор).
2. Установить на хост: `sudo apparmor_parser -r -W generated/apparmor.profile`
3. В `config.json`: `"process": { "apparmorProfile": "runc_scan_<id>" }` (или своё имя после переименования).

Профиль должен быть загружен в ядре **до** `runc run`.

### Capabilities

После успешного `--security-scan` `config.json` уже содержит суженный `process.capabilities`. Обычный запуск:

```bash
sudo runc run mycontainer
```

При необходимости legacy-набора: `--default-capabilities` / `--default-capabilities-docker` (не совместимы с целью «минимум прав»).

## Реализация (кратко)

| Компонент | Файлы |
|-----------|--------|
| Оркестрация скана | `src/scanner_linux.go` |
| Self-exec hooks | `src/scanner_hooks_linux.go` |
| Cgroup BPF map | `src/scanner_bpf_linux.go` |
| Finalize caps | `src/scanner_finalize_linux.go` |
| Дефолты caps | `src/utils_linux.go`, `libcontainer/specconv/example.go` |
| CLI | `src/run.go` |

Скрытые subcommands (вызываются только как OCI hooks): `scan-aa-load`, `scan-aa-unload`, `scan-cap-snapshot`, `scan-cap-trace-start`, `scan-cap-trace-stop`.

В bundle **не создаются** исполняемые скрипты — только данные под `generated/`.

## Тесты

```bash
# unit + integration (upstream)
make test

# smoke сканера (нужен root, stub hook)
sudo make localintegration TESTPATH=/security_scan.bats
```

E2E-матрица bundle'ов: репозиторий `thesis-ci-repo` (self-hosted runner, `scripts/run-scan.sh`).

## Лицензия

Apache 2.0 — как upstream ([LICENSE](LICENSE)).
