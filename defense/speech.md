# Текст выступления к презентации

## Слайд 1. Тема

Здравствуйте. Меня зовут Иван Платонов. Тема моей дипломной работы — генерация профилей безопасности на уровне OCI runtime. Основной объект работы — fork `runc`, который умеет автоматически строить seccomp, AppArmor и capability-профили для конкретного контейнерного workload.

## Слайд 2. Проблема

Контейнеры изолированы слабее, чем виртуальные машины, потому что они разделяют ядро хоста. Linux уже предоставляет нужные механизмы защиты: seccomp ограничивает системные вызовы, AppArmor ограничивает доступ к файловым путям, capabilities уменьшают привилегии root. Но на практике эти механизмы требуют корректных профилей. Ручное написание профилей сложно, sandbox runtimes вроде gVisor дают более сильную изоляцию ценой производительности, а cluster-side recorders требуют Kubernetes-инфраструктуры.

## Слайд 3. Research Questions

В работе были два основных вопроса. Первый: может ли runtime сам, без отдельной инфраструктуры, сгенерировать полезные профили seccomp, AppArmor и capabilities? Второй: помогает ли подход scan-then-enforce блокировать эксплуатацию command injection и улучшать containment по сравнению со stock `runc`?

## Слайд 4. Workflow

Предложенный workflow выглядит так. Разработчик запускает контейнер с флагом `--security-scan` и прогоняет репрезентативный легитимный трафик. Runtime временно ослабляет ограничения только в памяти, собирает evidence, затем пишет в bundle сгенерированные профили. После этого обычный запуск контейнера использует эти профили как стандартные OCI inputs. Важно, что исходный `config.json` не расширяется до запуска, а финализация сужает привилегии на основе наблюдений.

## Слайд 5. Реализация

Системные вызовы записываются через `oci-seccomp-bpf-hook`, capabilities — через `capable-bpfcc` с cgroup-wide tracing, чтобы видеть дочерние процессы. AppArmor работает через complain mode: во время scan собираются audit-события, потом профиль переводится в enforce mode. Все hook-команды реализованы как hidden subcommands самого runtime binary, поэтому OCI bundle не получает исполняемые helper scripts, только data artifacts.

## Слайд 6. Оценка в дипломе

В дипломе основная эмпирическая проверка была построена на Flask-приложении с намеренной command injection уязвимостью. Под stock `runc` payloads выполняли reconnaissance, чтение чувствительных файлов, reverse shell, mount probe и persistence attempts. После scan-then-enforce эти payloads блокировались, при этом легитимные ping и calendar upload продолжали работать. Дополнительная ablation-проверка показала, что даже если вручную вернуть `execve`, остальные слои всё равно ограничивают follow-on действия.

## Слайд 7. Что было сделано после отправки диплома

После отправки текста диплома были выполнены две дополнительные проверки. Первая — performance benchmark: CPU, memory, loopback network и Redis, 50 измерений после warm-up. Enforcement overhead оказался меньше 1% для CPU, memory и network, и около 5.5% для Redis. Вторая — отдельный security corpus из 22 reproducers: syscall, capability, filesystem, lateral movement, misconfiguration и scoped CVE checks. Enforced configuration заблокировала все 17 applicable attack reproducers и все 15 kernel-boundary probes; positive control при этом успешно выполнился.

## Слайд 8. Сравнение безопасности

На этом слайде видно сравнение stock `runc`, enforced hardened runtime и gVisor. Stock `runc` уже блокирует часть dangerous syscalls через Docker default seccomp, но пропускает filesystem и lateral movement сценарии. Enforced configuration блокирует все syscall, capability, filesystem и lateral probes. gVisor используется как sandbox baseline: он хорошо блокирует syscall probes, но в данном corpus тоже пропускает некоторые filesystem и misconfiguration cases. Misconfiguration row специально оставлен как limitation: runtime profiles не могут исправить `--privileged` или host namespace.

## Слайд 9. Вывод

Главный вывод: runtime-side profiling — это практичный middle ground между default `runc` и полным sandboxing. Он не заменяет gVisor как stronger isolation boundary, но заметно повышает security floor для plain OCI deployments и при этом почти не добавляет overhead на типичных workload. Оставшаяся работа — file capabilities, больше application coverage, экспорт в SPO-compatible resources и повтор бенчмарков на KVM или bare metal.

