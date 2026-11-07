# OpenWrt 25.12: 1.0.2-r1, 7 November 2026

* Official SDK: OpenWrt 25.12.6 mediatek/filogic, GCC 14.3.0, musl.
  Downloaded SDK SHA-256 verified against the official release index:
  `1c04ac47bdfc361d6aab299eb520d570e368013dedcb8d29cf39dc7168ae642e`.
* 20 host native tests passed. They cover the previous measurement contract,
  slow HTTP/HTTPS headers, fixed-origin verified-HTTPS API roundtrips,
  config limits, retry bounds, DoH cache/TTL, invalid DNS/FakeIP answers after
  the first four addresses, and failure to set the bypass socket mark.
* LuCI tests passed: no server/parallelism controls; API key remains masked;
  saving drops legacy server overrides, preserves api_connect_ip and unknown
  settings, forces one target, retains atomic validation/save and narrow ACLs.
* Shell syntax and shellcheck passed for init, config helper and installer.
* Payload inspection: ELF AArch64; config mode 0600, placeholder key only;
  direct_mode true, poll interval 30, one target. Packaged LuCI matches source.
  The final compiled C source matches this branch.
* Final binary SHA-256:
  `8e0eba571cd91b7b9e58512746be431062269b1d5eeb684420b4011435c29ab5`.
  Exactly this binary was run on a physical Routerich AX3000 v1,
  RouteRich 25.12.6 RR-4.6.4, kernel 6.12.112, using temporary files only.
* Physical direct checks: example.com and api.telegram.org. Local DNS returned
  FakeIP 198.18.0.30 for api.telegram.org, while Probe DoH returned public
  149.154.166.110 and 2001:67c:4e8:f004::9. The local ZeroBlock bypass rule's
  counter increased from 170 to 259 packets during the two runs.
* example.com: verified TLS and HTTP/HTTPS 200. CPU user/system 0.21/0.01 s,
  wall time 0.95 s, maximum RSS 9396 KiB. api.telegram.org: DNS/ICMP/TCP replied,
  TLS and HTTP/HTTPS timed out; those errors remain technical observations,
  not a blocking verdict. CPU user/system 0.16/0.02 s, wall 6.46 s, RSS 9052 KiB.
  These are two one-shot measurements, not long-term daemon/load benchmarks.
* No packet capture was made on the upstream router. Its exclusion was added
  by the owner; local mark handling and public DNS were independently tested.
* Both final APKs passed apk add --simulate on the physical router. The solver
  needs only iputils-ping, libidn and the two Probe packages; no system library
  replacements. After simulation, Probe/config remained absent.
* All temporary router test files were removed. No Probe service, routes,
  firewall, ZeroBlock, DNS or system library configuration was installed/changed.
  Authenticated production polling awaits owner installation and a separate
  node key. HTTPS API roundtrips were tested against local fixtures.

The previous release validations below are historical and target 24.10.

# Версия 1.0.1-r1, 6 ноября 2026

- Собрана официальным SDK OpenWrt 24.10.6 mediatek/filogic, aarch64_cortex-a53.
- 18 дифференциальных тестов ARM64 musl через QEMU прошли. Тестируются исполняемый файл из готового IPK и отдельный harness.
- Добавлены проверки медленных HTTP и HTTPS заголовков: общий deadline не продлевается каждым фрагментом. Отдельный тест запускает этот сценарий через бинарник из IPK.
- Проверены CA/hostname TLS, публичность всех DNS-адресов, редиректы, API и прежняя конфигурация, включая api_connect_ip.
- Физический роутер в этом обновлении не изменялся. Исторические измерения ниже относятся к прежним версиям.

# Проверка 11 октября 2026

База сравнения: неизменённый Python из upstream commit
`422141a3850e078064033e60811d0d037ccf57d2`.

## Что выполнено

* C собирается GCC с `-Wall -Wextra -Werror`.
* 16 тестов на Linux x86_64: Python/C сравниваются на одинаковых локальных
  DNS/TCP/TLS/HTTP fixtures, включая ошибки/редиректы и весь обмен API.
* Те же 16 тестов прошли для **бинарника, извлечённого из готового IPK**,
  с ARM64 musl и библиотеками SDK через QEMU.
* Исходные пять Python-тестов прошли; исходный Python/installer не изменены.
* LuCI JS-тесты: скрытое поле, валидация ключа/сервера, числовые настройки,
  сохранение неизвестных полей, запись 0600, перезапуск после сохранения,
  отсутствие перезапуска/сообщения об успехе при ошибке, меню и узкий ACL.
* ShellCheck для init, helper и test runner; `git diff --check`.
* Atomic helper проверен на успешном сохранении/backup, ошибочном JSON
  и попытке записи через симлинк. При ошибке прежний конфиг сохраняется.
* Один полный сетевой fixture пройден с UndefinedBehaviorSanitizer.

SDK: официальный OpenWrt **24.10.6 mediatek/filogic**, GCC 13.3.0/musl,
`aarch64_cortex-a53`. SHA-256 загруженного SDK:
`bf9821b98fe810e2cc3ab53b8faa13bc919b9d98d703cba5e53906c17bd23864`.
Libcurl в тестовой сборке использует OpenSSL; другие зависимости взяты
из закреплённых feeds этого SDK. Ядро/прошивка роутера не изменяются.

## Размер и память

ARM64-бинарник из пакета: **65 499 байт**. Core IPK: **18 034 байта**.
LuCI IPK (`all`): **4 135 байт**.
Это без разделяемых библиотек и CA. Пакет LuCI отдельно; дополнительного
постоянного процесса для интерфейса нет.

Пять одинаковых локальных проверок, Ubuntu 24.04 x86_64:

| Клиент | Пиковая RSS, KiB | Медиана, MiB |
|---|---|---|
| C | 12864, 12896, 12984, 12812, 12896 | 12.59 |
| Python | 22936, 22832, 23064, 22908, 22840 | 22.37 |

В этих измерениях RSS включает библиотеки и тестовый shim. Для C сумма
CPU user+system округлялась до 0–0.01 секунды, для Python — 0.06–0.08.
Это сравнение на стенде, **не измерение расхода RAM/CPU Routerich**.
QEMU также не используется как источник обещаний о производительности.

## Что ещё не проверено

LuCI проверена на уровне поведения JS/helper/ACL и установки пакета,
но не просмотрена в живом браузерном интерфейсе роутера.
Ревизия r2 проверена на физическом роутере и production API — см. ниже.

Пакет рассчитан на ABI OpenWrt 24.10.6 для ARM64 Cortex-A53. Обновления
ветки 24.10 обычно сохраняют ABI, но изменения vendor feeds, TLS-библиотек
и переход на другую основную версию нужно проверять отдельно. Зависимости
устанавливаются из feeds **самого роутера**, без принудительной замены
системных библиотек из чужой прошивки.

Алгоритм обычных публичных проверок и JSON проверены на эквивалентность.
Защитные отличия, пределы размера и различия между версиями Python/TLS
описаны в README; полной буквальной эквивалентности произвольного ввода
этими тестами доказать нельзя.
# Проверка ревизии r2 на Routerich

11 октября 2026: Routerich AX3000 v1, RouteRich 24.10.6,
`aarch64_cortex-a53`, `mediatek/filogic`, ядро 6.6.127.
Установлены оба пакета `1.0.0-r2`; конфигурация и ключ сохранены.
Диагностировано соединение API с LuCI по собственному WAN IP роутера.
`api_connect_ip` направляет только API к локальному серверу,
оставляя прежние URL/Host/SNI и проверку сертификата.
Журнал реального устройства подтвердил `Received 1 checks` и
`Submitted: accepted=1 duplicates=0 rejected=0`.
Отдельная реальная проверка `example.com` подтвердила DNS и TLS,
HTTP/HTTPS 200. Служба запущена, автозапуск включён, конфиг имеет
права 0600, API-ключ совпадает с резервной копией до обновления.
16 тестов также прошли с бинарником нового IPK в ARM64 QEMU;
проверены API roundtrip с override и отказ для некорректного IP.
Тесты LuCI проверили сохранение новой настройки и прежний API-ключ.

