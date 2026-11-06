# Roskompozor Probe для OpenWrt

Нативный C-клиент, без Python на роутере. Алгоритм перенесён из
`roskompozor_probe.py`. Исправление HTTP deadline сверено с Python 1.0.1,
commit `0bea899aff564d903077e4413d4b2ba7d3714968`.

Обновление существующей установки: [UPDATE.md](UPDATE.md).

## Проверки и ресурсы

* IPv4/IPv6/IDN; IDNA 2003 соответствует встроенному codec Python.
* DNS: проверка **всех** ответов на публичность, сортировка строк,
  удаление дубликатов, выбор первых четырёх адресов.
* Ping: один пакет каждому адресу, даже после успеха; результат — первый
  успешный либо последняя неудачная попытка.
* TCP: обязательные 80/443 и до восьми пользовательских портов без
  дубликатов. Порты параллельно, адреса внутри порта по очереди до успеха.
* TLS: после успеха TCP 443, с проверкой CA, имени/IP, SNI для домена,
  CN/сроком сертификата; попытки по адресам до успеха.
* HTTP/HTTPS: параллельные GET `/`, только заголовки (64 KiB), до пяти
  редиректов; каждый переход заново проверяет URL, порт и DNS, затем
  соединяется с проверенным IP. HTTP 403 считается сетевым ответом.
* Таймауты: TCP/Ping максимум 2 секунды, TLS/HTTP максимум 3 секунды;
  ограничение процесса Ping равно таймауту + 2 секунды.
* Итоговый `ok`: Ping **или** TCP 80/443 **или** HTTP/HTTPS. Дополнительный
  порт сам по себе итог не меняет. Таймаут не доказывает блокировку.
* Исходные API, Bearer-ключ, `check_id`, JSON результатов и русские summary.

Размер бинарника не равен размеру всей установки: нужны разделяемые
`libopenssl`, `libjson-c`, `libcurl`, `libidn`, CA bundle и `iputils-ping`.
OpenSSL нужен для TLS, libidn для исходного IDNA. Libcurl обслуживает API
и разбирает URL; диагностические соединения идут через собственный
SSRF-safe слой, без proxy и повторного DNS при connect.

По умолчанию одна цель одновременно. Параллельность портов и HTTP/HTTPS
внутри неё сохранена. Стеки потоков 128 KiB, в простое процесс спит.
Журнал через procd/logd, без БД и постоянных записей на flash. Низкий
`max_parallel_checks` снижает скорость обработки больших пакетов
заданий — это тот же параметр, что в Python.

## Сборка под свой роутер

Нужен **OpenWrt SDK под установленную версию и target/subtarget роутера**.
Сборка на Linux/WSL, не на роутере:

```sh
cp -r /path/to/roskompozor-probe/openwrt /path/to/sdk/package/roskompozor-probe
cp -r /path/to/roskompozor-probe/luci-app-roskompozor-probe /path/to/sdk/package/
cd /path/to/sdk
./scripts/feeds update base packages luci
./scripts/feeds install libidn libcurl iputils-ping libopenssl libjson-c ca-bundle luci-base rpcd-mod-file
make menuconfig
```

Выберите `Network -> roskompozor-probe` как `M`. Libcurl нужны HTTP и TLS;
рекомендуется OpenSSL, чтобы не тянуть второй TLS runtime. При сборке
своей прошивки можно отключить лишние протоколы libcurl. Не заменяйте
штатный libcurl другой конфигурацией поверх установленного пакета.

```sh
make defconfig
make -j4 package/roskompozor-probe/compile V=s
make -j4 package/luci-app-roskompozor-probe/compile V=s
```

Пакет появляется в `bin/packages/...`. OpenWrt 24.10 использует `.ipk`;
пакет одной архитектуры нельзя ставить на другую. В новых SDK формат
может быть `.apk` — используйте менеджер пакетов своей прошивки.

## Установка

Для OpenWrt 24.10, после копирования подходящего пакета:

```sh
opkg update
opkg install /tmp/roskompozor-probe_1.0.0-r1_АРХИТЕКТУРА.ipk
opkg install /tmp/luci-app-roskompozor-probe_1.0.0-r1_all.ipk
```

Откройте **LuCI → Службы → Roskompozor Probe**, вставьте ключ **отдельного**
узла из админки Roskompozor, отметьте автозапуск и нажмите «Сохранить и
применить». Ключ скрыт, конфиг имеет права `0600`; запись проверяется,
сохраняется одна резервная копия и файл заменяется атомарно. Интерфейс
также показывает состояние и умеет запускать/останавливать службу.

LuCI — отдельный пакет без дополнительного демона. CLI-вариант работает
без него: отредактируйте `/etc/roskompozor-probe/config.json` вручную и
включите службу командами ниже.

```sh
chmod 600 /etc/roskompozor-probe/config.json
/etc/init.d/roskompozor-probe enable
/etc/init.d/roskompozor-probe start
logread -e roskompozor-probe
```

Служба работает от root для ICMP, через procd, с `nice 10` и ограниченным
числом перезапусков. Нужны WAN, DNS и верное время для TLS.

Одна цель без API/ключа:

```sh
printf '%s\n' '{"target":"example.com","type":"domain","ports":[1380]}' >/tmp/check.json
/usr/bin/roskompozor-probe --check /tmp/check.json
```

`--once /etc/roskompozor-probe/config.json` выполняет один **настоящий**
цикл API. Не запускайте одновременно со службой с тем же ключом.

## Эквивалентность и границы

### API на сервере за этим же роутером

Если публичный IP `roskompozor.ru` совпадает с WAN-адресом роутера,
локальное обращение роутера может попасть в LuCI вместо сервера.
В LuCI укажите «IP для подключения к API», например локальный IP сервера.
В JSON это необязательное поле `api_connect_ip`. Подмена применяется
только к соединениям API: URL, Host, SNI и проверка TLS-сертификата
сохраняют имя из `server`. DNS и проверки целей не изменяются.
Пустое поле возвращает обычное разрешение имени API.

Журнал показывает `Received … checks`, `Submitted: accepted=…` и
числовой код curl при ошибке. Состояние «Работает» в LuCI означает
только наличие запущенного процесса.

```sh
# На машине разработчика; установленному клиенту Python не нужен.
sh openwrt/tests/run.sh
python3 -m unittest -v
node openwrt/tests/test_luci.cjs
```

Тесты сравнивают неизменённый Python и C на одинаковых локальных DNS,
TCP, HTTP, TLS fixtures. `netshim.so` — только тестовая библиотека,
**не включается в пакет**. Проверяются формат/попытки, IDN, смешанный DNS,
порты, HTTP 403, редиректы, сертификаты, конфиг и полный обмен с API.

Время и системный текст ошибки зависят от платформы: сравнение исключает
`ms`, `total_ms`, `error`, но сравнивает категории ошибок. TLS-наборы
зависят от сборки OpenSSL/Python и CA bundle. Политика специальных
IP закреплена по CPython 3.12.3 с обновлениями Ubuntu — между версиями
Python таблица менялась. Дополнительные защитные ограничения: отказ для
IPv6 site-local `fec0::/10`, управляющих символов HTTP path, редиректов
**API** (защита Bearer-ключа). URL ограничен 8192 байтами, API-ответ 1 MiB.
Для обычных публичных целей алгоритм сохранён; побайтовую эквивалентность
любого некорректного ввода и разных TLS-сборок заявлять нельзя.

Сборка, тесты, измерения: `VALIDATION.md`. Замеры Linux x86_64 — не замеры роутера.
