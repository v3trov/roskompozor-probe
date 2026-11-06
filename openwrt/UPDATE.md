# Обновление до 1.0.1-r1

Для OpenWrt/RouteRich 24.10 на aarch64_cortex-a53, включая сборку для Routerich AX3000. Перед установкой можно проверить архитектуру командой `opkg print-architecture`.

Обновляется только roskompozor-probe. Существующий пакет LuCI, настройки, ключ и api_connect_ip сохраняются. Файл config.json объявлен conffile в IPK; команды дополнительно сохраняют его копию в /root и проверяют сохранность после установки.

В консоли роутера от root:

```sh
(
set -e
pkg=roskompozor-probe_1.0.1-r1_aarch64_cortex-a53.ipk
cd /tmp
wget -O "$pkg" "https://github.com/v3trov/roskompozor-probe/releases/download/openwrt-v1.0.1-r1/$pkg"
printf '%s  %s\n' '0c7e614a5f861138bc19179a14293b0f88460531762e2d97ab710f5b09577954' "$pkg" | sha256sum -c -
backup="/root/roskompozor-probe-$(date +%Y%m%d-%H%M%S).json"
cp -p /etc/roskompozor-probe/config.json "$backup"
opkg install "/tmp/$pkg"
cmp -s "$backup" /etc/roskompozor-probe/config.json || cp -p "$backup" /etc/roskompozor-probe/config.json
/etc/init.d/roskompozor-probe restart
opkg status roskompozor-probe | grep '^Version:'
logread -e roskompozor-probe | tail -n 15
)
```

Ожидаемая версия: `1.0.1-r1`. Работающий обмен подтверждают сообщения `Received … checks` и `Submitted: accepted=… rejected=0`. Сразу после перезапуска журнал может ещё содержать старые строки.

При ошибке архитектуры или зависимостей остановитесь на сообщении opkg; параметры force не требуются. Для другой основной версии прошивки нужен подходящий пакет. На физическом роутере новая версия пока не устанавливалась: проверены x86_64 и ARM64 musl под QEMU, включая бинарник из готового IPK.
