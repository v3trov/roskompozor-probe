# Roskompozor Probe 2.0

```sh
t=$(mktemp) && curl -fsSL https://raw.githubusercontent.com/v3trov/roskompozor-probe/main/install.sh -o "$t" && sudo sh "$t"; rm -f "$t"
```

От root: замените `sudo sh` на `sh`. OpenWrt 24.10 с opkg поддерживается этим же
установщиком. Linux: systemd или OpenRC, Python 3.9+. Недостающие зависимости
устанавливаются автоматически. API-ключ вводится скрыто; каждому узлу нужен
отдельный ключ из админки сайта. При обновлении существующий ключ сохраняется.

```sh
systemctl status roskompozor-probe-next
journalctl -u roskompozor-probe-next -f
```

OpenWrt: `/etc/init.d/roskompozor-probe-next status`, журнал — `logread`.
OpenRC: `rc-service roskompozor-probe-next status`.

Конфигурация: `/etc/roskompozor-probe-next/config.json`. Резервные копии:
`/var/backups/roskompozor-probe-next/`, на OpenWrt —
`/etc/roskompozor-probe-next-backups/`. Старый клиент останавливается после
проверки нового ключа через API. История очереди нового клиента сохраняется.

OpenWrt использует тот же Python-движок и формат отчётов. Для ZeroBlock задаётся
метка только сокетам Probe; DNS измеряется напрямую. Если в прежней конфигурации
был задан `api_connect_ip`, локальный доступ к серверу API сохраняется.
Существующий интерфейс LuCI обновляется вместе с клиентом.

Подробности реализации и тесты: [next/README.md](next/README.md).
Старые native-пакеты в `openwrt/` и прежних релизах относятся к версии 1.x;
для новых узлов используйте установщик выше.
