```sh
t=$(mktemp) && curl -fsSL https://raw.githubusercontent.com/v3trov/roskompozor-probe/main/install.sh -o "$t" && sudo sh "$t"; rm -f "$t"
```

От root: замените `sudo sh` на `sh`.

Linux с systemd или OpenRC, Python 3.10+. Armbian поддерживается.
API-ключ вводится интерактивно, ввод скрыт. Для каждого узла нужен отдельный ключ.

```sh
systemctl status roskompozor-probe
journalctl -u roskompozor-probe -f
```

OpenRC: `rc-service roskompozor-probe status`.
Журнал OpenRC: `/var/log/roskompozor-probe.log`.

Конфигурация: `/etc/roskompozor-probe/config.json` (root и группа службы, `0640`).
Резервные копии при переустановке: `/var/backups/roskompozor-probe/` (root, `0700`).
Повторный запуск установщика обновляет код и запрашивает ключ заново.

Нестандартный init, Python старше 3.10 и контейнеры без необходимых прав ICMP
не поддерживаются автоматически: установщик завершится с объяснением.

## OpenWrt

Нативный пакет для OpenWrt/RouteRich 24.10, aarch64_cortex-a53: [OpenWrt 1.0.1-r1](https://github.com/v3trov/roskompozor-probe/releases/tag/openwrt-v1.0.1-r1).
Обновляется только пакет roskompozor-probe; существующий LuCI и config.json сохраняются.
Исходники и сборка: [openwrt/](openwrt/).
