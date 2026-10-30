# Hysteria 2 Manager

Bash-скрипт для установки и управления сервером Hysteria 2 на Linux с IPv4.

## Установка

Требуются `root` и `curl`:

```bash
curl -fsSLo hysteria-manager.sh https://raw.githubusercontent.com/mirror-ru/hysteria2-manager/main/hysteria-manager.sh && bash hysteria-manager.sh
```

Скрипт сам устанавливает зависимости через `apt`, `dnf`, `yum` или `zypper`. На Arch Linux зависимости устанавливаются вручную по команде, которую выведет скрипт.

Повторный запуск:

```bash
bash hysteria-manager.sh
```

## Возможности

- установка Hysteria 2 для `amd64`, `arm64`, `arm`, `386` и `s390x`;
- Let's Encrypt или самоподписанный сертификат;
- отдельные `username/password` для клиентов;
- генерация YAML-профилей, ссылок и QR-кодов;
- port hopping: native, `iptables` или `nftables`;
- обфускация Salamander и Gecko;
- выбор Brutal, BBR или Reno;
- обновление ядра Hysteria с проверкой SHA-256;
- безопасное удаление установки.

## Меню

```text
1   Добавить клиента
2   Список клиентов / QR
3   Удалить клиента
4   Настройки сервера
5   Обновить ядро Hysteria
7   Удалить Hysteria
99  Обновить скрипт
0   Выход
```

Пункт `99` скачивает новую версию из публичной raw-ссылки, показывает дату и короткий SHA снимка, проверяет заголовок и синтаксис Bash, сохраняет резервную копию и перезапускает менеджер. `GITHUB_TOKEN` не используется.

## Важно

- Скрипт рассчитан на Linux и запуск от `root`.
- Используется только IPv4.
- Для production рекомендуется Let's Encrypt. Самоподписанный сертификат требует `insecure: true` на клиенте.
- При изменении порта, port hopping или обфускации профили клиентов пересоздаются.
- Старые установки без базы клиентов автоматически не мигрируются; перед обновлением сохраните `/etc/hysteria`.

## Проверка

Локальные регрессионные тесты:

```bash
bash tests/regression.sh
```

Тесты не заменяют проверку на реальном Linux-сервере: systemd, firewall и ACME в них не запускаются.
