#!/usr/bin/env bash
# Изолированные проверки функций менеджера; systemd и firewall не вызываются.
set -euo pipefail
umask 077

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
test_dir=$(mktemp -d)
trap 'rm -rf -- "$test_dir"' EXIT

# Загружаем определения функций, не выполняя проверку root и главное меню.
source <(sed -n '/^die() {/,/^# MAIN LOOP/p' "$script_dir/hysteria-manager.sh" | sed '$d')
RED='' GREEN='' YELLOW='' BLUE='' NC=''
HYSTERIA_DIR=$test_dir
CLIENTS_DIR=$test_dir/clients
CLIENT_EXPORT_DIR=$test_dir/exports
CLIENTS_DB=$test_dir/clients.db
CLIENT_LIST=$test_dir/clients.list
SETTINGS_FILE=$test_dir/settings.conf
CONFIG_FILE=$test_dir/config.yaml
mkdir -p "$CLIENTS_DIR" "$CLIENT_EXPORT_DIR"

mkdir -p "$test_dir/bin"
cat > "$test_dir/bin/qrencode" <<'EOF'
#!/usr/bin/env bash
printf '%s' "$*" > "${QR_CAPTURE}.args"
cat > "$QR_CAPTURE"
EOF
chmod 755 "$test_dir/bin/qrencode"
QR_CAPTURE="$test_dir/qr-input"
export QR_CAPTURE
PATH="$test_dir/bin:$PATH"
print_qr 'hysteria2://alice:secret@example.com:443/?insecure=1#alice'
[[ "$(< "$QR_CAPTURE")" == 'hysteria2://alice:secret@example.com:443/?insecure=1#alice' ]]
grep -Fq -- '-t ANSI' "$QR_CAPTURE.args"

valid_range 20000-50000
valid_range 1-65535
if valid_range 50000-20000 || valid_range 1-65536; then
    echo 'Ошибка: неверный диапазон портов принят' >&2
    exit 1
fi

valid_port 1
valid_port 65535
if valid_port 0 || valid_port 65536 || valid_port 00001; then
    echo 'Ошибка: неверный порт принят' >&2
    exit 1
fi
port_in_range 443 400-500
if port_in_range 443 444-500 || port_in_range 443 1-100; then
    echo 'Ошибка: проверка попадания порта в диапазон работает неверно' >&2
    exit 1
fi

valid_ipv4 192.0.2.1
valid_ipv4 255.255.255.255
if valid_ipv4 256.0.2.1 || valid_ipv4 192.0.2 || valid_ipv4 192.0.2.1.999; then
    echo 'Ошибка: неверный IPv4 принят' >&2
    exit 1
fi
valid_host example.com
if valid_host '.example.com' || valid_host 'example..com' || valid_host 'example.com.'; then
    echo 'Ошибка: неверный домен принят' >&2
    exit 1
fi
valid_email admin@example.com
if valid_email admin@example || valid_email 'admin@example.c'; then
    echo 'Ошибка: неверный email принят' >&2
    exit 1
fi
valid_name client_01
valid_server_addr example.com
valid_server_addr 192.0.2.10
if valid_name '-client' || valid_name 'client name' || valid_server_addr 999.0.2.10; then
    echo 'Ошибка: неверное имя или адрес принят' >&2
    exit 1
fi

secret=$(random_secret)
[[ "$secret" =~ ^[0-9a-f]{32}$ ]]

printf 'PORT=443\n' > "$SETTINGS_FILE"
settings_write_failed=false
write_setting PORT 8443
write_setting SNI example.com
write_setting PORT 9443
grep -Fxq 'PORT=9443' "$SETTINGS_FILE"
[[ "$(grep -c '^PORT=' "$SETTINGS_FILE")" == 1 ]]
grep -Fxq 'SNI=example.com' "$SETTINGS_FILE"
[[ "$(read_setting PORT)" == '9443' ]]
[[ "$(read_setting SNI)" == 'example.com' ]]
[[ -z "$(read_setting UNKNOWN)" ]]

cat > "$test_dir/hashes.txt" <<'EOF'
ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789  build/hysteria-linux-amd64
1111111111111111111111111111111111111111111111111111111111111111  *hysteria-linux-arm64
EOF
[[ "$(find_expected_hash "$test_dir/hashes.txt" hysteria-linux-amd64)" == "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789" ]]
[[ "$(find_expected_hash "$test_dir/hashes.txt" hysteria-linux-arm64)" == "1111111111111111111111111111111111111111111111111111111111111111" ]]
[[ -z "$(find_expected_hash "$test_dir/hashes.txt" hysteria-linux-s390x)" ]]

printf 'alice|alice|abc|2||\nbob|bob|def|2||' > "$CLIENTS_DB"
validate_client_db
printf 'alice|alice|abc|2||\nbob|alice|def|2||\n' > "$CLIENTS_DB"
if validate_client_db 2>/dev/null; then
    echo 'Ошибка: повторяющийся логин принят' >&2
    exit 1
fi
printf 'alice|alice||2||\n' > "$CLIENTS_DB"
if validate_client_db 2>/dev/null; then
    echo 'Ошибка: пустой пароль принят' >&2
    exit 1
fi
printf 'true|true|123456|2||\n123|123|true|2||' > "$CLIENTS_DB"
validate_client_db
write_userpass_entries > "$test_dir/auth.yaml"
grep -Fxq '    "true": "123456"' "$test_dir/auth.yaml"
grep -Fxq '    "123": "true"' "$test_dir/auth.yaml"

PORT=443 SERVER_ADDR=example.com SNI=example.com INSECURE_FLAG=false
HOP_RANGE='' OBFS_ENABLED=false
printf 'старый профиль' > "$CLIENTS_DIR/alice.yaml"
printf 'старая копия' > "$CLIENT_EXPORT_DIR/alice_hysteria.yaml"
if write_client_profile alice alice abc invalid; then
    echo 'Ошибка: неверный алгоритм принят' >&2
    exit 1
fi
[[ $(< "$CLIENTS_DIR/alice.yaml") == 'старый профиль' ]]
[[ $(< "$CLIENT_EXPORT_DIR/alice_hysteria.yaml") == 'старая копия' ]]
write_client_profile alice alice abc 2
grep -Fxq 'auth: alice:abc' "$CLIENTS_DIR/alice.yaml"
grep -Fxq '  listen: 127.0.0.1:1080' "$CLIENTS_DIR/alice.yaml"
cmp -s "$CLIENTS_DIR/alice.yaml" "$CLIENT_EXPORT_DIR/alice_hysteria.yaml"

PORT=443 SERVER_ADDR=example.com SNI=google.com INSECURE_FLAG=true
HOP_RANGE='' OBFS_ENABLED=true OBFS_TYPE=salamander OBFS_PASSWORD=0123456789abcdef0123456789abcdef
write_client_profile bob bob def
grep -Fxq '  type: bbr' "$CLIENTS_DIR/bob.yaml"
grep -Fxq '  type: salamander' "$CLIENTS_DIR/bob.yaml"
grep -Fq 'obfs=salamander&obfs-password=0123456789abcdef0123456789abcdef' "$CLIENT_LIST"

OBFS_TYPE=gecko OBFS_MIN_PKT=512 OBFS_MAX_PKT=1200
write_client_profile carol carol ghi 2
grep -Fxq '  type: gecko' "$CLIENTS_DIR/carol.yaml"
grep -Fxq '    minPacketSize: 512' "$CLIENTS_DIR/carol.yaml"
grep -Fxq '    maxPacketSize: 1200' "$CLIENTS_DIR/carol.yaml"

cat > "$SETTINGS_FILE" <<EOF
SERVER_ADDR=example.com
PORT=443
HOP_RANGE=
HOP_METHOD=
INSECURE_FLAG=true
SNI=google.com
OBFS_ENABLED=true
OBFS_TYPE=salamander
OBFS_PASSWORD=0123456789abcdef0123456789abcdef
OBFS_MIN_PKT=
OBFS_MAX_PKT=
MASQ_DOMAIN=google.com
CERT_TYPE=self
DOMAIN=
ACME_EMAIL=
FIREWALL_BACKEND=
EOF
printf 'alice|alice|abc|2||\nbob|bob|def|2||\n' > "$CLIENTS_DB"
load_settings
validate_settings
rebuild_client_profiles
grep -Fxq 'auth: alice:abc' "$CLIENTS_DIR/alice.yaml"
grep -Fxq 'auth: bob:def' "$CLIENTS_DIR/bob.yaml"

CERT_TYPE=acme DOMAIN=example.com ACME_EMAIL=admin@example.com
validate_settings

cat > "$SETTINGS_FILE" <<'EOF'
SERVER_ADDR=192.0.2.10
PORT=443
INSECURE_FLAG=false
SNI=example.com
OBFS_ENABLED=false
MASQ_DOMAIN=example.com
CERT_TYPE=self
EOF
SNI=stale-value
load_settings
[[ "$SNI" == 'example.com' ]]
[[ -z "$ACME_EMAIL" ]]

echo 'Проверки пройдены.'
