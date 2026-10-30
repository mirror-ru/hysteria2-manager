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
cat > "$QR_CAPTURE"
EOF
chmod 755 "$test_dir/bin/qrencode"
QR_CAPTURE="$test_dir/qr-input"
export QR_CAPTURE
PATH="$test_dir/bin:$PATH"
print_qr 'hysteria2://alice:secret@example.com:443/?insecure=1#alice'
[[ "$(< "$QR_CAPTURE")" == 'hysteria2://alice:secret@example.com:443/?insecure=1#alice' ]]

valid_range 20000-50000
valid_range 1-65535
if valid_range 50000-20000 || valid_range 1-65536; then
    echo 'Ошибка: неверный диапазон портов принят' >&2
    exit 1
fi

cat > "$test_dir/hashes.txt" <<'EOF'
ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789  build/hysteria-linux-amd64
1111111111111111111111111111111111111111111111111111111111111111  *hysteria-linux-arm64
EOF
[[ "$(find_expected_hash "$test_dir/hashes.txt" hysteria-linux-amd64)" == "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789" ]]
[[ "$(find_expected_hash "$test_dir/hashes.txt" hysteria-linux-arm64)" == "1111111111111111111111111111111111111111111111111111111111111111" ]]

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

echo 'Проверки пройдены.'
