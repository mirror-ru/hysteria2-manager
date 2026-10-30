#!/bin/bash
# Hysteria 2 Manager
set -o pipefail
umask 077
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

HYSTERIA_DIR="/etc/hysteria"
CONFIG_FILE="${HYSTERIA_DIR}/config.yaml"
SETTINGS_FILE="${HYSTERIA_DIR}/settings.conf"
CLIENTS_DIR="${HYSTERIA_DIR}/clients"
CLIENTS_DB="${HYSTERIA_DIR}/clients.db"
CLIENT_EXPORT_DIR="${HYSTERIA_DIR}/exports"
BIN_PATH="/usr/local/bin/hysteria"
CLIENT_LIST="${HYSTERIA_DIR}/clients.list"
SCRIPT_PATH="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/$(basename -- "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(dirname -- "$SCRIPT_PATH")"
MANAGER_RAW_URL="https://raw.githubusercontent.com/mirror-ru/hysteria2-manager/main/hysteria-manager.sh"
MANAGER_COMMITS_API_URL="https://api.github.com/repos/mirror-ru/hysteria2-manager/commits?path=hysteria-manager.sh&per_page=1"

if [[ "$EUID" -ne 0 ]]; then
    echo -e "${RED}Ошибка: скрипт нужно запускать от root${NC}"
    exit 1
fi

die() {
    echo -e "${RED}Ошибка: $*${NC}" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "Не найдена обязательная команда: $1"
}

read_setting() {
    local key="$1"
    [[ -f "$SETTINGS_FILE" ]] || return 1
    awk -F= -v wanted="$key" '$1 == wanted {sub(/^[^=]*=/, ""); print; exit}' "$SETTINGS_FILE"
}

load_settings() {
    [[ -f "$SETTINGS_FILE" ]] || die "Файл настроек не найден: $SETTINGS_FILE"
    SERVER_ADDR=""; PORT=""; HOP_RANGE=""; HOP_METHOD=""; INSECURE_FLAG=""
    SNI=""; OBFS_ENABLED=""; OBFS_TYPE=""; OBFS_PASSWORD=""
    OBFS_MIN_PKT=""; OBFS_MAX_PKT=""; MASQ_DOMAIN=""; CERT_TYPE=""
    DOMAIN=""; ACME_EMAIL=""; FIREWALL_BACKEND=""
    while IFS='=' read -r key value; do
        case "$key" in
            SERVER_ADDR) SERVER_ADDR="$value" ;;
            PORT) PORT="$value" ;;
            HOP_RANGE) HOP_RANGE="$value" ;;
            HOP_METHOD) HOP_METHOD="$value" ;;
            INSECURE_FLAG) INSECURE_FLAG="$value" ;;
            SNI) SNI="$value" ;;
            OBFS_ENABLED) OBFS_ENABLED="$value" ;;
            OBFS_TYPE) OBFS_TYPE="$value" ;;
            OBFS_PASSWORD) OBFS_PASSWORD="$value" ;;
            OBFS_MIN_PKT) OBFS_MIN_PKT="$value" ;;
            OBFS_MAX_PKT) OBFS_MAX_PKT="$value" ;;
            MASQ_DOMAIN) MASQ_DOMAIN="$value" ;;
            CERT_TYPE) CERT_TYPE="$value" ;;
            DOMAIN) DOMAIN="$value" ;;
            ACME_EMAIL) ACME_EMAIL="$value" ;;
            FIREWALL_BACKEND) FIREWALL_BACKEND="$value" ;;
        esac
    done < "$SETTINGS_FILE"
}

write_setting() {
    local key="$1" value="$2" tmp
    [[ "${settings_write_failed:-false}" == false ]] || return 1
    tmp=$(mktemp "${SETTINGS_FILE}.XXXXXX") || { settings_write_failed=true; return 1; }
    if [[ -f "$SETTINGS_FILE" ]]; then
        if ! awk -F= -v key="$key" -v value="$value" 'BEGIN { found=0 } $1 == key { print key "=" value; found=1; next } { print } END { if (!found) print key "=" value }' "$SETTINGS_FILE" > "$tmp"; then
            rm -f "$tmp"; settings_write_failed=true; return 1
        fi
    else
        if ! printf '%s=%s\n' "$key" "$value" > "$tmp"; then
            rm -f "$tmp"; settings_write_failed=true; return 1
        fi
    fi
    if ! chmod 600 "$tmp" || ! mv -f "$tmp" "$SETTINGS_FILE"; then
        rm -f "$tmp"; settings_write_failed=true; return 1
    fi
}

valid_port() { [[ "$1" =~ ^[1-9][0-9]{0,4}$ ]] && (( 10#$1 <= 65535 )); }
valid_range() {
    [[ "$1" =~ ^([1-9][0-9]{0,4})-([1-9][0-9]{0,4})$ ]] || return 1
    local start="${BASH_REMATCH[1]}" end="${BASH_REMATCH[2]}"
    valid_port "$start" && valid_port "$end" && (( 10#$start < 10#$end ))
}
port_in_range() { local port="$1" range="$2" start="${2%-*}" end="${2#*-}"; (( 10#$port >= 10#$start && 10#$port <= 10#$end )); }
valid_name() { [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$ ]]; }
valid_host() { [[ "$1" =~ ^[A-Za-z0-9.-]{1,253}$ && "$1" != .* && "$1" != *..* && "$1" != *. ]]; }
valid_email() { [[ "$1" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$ ]]; }
valid_ipv4() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1; local octet; local -a octets; IFS=. read -r -a octets <<< "$1"; for octet in "${octets[@]}"; do (( 10#$octet <= 255 )) || return 1; done; }
valid_server_addr() { if [[ "$1" =~ ^[0-9.]+$ ]]; then valid_ipv4 "$1"; else valid_host "$1"; fi; }

validate_settings() {
    valid_server_addr "$SERVER_ADDR" || die "Недопустимый адрес сервера в настройках"
    valid_port "$PORT" || die "Недопустимый порт в настройках"
    [[ -z "$HOP_RANGE" ]] || valid_range "$HOP_RANGE" || die "Недопустимый диапазон портов в настройках"
    [[ -z "$HOP_RANGE" ]] || ! port_in_range "$PORT" "$HOP_RANGE" || die "Основной порт не должен входить в диапазон hopping"
    [[ -z "$HOP_RANGE" || "$HOP_METHOD" == "native" || "$HOP_METHOD" == "iptables" || "$HOP_METHOD" == "nftables" ]] || die "Недопустимый метод port hopping в настройках"
    [[ "$INSECURE_FLAG" == "true" || "$INSECURE_FLAG" == "false" ]] || die "Недопустимый TLS-флаг в настройках"
    [[ -z "$FIREWALL_BACKEND" || "$FIREWALL_BACKEND" == "iptables" || "$FIREWALL_BACKEND" == "nftables" ]] || die "Недопустимый backend firewall в настройках"
    if [[ -n "$HOP_RANGE" ]]; then
        case "$HOP_METHOD:$FIREWALL_BACKEND" in
            native:|iptables:iptables|nftables:nftables) ;;
            *) die "Метод port hopping не соответствует выбранному firewall" ;;
        esac
    fi
    valid_host "$SNI" || die "Недопустимый SNI в настройках"
    valid_host "$MASQ_DOMAIN" || die "Недопустимый домен маскировки в настройках"
    [[ "$CERT_TYPE" == "self" || "$CERT_TYPE" == "acme" ]] || die "Недопустимый тип сертификата в настройках"
    if [[ "$CERT_TYPE" == "acme" ]]; then
        valid_host "$DOMAIN" || die "Недопустимый домен ACME в настройках"
        valid_email "$ACME_EMAIL" || die "Недопустимый email ACME в настройках"
    fi
    [[ "$OBFS_ENABLED" == "true" || "$OBFS_ENABLED" == "false" ]] || die "Недопустимое состояние обфускации в настройках"
    if [[ "$OBFS_ENABLED" == "true" ]]; then
        [[ "$OBFS_TYPE" == "salamander" || "$OBFS_TYPE" == "gecko" ]] || die "Недопустимый тип обфускации в настройках"
        [[ "$OBFS_PASSWORD" =~ ^[A-Za-z0-9]+$ ]] || die "Недопустимый пароль обфускации в настройках"
        if [[ "$OBFS_TYPE" == "gecko" ]]; then
            local min_packet="${OBFS_MIN_PKT:-512}" max_packet="${OBFS_MAX_PKT:-1200}"
            [[ "$min_packet" =~ ^[1-9][0-9]{0,3}$ && "$max_packet" =~ ^[1-9][0-9]{0,3}$ ]] && (( min_packet <= max_packet && max_packet <= 2048 )) || die "Недопустимые размеры пакетов Gecko в настройках"
        fi
    fi
    if [[ "$HOP_METHOD" == "iptables" ]]; then
        command -v iptables >/dev/null 2>&1 || die "Для ручного port hopping требуется iptables"
    elif [[ "$HOP_METHOD" == "nftables" ]]; then
        command -v nft >/dev/null 2>&1 || die "Для ручного port hopping требуется nft"
    fi
}

ensure_state_permissions() {
    mkdir -p "$HYSTERIA_DIR" "$CLIENTS_DIR" "$CLIENT_EXPORT_DIR" || die "Не удалось создать каталоги Hysteria"
    chmod 700 "$HYSTERIA_DIR" "$CLIENTS_DIR" "$CLIENT_EXPORT_DIR" || die "Не удалось ограничить права каталогов Hysteria"
    local file
    for file in "$SETTINGS_FILE" "$CLIENTS_DB" "$CLIENT_LIST" "$CONFIG_FILE" "${HYSTERIA_DIR}/server.key"; do
        if [[ -f "$file" ]]; then
            chmod 600 "$file" || die "Не удалось ограничить права файла: $file"
        fi
    done
    if [[ -f "${HYSTERIA_DIR}/server.crt" ]]; then
        chmod 644 "${HYSTERIA_DIR}/server.crt" || die "Не удалось установить права сертификата"
    fi
}

random_secret() {
    local secret
    secret=$(openssl rand -hex 16 2>/dev/null) || return 1
    [[ "$secret" =~ ^[0-9a-fA-F]{32}$ ]] || return 1
    printf '%s\n' "$secret"
}

# ==========================================
# SYSTEM DETECTION & HELPERS
# ==========================================
detect_arch() {
    case "$(uname -m)" in
        x86_64 | amd64) ARCH="amd64" ;;
        aarch64 | arm64) ARCH="arm64" ;;
        armv7l | armv8l | arm) ARCH="arm" ;;
        i386 | i686) ARCH="386" ;;
        s390x) ARCH="s390x" ;;
        *) echo -e "${RED}Неподдерживаемая архитектура: $(uname -m)${NC}"; exit 1 ;;
    esac
}

install_deps() {
    echo -e "${GREEN}Проверка и установка зависимостей...${NC}"
    local FW_PKG=""
    if [[ "$FIREWALL_BACKEND" == "nftables" ]]; then
        FW_PKG="nftables"
    else
        FW_PKG="iptables"
    fi
    if [ -x "$(command -v apt-get)" ]; then
        apt-get update && apt-get install -y curl openssl qrencode jq "$FW_PKG" || die "Не удалось установить зависимости"
    elif [ -x "$(command -v dnf)" ]; then
        dnf install -y curl openssl qrencode jq "$FW_PKG" || die "Не удалось установить зависимости"
    elif [ -x "$(command -v yum)" ]; then
        yum install -y curl openssl epel-release qrencode jq "$FW_PKG" || die "Не удалось установить зависимости"
    elif [ -x "$(command -v pacman)" ]; then
        local required fw_command
        fw_command=iptables
        [[ "$FW_PKG" == nftables ]] && fw_command=nft
        for required in curl openssl qrencode jq "$fw_command"; do
            if ! command -v "$required" >/dev/null 2>&1; then
                echo -e "${RED}Не найдена команда $required. Обновите систему и установите зависимости вручную:${NC}" >&2
                echo "pacman -Syu --needed curl openssl qrencode jq $FW_PKG" >&2
                return 1
            fi
        done
    elif [ -x "$(command -v zypper)" ]; then
        zypper install -y curl openssl qrencode jq "$FW_PKG" || die "Не удалось установить зависимости"
    else
        echo -e "${RED}Неподдерживаемый менеджер пакетов. Установите вручную curl, jq, openssl, qrencode и $FW_PKG.${NC}"
        exit 1
    fi
}

get_public_ip() {
    local local_ip candidate endpoint
    for endpoint in https://api.ipify.org https://ifconfig.me; do
        candidate=$(curl -q -4 --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 5 --max-time 10 "$endpoint") || continue
        if valid_ipv4 "$candidate"; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    local_ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<NF; i++) if ($i == "src") {print $(i+1); exit}}')
    if valid_ipv4 "$local_ip" && [[ ! "$local_ip" =~ ^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.) ]]; then
        printf '%s\n' "$local_ip"
        return 0
    fi
    return 1
}

cleanup_firewall() {
    [[ -f "$SETTINGS_FILE" ]] || return 0
    local hop_method hop_range port ipt_range
    hop_method=$(read_setting HOP_METHOD)
    hop_range=$(read_setting HOP_RANGE)
    port=$(read_setting PORT)
    if [[ "$hop_method" == "iptables" ]] && valid_range "$hop_range" && valid_port "$port" && command -v iptables >/dev/null 2>&1; then
        ipt_range="${hop_range//-/:}"
        for _ in {1..100}; do
            iptables -t nat -D PREROUTING -p udp --dport "$ipt_range" -j REDIRECT --to-ports "$port" 2>/dev/null || break
        done
    fi
    if [[ "$hop_method" == "nftables" ]] && command -v nft >/dev/null 2>&1; then
        nft delete table ip hysteria_nat 2>/dev/null || true
    fi
}

find_expected_hash() {
    local hashes_file="$1" asset_name="$2"
    awk -v name="$asset_name" '
        {
            candidate = $NF
            sub(/^.*\//, "", candidate)
            if (candidate == name || candidate == "*" name) {
                print $1
                exit
            }
        }
    ' "$hashes_file" | tr '[:upper:]' '[:lower:]'
}

download_verified_binary() {
    local output="$1" version="$2" asset="hysteria-linux-${ARCH}" hashes_tmp expected actual
    hashes_tmp=$(mktemp) || return 1
    if ! curl -q --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 15 --max-time 120 \
        -o "$output" "https://github.com/HyNetworks/hysteria/releases/download/${version}/${asset}" || \
       ! curl -q --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 15 --max-time 120 \
        -o "$hashes_tmp" "https://github.com/HyNetworks/hysteria/releases/download/${version}/hashes.txt"; then
        rm -f "$hashes_tmp"
        return 1
    fi
    expected=$(find_expected_hash "$hashes_tmp" "$asset")
    rm -f "$hashes_tmp"
    [[ "$expected" =~ ^[A-Fa-f0-9]{64}$ ]] || return 1
    actual=$(sha256sum "$output" | awk '{print $1}' | tr '[:upper:]' '[:lower:]')
    [[ "$actual" == "$expected" ]]
}

latest_version() {
    local tag
    tag=$(curl -q --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 15 --max-time 30 \
        https://api.github.com/repos/HyNetworks/hysteria/releases/latest |
        jq -r '.tag_name // empty') || return 1
    [[ "$tag" =~ ^app/v[0-9]+\.[0-9]+\.[0-9]+([.+-][0-9A-Za-z.-]+)?$ ]] || return 1
    printf '%s\n' "$tag"
}

# ==========================================
# CORE FUNCTIONS
# ==========================================
write_client_profile_contents() {
    local client_name="$1" client_user="$2" client_password="$3" cc_choice="${4:-2}" down="${5:-}" up="${6:-}"
    local client_ports="$PORT" client_server="$SERVER_ADDR" client_host="$SERVER_ADDR" link_insecure=0
    [[ "$INSECURE_FLAG" == "true" ]] && link_insecure=1
    [[ -n "$HOP_RANGE" ]] && client_ports="${PORT},${HOP_RANGE}"
    local client_config_file="$7" client_export_file="$8"
    cat <<EOF > "$client_config_file" || return 1
server: $client_server:$client_ports
auth: ${client_user}:${client_password}
tls:
  sni: $SNI
  insecure: $INSECURE_FLAG
socks5:
  listen: 127.0.0.1:1080
EOF

    HY2_LINK="hysteria2://${client_user}:${client_password}@${client_host}:${client_ports}/?insecure=${link_insecure}&sni=${SNI}"
    case "$cc_choice" in
        1)
            [[ "$down" =~ ^[1-9][0-9]{0,5}$ && "$up" =~ ^[1-9][0-9]{0,5}$ ]] || return 1
            cat <<EOF >> "$client_config_file" || return 1
bandwidth:
  up: $up mbps
  down: $down mbps
EOF
            ;;
        2)
            printf 'congestion:\n  type: bbr\n' >> "$client_config_file" || return 1
            ;;
        3)
            printf 'congestion:\n  type: reno\n' >> "$client_config_file" || return 1
            ;;
        *) return 1 ;;
    esac

    if [[ "$OBFS_ENABLED" == "true" ]]; then
        if [[ "$OBFS_TYPE" == "gecko" ]]; then
            cat <<EOF >> "$client_config_file" || return 1
obfs:
  type: gecko
  gecko:
    password: $OBFS_PASSWORD
    minPacketSize: ${OBFS_MIN_PKT:-512}
    maxPacketSize: ${OBFS_MAX_PKT:-1200}
EOF
            HY2_LINK="${HY2_LINK}&obfs=gecko&obfs-password=${OBFS_PASSWORD}"
        else
            cat <<EOF >> "$client_config_file" || return 1
obfs:
  type: salamander
  salamander:
    password: $OBFS_PASSWORD
EOF
            HY2_LINK="${HY2_LINK}&obfs=salamander&obfs-password=${OBFS_PASSWORD}"
        fi
    fi
    HY2_LINK="${HY2_LINK}#${client_name}"
    cp "$client_config_file" "$client_export_file" || return 1
    chmod 600 "$client_config_file" "$client_export_file" || return 1
    printf '%s | %s\n' "$client_name" "$HY2_LINK" >> "$CLIENT_LIST" || return 1
}

write_client_profile() {
    local client_name="$1" config_tmp export_tmp
    config_tmp=$(mktemp "${CLIENTS_DIR}/${client_name}.yaml.XXXXXX") || return 1
    export_tmp=$(mktemp "${CLIENT_EXPORT_DIR}/${client_name}_hysteria.yaml.XXXXXX") || { rm -f "$config_tmp"; return 1; }
    if ! write_client_profile_contents "$1" "$2" "$3" "${4:-2}" "${5:-}" "${6:-}" "$config_tmp" "$export_tmp" ||
       ! mv -f "$config_tmp" "${CLIENTS_DIR}/${client_name}.yaml" ||
       ! mv -f "$export_tmp" "${CLIENT_EXPORT_DIR}/${client_name}_hysteria.yaml"; then
        rm -f "$config_tmp" "$export_tmp"
        return 1
    fi
}

validate_client_db() {
    local client_name client_user client_password cc_choice down up count=0
    local -A seen_names=() seen_users=()
    while IFS='|' read -r client_name client_user client_password cc_choice down up || [[ -n "$client_name$client_user$client_password$cc_choice$down$up" ]]; do
        [[ -n "$client_name$client_user$client_password$cc_choice$down$up" ]] || continue
        if ! valid_name "$client_name" || ! valid_name "$client_user" || [[ ! "$client_password" =~ ^[A-Za-z0-9]+$ ]] || [[ -n "${seen_names[$client_name]:-}" || -n "${seen_users[$client_user]:-}" ]]; then
            echo -e "${RED}Повреждена база клиентов: проверьте имена, пароли и повторяющиеся записи в $CLIENTS_DB${NC}" >&2
            return 1
        fi
        seen_names[$client_name]=1; seen_users[$client_user]=1
        ((count += 1))
    done < "$CLIENTS_DB"
    (( count > 0 )) || { echo -e "${RED}В базе нет корректных записей клиентов${NC}" >&2; return 1; }
}

write_userpass_entries() {
    local client_name client_user client_password cc_choice down up
    while IFS='|' read -r client_name client_user client_password cc_choice down up || [[ -n "$client_name$client_user$client_password$cc_choice$down$up" ]]; do
        [[ -n "$client_name$client_user$client_password$cc_choice$down$up" ]] || continue
        printf '    "%s": "%s"\n' "$client_user" "$client_password" || return 1
    done < "$CLIENTS_DB"
}

rebuild_client_profiles() {
    load_settings
    validate_settings
    ensure_state_permissions
    [[ -f "$CLIENTS_DB" ]] || return 0
    [[ ! -s "$CLIENTS_DB" ]] || validate_client_db || return 1
    local list_target="$CLIENT_LIST" CLIENT_LIST
    CLIENT_LIST=$(mktemp "${list_target}.XXXXXX") || return 1
    while IFS='|' read -r client_name client_user client_password cc_choice down up || [[ -n "$client_name$client_user$client_password$cc_choice$down$up" ]]; do
        [[ -n "$client_name" ]] || continue
        valid_name "$client_name" && valid_name "$client_user" && [[ "$client_password" =~ ^[A-Za-z0-9]+$ ]] &&
            write_client_profile "$client_name" "$client_user" "$client_password" "${cc_choice:-2}" "$down" "$up" || {
                echo -e "${RED}Не удалось создать профиль клиента $client_name. Проверьте базу клиентов и права доступа.${NC}" >&2
                rm -f "$CLIENT_LIST"
                return 1
            }
    done < "$CLIENTS_DB"
    if ! chmod 600 "$CLIENT_LIST" || ! mv -f "$CLIENT_LIST" "$list_target"; then
        rm -f "$CLIENT_LIST"
        echo -e "${RED}Не удалось обновить список ссылок клиентов${NC}" >&2
        return 1
    fi
}

save_server_config() {
    load_settings
    validate_settings
    ensure_state_permissions
    if [[ ! -s "$CLIENTS_DB" ]]; then
        echo -e "${RED}Нет учётных записей клиентов. Добавьте клиента перед применением конфигурации.${NC}" >&2
        return 1
    fi
    validate_client_db || return 1
    local config_tmp service_tmp old_config old_service
    config_tmp=$(mktemp "${CONFIG_FILE}.XXXXXX") || return 1
    service_tmp=$(mktemp "/etc/systemd/system/hysteria.service.XXXXXX") || { rm -f "$config_tmp"; return 1; }
    chmod 600 "$config_tmp"
    chmod 644 "$service_tmp"

    # Формируем строку listen с учётом метода port hopping
    local LISTEN_LINE="listen: 0.0.0.0:$PORT"
    if [[ -n "$HOP_RANGE" && "$HOP_METHOD" == "native" ]]; then
        LISTEN_LINE="listen: 0.0.0.0:$PORT,$HOP_RANGE"
    fi

    {
        cat <<EOF
$LISTEN_LINE
auth:
  type: userpass
  userpass:
EOF
        write_userpass_entries || { rm -f "$config_tmp" "$service_tmp"; return 1; }
        cat <<EOF
masquerade:
  type: proxy
  proxy:
    url: https://$MASQ_DOMAIN
    rewriteHost: true
EOF
    } > "$config_tmp"

    if [[ "$OBFS_ENABLED" == "true" ]]; then
        if [[ "$OBFS_TYPE" == "gecko" ]]; then
            cat <<EOF >> "$config_tmp"
obfs:
  type: gecko
  gecko:
    password: $OBFS_PASSWORD
    minPacketSize: ${OBFS_MIN_PKT:-512}
    maxPacketSize: ${OBFS_MAX_PKT:-1200}
EOF
        else
            # Default — salamander
            cat <<EOF >> "$config_tmp"
obfs:
  type: salamander
  salamander:
    password: $OBFS_PASSWORD
EOF
        fi
    fi

    if [[ "$CERT_TYPE" == "acme" ]]; then
        cat <<EOF >> "$config_tmp"
acme:
  domains:
    - $DOMAIN
  email: $ACME_EMAIL
EOF
    else
        cat <<EOF >> "$config_tmp"
tls:
  cert: ${HYSTERIA_DIR}/server.crt
  key: ${HYSTERIA_DIR}/server.key
EOF
    fi

    cat <<EOF > "$service_tmp"
[Unit]
Description=Hysteria 2 Service
After=network.target

[Service]
EOF

    if [[ -n "$FIREWALL_BACKEND" ]]; then
        echo "Environment=\"HYSTERIA_FIREWALL_BACKEND=$FIREWALL_BACKEND\"" >> "$service_tmp"
    fi

    # Ручные правила перенаправления только для не-native режима
    if [[ -n "$HOP_RANGE" && "$HOP_METHOD" != "native" ]]; then
        if [[ "$FIREWALL_BACKEND" == "nftables" ]]; then
            local NFT_CMD=$(command -v nft)
            cat <<EOF >> "$service_tmp"
ExecStartPre=+/bin/sh -c '${NFT_CMD} delete table ip hysteria_nat 2>/dev/null || true'
ExecStartPre=+${NFT_CMD} add table ip hysteria_nat
ExecStartPre=+${NFT_CMD} add chain ip hysteria_nat prerouting { type nat hook prerouting priority dstnat \; }
ExecStartPre=+${NFT_CMD} add rule ip hysteria_nat prerouting udp dport $HOP_RANGE counter redirect to :$PORT
ExecStopPost=+/bin/sh -c '${NFT_CMD} delete table ip hysteria_nat 2>/dev/null || true'
EOF
        else
            local IPTABLES_CMD=$(command -v iptables)
            local IPT_RANGE=${HOP_RANGE//-/:}
            cat <<EOF >> "$service_tmp"
ExecStartPre=+/bin/sh -c '${IPTABLES_CMD} -t nat -C PREROUTING -p udp --dport $IPT_RANGE -j REDIRECT --to-ports $PORT 2>/dev/null || ${IPTABLES_CMD} -t nat -A PREROUTING -p udp --dport $IPT_RANGE -j REDIRECT --to-ports $PORT'
ExecStopPost=+/bin/sh -c 'while ${IPTABLES_CMD} -t nat -D PREROUTING -p udp --dport $IPT_RANGE -j REDIRECT --to-ports $PORT 2>/dev/null; do :; done'
EOF
        fi
    fi

    cat <<EOF >> "$service_tmp"
ExecStart=$BIN_PATH server -c $CONFIG_FILE
WorkingDirectory=$HYSTERIA_DIR
Restart=always
User=root
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    old_config="${CONFIG_FILE}.previous"
    old_service="/etc/systemd/system/hysteria.service.previous"
    if [[ -e "$old_config" || -e "$old_service" ]]; then
        rm -f "$config_tmp" "$service_tmp"
        echo -e "${RED}Обнаружена резервная копия предыдущей конфигурации. Проверьте $old_config и $old_service перед повторным применением настроек.${NC}" >&2
        return 1
    fi
    if [[ -f "$CONFIG_FILE" ]] && ! cp -p "$CONFIG_FILE" "$old_config"; then
        rm -f "$config_tmp" "$service_tmp"
        return 1
    fi
    if [[ -f /etc/systemd/system/hysteria.service ]] && ! cp -p /etc/systemd/system/hysteria.service "$old_service"; then
        rm -f "$config_tmp" "$service_tmp" "$old_config"
        return 1
    fi
    mv -f "$config_tmp" "$CONFIG_FILE" || { rm -f "$config_tmp" "$service_tmp"; return 1; }
    if ! mv -f "$service_tmp" /etc/systemd/system/hysteria.service; then
        if [[ -f "$old_config" ]] && ! mv -f "$old_config" "$CONFIG_FILE"; then
            echo -e "${RED}Не удалось восстановить конфигурацию. Резервная копия: $old_config${NC}" >&2
        fi
        if [[ -f "$old_service" ]] && ! mv -f "$old_service" /etc/systemd/system/hysteria.service; then
            echo -e "${RED}Не удалось восстановить файл сервиса. Резервная копия: $old_service${NC}" >&2
        fi
        rm -f "$service_tmp"
        return 1
    fi
    if ! systemctl daemon-reload || ! systemctl restart hysteria || ! systemctl is-active --quiet hysteria; then
        echo -e "${RED}Новая конфигурация не прошла проверку или сервис не перезапустился. Выполняется откат.${NC}" >&2
        local rollback_failed=false
        if [[ -f "$old_config" ]] && ! mv -f "$old_config" "$CONFIG_FILE"; then
            echo -e "${RED}Не удалось восстановить конфигурацию. Резервная копия: $old_config${NC}" >&2
            rollback_failed=true
        fi
        if [[ -f "$old_service" ]] && ! mv -f "$old_service" /etc/systemd/system/hysteria.service; then
            echo -e "${RED}Не удалось восстановить файл сервиса. Резервная копия: $old_service${NC}" >&2
            rollback_failed=true
        fi
        if [[ "$rollback_failed" == false ]]; then
            if ! systemctl daemon-reload || ! systemctl restart hysteria || ! systemctl is-active --quiet hysteria; then
                echo -e "${RED}Не удалось запустить сервис после отката. Проверьте journalctl -u hysteria.${NC}" >&2
            fi
        fi
        rm -f "$config_tmp" "$service_tmp"
        return 1
    fi
    rm -f "$old_config" "$old_service"
}

install_hysteria() {
    if [[ -e "$SETTINGS_FILE" || -e "$CLIENTS_DB" || -e "$CONFIG_FILE" || -e "${HYSTERIA_DIR}/server.key" || -e "${HYSTERIA_DIR}/server.crt" || -e /etc/systemd/system/hysteria.service ]]; then
        die "Обнаружены файлы существующей установки Hysteria. Автоматическая установка остановлена, чтобы сохранить данные. Сделайте резервную копию $HYSTERIA_DIR и файла сервиса перед восстановлением или переносом установки."
    fi
    echo -e "${BLUE}--- Установка и настройка Hysteria 2 ---${NC}"
    detect_arch
    echo -e "${GREEN}Архитектура: ${ARCH}${NC}"

    read -p "Основной порт сервера (например, 443) [443]: " PORT
    PORT=${PORT:-443}
    valid_port "$PORT" || die "Недопустимый порт: $PORT"

    echo -e "
${YELLOW}Port hopping помогает обходить блокировку UDP, используя диапазон портов.${NC}"
    read -p "Включить port hopping? [y/N]: " ENABLE_HOPPING
    if [[ "$ENABLE_HOPPING" =~ ^[Yy]$ ]]; then
        read -p "Диапазон портов (например, 20000-50000) [20000-50000]: " HOP_RANGE
        HOP_RANGE=${HOP_RANGE:-20000-50000}
        valid_range "$HOP_RANGE" || die "Недопустимый диапазон портов: $HOP_RANGE"
        ! port_in_range "$PORT" "$HOP_RANGE" || die "Основной порт должен находиться вне диапазона hopping"

        echo -e "
Метод port hopping:"
        echo "1) Native (Hysteria сама управляет firewall — рекомендуется)"
        echo "2) Через iptables (старые ОС или CentOS/Alma)"
        echo "3) Через nftables (современные Debian/Ubuntu)"
        read -p "Выбор [1-3]: " HOP_CHOICE
        case "$HOP_CHOICE" in
            2) HOP_METHOD="iptables"; FIREWALL_BACKEND="iptables" ;;
            3) HOP_METHOD="nftables"; FIREWALL_BACKEND="nftables" ;;
            1|'') HOP_METHOD="native"; FIREWALL_BACKEND="" ;;
            *) die "Недопустимый метод port hopping" ;;
        esac
    else
        HOP_RANGE=""
        HOP_METHOD=""
        FIREWALL_BACKEND=""
    fi

    install_deps || die "Не удалось подготовить зависимости"
    SERVER_IP=$(get_public_ip) || die "Не удалось определить публичный IPv4-адрес сервера. Проверьте сеть и доступность сервисов определения IP"

    echo -e "
Тип сертификата:"
    echo "1) Let's Encrypt (домен)"
    echo "2) Самоподписанный (IP сервера: $SERVER_IP)"
    read -p "Выбор [1-2]: " CERT_CHOICE
    if [[ "$CERT_CHOICE" == "1" ]]; then
        read -p "Домен: " DOMAIN
        read -p "Email: " ACME_EMAIL
        valid_host "$DOMAIN" || die "Недопустимый домен: $DOMAIN"
        valid_email "$ACME_EMAIL" || die "Недопустимый email"
        CERT_TYPE="acme"
        SERVER_ADDR=$DOMAIN
        INSECURE_FLAG="false"
        SNI=$DOMAIN
    elif [[ "$CERT_CHOICE" == "2" ]]; then
        CERT_TYPE="self"
        SERVER_ADDR=$SERVER_IP
        read -p "Маскирующий SNI [google.com]: " SNI
        SNI=${SNI:-google.com}
        valid_host "$SNI" || die "Недопустимый SNI: $SNI"
        INSECURE_FLAG="true"
    else
        die "Недопустимый выбор сертификата"
    fi

    read -p "Сайт для маскировки [google.com]: " MASQ_DOMAIN
    MASQ_DOMAIN=${MASQ_DOMAIN:-google.com}
    valid_host "$MASQ_DOMAIN" || die "Недопустимый домен маскировки: $MASQ_DOMAIN"

    echo -e "
Обфускация (скрывает сигнатуру QUIC):"
    echo "1) Выключена (имитация обычного HTTP/3)"
    echo "2) Salamander (рекомендуется; случайно выглядящие байты)"
    echo "3) Gecko (случайные байты и размер пакетов)"
    read -p "Выбор [1-3, Enter=2]: " OBFS_CHOICE
    case "$OBFS_CHOICE" in
        2|'')
            OBFS_ENABLED="true"
            OBFS_TYPE="salamander"
            OBFS_PASSWORD=$(random_secret) || die "Не удалось сгенерировать пароль обфускации"
            OBFS_MIN_PKT=""; OBFS_MAX_PKT=""
            ;;
        3)
            OBFS_ENABLED="true"
            OBFS_TYPE="gecko"
            OBFS_PASSWORD=$(random_secret) || die "Не удалось сгенерировать пароль обфускации"
            read -p "Gecko minPacketSize [512]: " OBFS_MIN_PKT
            read -p "Gecko maxPacketSize [1200]: " OBFS_MAX_PKT
            OBFS_MIN_PKT=${OBFS_MIN_PKT:-512}
            OBFS_MAX_PKT=${OBFS_MAX_PKT:-1200}
            [[ "$OBFS_MIN_PKT" =~ ^[1-9][0-9]{0,3}$ && "$OBFS_MAX_PKT" =~ ^[1-9][0-9]{0,3}$ ]] || die "Размеры пакетов должны быть положительными числами без ведущих нулей"
            (( OBFS_MIN_PKT >= 1 && OBFS_MIN_PKT <= OBFS_MAX_PKT && OBFS_MAX_PKT <= 2048 )) || die "Недопустимый диапазон размеров Gecko-пакетов"
            ;;
        1)
            OBFS_ENABLED="false"
            OBFS_TYPE=""
            OBFS_PASSWORD=""
            OBFS_MIN_PKT=""; OBFS_MAX_PKT=""
            ;;
        *) die "Недопустимый выбор обфускации" ;;
    esac

    echo -e "${GREEN}Загрузка Hysteria 2 для linux-${ARCH}...${NC}"
    local tmp_bin
    tmp_bin=$(mktemp "${BIN_PATH}.XXXXXX") || die "Не удалось создать временный файл бинарника"
    if ! LATEST_VER=$(latest_version) || ! download_verified_binary "$tmp_bin" "$LATEST_VER"; then
        rm -f "$tmp_bin"
        die "Не удалось загрузить или проверить Hysteria"
    fi
    chmod 755 "$tmp_bin"
    "$tmp_bin" version >/dev/null 2>&1 || { rm -f "$tmp_bin"; die "Загруженный бинарник Hysteria не прошёл проверку"; }
    install -m 0755 "$tmp_bin" "$BIN_PATH" || { rm -f "$tmp_bin"; die "Не удалось установить бинарник Hysteria"; }
    rm -f "$tmp_bin"

    mkdir -p "$HYSTERIA_DIR" "$CLIENTS_DIR" "$CLIENT_EXPORT_DIR" || die "Не удалось создать каталог Hysteria"
    : > "$CLIENTS_DB" || die "Не удалось создать базу клиентов"

    if [[ "$CERT_TYPE" == "self" ]]; then
        echo -e "${GREEN}Создание самоподписанного сертификата...${NC}"
        openssl ecparam -genkey -name prime256v1 -out "${HYSTERIA_DIR}/server.key" 2>/dev/null || die "Не удалось создать закрытый ключ сертификата"
        openssl req -new -x509 -days 36500 -key "${HYSTERIA_DIR}/server.key" -out "${HYSTERIA_DIR}/server.crt" -subj "/CN=$SERVER_IP" 2>/dev/null || die "Не удалось создать сертификат"
        chmod 600 "${HYSTERIA_DIR}/server.key" || die "Не удалось ограничить права закрытого ключа"
        chmod 644 "${HYSTERIA_DIR}/server.crt" || die "Не удалось установить права сертификата"
    fi

    cat <<EOF > "$SETTINGS_FILE" || die "Не удалось записать файл настроек"
SERVER_ADDR=$SERVER_ADDR
PORT=$PORT
HOP_RANGE=$HOP_RANGE
HOP_METHOD=$HOP_METHOD
INSECURE_FLAG=$INSECURE_FLAG
SNI=$SNI
OBFS_ENABLED=$OBFS_ENABLED
OBFS_TYPE=$OBFS_TYPE
OBFS_PASSWORD=$OBFS_PASSWORD
OBFS_MIN_PKT=$OBFS_MIN_PKT
OBFS_MAX_PKT=$OBFS_MAX_PKT
MASQ_DOMAIN=$MASQ_DOMAIN
CERT_TYPE=$CERT_TYPE
DOMAIN=$DOMAIN
ACME_EMAIL=$ACME_EMAIL
FIREWALL_BACKEND=$FIREWALL_BACKEND
EOF

    chmod 600 "$SETTINGS_FILE" "$CLIENTS_DB"
    while [[ ! -s "$CLIENTS_DB" ]]; do
        add_client || die "Ввод завершён до создания клиента"
          [[ -s "$CLIENTS_DB" ]] || echo -e "${YELLOW}Добавьте хотя бы одного клиента перед запуском сервера${NC}"
    done
    save_server_config || die "Не удалось применить конфигурацию сервера"
    systemctl enable hysteria || die "Не удалось включить сервис Hysteria"
    systemctl start hysteria || die "Не удалось запустить сервис Hysteria"
    systemctl is-active --quiet hysteria || die "Сервис Hysteria не запустился; проверьте journalctl -u hysteria"

    echo -e "${GREEN}Hysteria 2 успешно установлена и настроена!${NC}"
}

update_hysteria() {
    echo -e "
${BLUE}--- Обновление ядра ---${NC}"
    CURRENT_VER=$($BIN_PATH version 2>/dev/null | awk '/Version/ {print $2; exit}')
    echo -e "Текущая версия: ${YELLOW}$CURRENT_VER${NC}"
    echo "Проверка обновлений на GitHub..."
    if ! LATEST_VER=$(latest_version); then
        echo -e "${RED}Не удалось получить последнюю версию. Проверьте сеть.${NC}"
        return
    fi
    local latest_display="${LATEST_VER#app/}"
    echo -e "Последняя версия: ${GREEN}$latest_display${NC}"

    local current_normalized="${CURRENT_VER#v}" latest_normalized="${LATEST_VER#app/}"
    latest_normalized="${latest_normalized#v}"
    if [[ -n "$current_normalized" && "$current_normalized" == "$latest_normalized" ]]; then
        echo -e "${GREEN}Установлена последняя версия${NC}"
        return
    fi

    read -p "Обновить до $latest_display? [y/N]: " CONFIRM
    if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
        detect_arch
        echo -e "${GREEN}Загрузка версии $latest_display для linux-${ARCH}...${NC}"
        local tmp_bin backup_bin
        tmp_bin=$(mktemp "${BIN_PATH}.XXXXXX") || { echo -e "${RED}Не удалось создать временный файл бинарника${NC}"; return; }
        if ! download_verified_binary "$tmp_bin" "$LATEST_VER"; then
            rm -f "$tmp_bin"
            echo -e "${RED}Загрузка или проверка контрольной суммы не удалась; текущий бинарник сохранён${NC}"
            return
        fi
        chmod 755 "$tmp_bin"
        if ! "$tmp_bin" version >/dev/null 2>&1; then
            rm -f "$tmp_bin"
            echo -e "${RED}Загруженный бинарник не прошёл проверку; текущий бинарник сохранён${NC}"
            return
        fi
        backup_bin=$(mktemp "${BIN_PATH}.backup.XXXXXX") || { rm -f "$tmp_bin"; echo -e "${RED}Не удалось создать файл резервной копии${NC}"; return; }
        if ! cp -p "$BIN_PATH" "$backup_bin"; then
            rm -f "$tmp_bin" "$backup_bin"
            echo -e "${RED}Не удалось создать резервную копию текущего бинарника${NC}"
            return
        fi
        if ! mv -f "$tmp_bin" "$BIN_PATH"; then
            rm -f "$tmp_bin" "$backup_bin"
            echo -e "${RED}Не удалось установить новый бинарник; текущий сохранён${NC}"
            return
        fi
        rm -f "$tmp_bin"
        if ! systemctl restart hysteria || ! systemctl is-active --quiet hysteria; then
            echo -e "${RED}Новый бинарник не запустился; выполняется откат${NC}"
            if ! mv -f "$backup_bin" "$BIN_PATH"; then
                echo -e "${RED}Не удалось восстановить бинарник. Резервная копия сохранена: $backup_bin${NC}" >&2
                return
            fi
            systemctl restart hysteria || echo -e "${RED}Не удалось запустить сервис после отката; проверьте journalctl -u hysteria${NC}" >&2
            return
        fi
        rm -f "$backup_bin"
        echo -e "${GREEN}Hysteria 2 успешно обновлена!${NC}"
    else
        echo "Обновление отменено"
    fi
}

add_client() {
    load_settings
    validate_settings
    ensure_state_permissions
    echo -e "
${BLUE}--- Добавление клиента ---${NC}"
    read -p "Имя клиента (пустая строка — назад): " CLIENT_NAME || return 1
    if [[ -z "$CLIENT_NAME" ]]; then return; fi
    valid_name "$CLIENT_NAME" || { echo -e "${RED}Используйте 1–32 латинских букв, цифр, _ или -${NC}"; return; }
    if [[ -s "$CLIENTS_DB" ]] && ! validate_client_db; then return; fi
    if [[ -f "$CLIENTS_DB" ]] && awk -F'|' -v n="$CLIENT_NAME" '$1 == n { found=1 } END { exit !found }' "$CLIENTS_DB"; then
        echo -e "${RED}Клиент с таким именем уже существует${NC}"
        return
    fi

    local CC_CHOICE=2
    CLIENT_USER="$CLIENT_NAME"
    CLIENT_PASSWORD=$(random_secret) || { echo -e "${RED}Не удалось сгенерировать пароль клиента${NC}" >&2; return; }
    local DOWN="" UP=""
    local db_backup tmp_db
    db_backup=$(mktemp "${CLIENTS_DB}.backup.XXXXXX") || { echo -e "${RED}Не удалось создать резервную копию базы клиентов${NC}"; return; }
    cp -p "$CLIENTS_DB" "$db_backup" || { rm -f "$db_backup"; echo -e "${RED}Не удалось сохранить резервную копию базы клиентов${NC}"; return; }
    tmp_db=$(mktemp "${CLIENTS_DB}.XXXXXX") || { rm -f "$db_backup"; echo -e "${RED}Не удалось подготовить базу клиентов${NC}" >&2; return; }
    if ! awk '{print}' "$CLIENTS_DB" > "$tmp_db" || ! printf '%s|%s|%s|%s|%s|%s\n' "$CLIENT_NAME" "$CLIENT_USER" "$CLIENT_PASSWORD" "$CC_CHOICE" "$DOWN" "$UP" >> "$tmp_db" || ! chmod 600 "$tmp_db" || ! mv -f "$tmp_db" "$CLIENTS_DB"; then
        rm -f "$tmp_db" "$db_backup"
        echo -e "${RED}Не удалось обновить базу клиентов${NC}"
        return
    fi
    if ! rebuild_client_profiles; then
        if ! mv -f "$db_backup" "$CLIENTS_DB"; then
            echo -e "${RED}Не удалось восстановить базу клиентов. Резервная копия: $db_backup${NC}" >&2
            return
        fi
        rm -f "${CLIENTS_DIR:?}/${CLIENT_NAME}.yaml" "${CLIENT_EXPORT_DIR:?}/${CLIENT_NAME}_hysteria.yaml"
        rebuild_client_profiles || echo -e "${RED}Не удалось восстановить профили клиентов${NC}" >&2
        echo -e "${RED}Клиент не добавлен: не удалось создать профиль${NC}" >&2
        return
    fi
    chmod 600 "$CLIENTS_DB"
    if [[ -f "$CONFIG_FILE" ]]; then
        if ! save_server_config; then
            if ! mv -f "$db_backup" "$CLIENTS_DB"; then
                echo -e "${RED}Не удалось восстановить базу клиентов. Резервная копия: $db_backup${NC}" >&2
                return
            fi
            rm -f "${CLIENTS_DIR:?}/${CLIENT_NAME}.yaml" "${CLIENT_EXPORT_DIR:?}/${CLIENT_NAME}_hysteria.yaml"
            rebuild_client_profiles || echo -e "${RED}Не удалось восстановить профили клиентов${NC}" >&2
            echo -e "${RED}Клиент не добавлен: конфигурацию сервера не удалось перезагрузить${NC}"
            return
        fi
    fi
    rm -f "$db_backup"
    echo -e "${GREEN}Конфигурация сохранена в ${CLIENT_EXPORT_DIR}/${CLIENT_NAME}_hysteria.yaml${NC}"
    print_qr "$HY2_LINK"
    echo -e "${YELLOW}Ссылка: ${NC}$HY2_LINK"
}

print_qr() {
    local data="$1"
    if [[ -z "$data" ]]; then
        echo -e "${RED}Не удалось показать QR: ссылка клиента пуста${NC}" >&2
        return 1
    fi
    if ! command -v qrencode >/dev/null 2>&1; then
        echo -e "${RED}Не удалось показать QR: команда qrencode не найдена${NC}" >&2
        return 1
    fi
    if ! printf '%s' "$data" | qrencode -t ANSI; then
        echo -e "${RED}Не удалось сгенерировать QR-код. Используйте ссылку ниже.${NC}" >&2
        return 1
    fi
}

list_clients() {
    if [ ! -f "$CLIENT_LIST" ] || [ ! -s "$CLIENT_LIST" ]; then
        echo -e "${RED}Клиенты не найдены${NC}"
        return
    fi
    echo -e "
${BLUE}--- Список клиентов ---${NC}"
    local names=()
    local links=()
    local i=1
    while IFS='|' read -r name link; do
        name=$(echo "$name" | xargs)
        link=$(echo "$link" | xargs)
        if [[ -n "$name" ]]; then
            echo "$i) $name"
            names+=("$name")
            links+=("$link")
            ((i++))
        fi
    done < "$CLIENT_LIST"
    echo ""
    read -p "Номер клиента для показа QR (пустая строка — назад): " CLIENT_NUM
    if [[ -z "$CLIENT_NUM" ]]; then return; fi
    if [[ "$CLIENT_NUM" =~ ^[1-9][0-9]{0,8}$ ]] && [ "$CLIENT_NUM" -le "${#names[@]}" ]; then
        local idx=$((CLIENT_NUM - 1))
        echo ""
        echo -e "Клиент: ${YELLOW}${names[$idx]}${NC}"
        print_qr "${links[$idx]}"
        echo -e "Ссылка: ${links[$idx]}"
    else
        echo -e "${RED}Недопустимый выбор${NC}"
    fi
}

delete_client() {
    if [ ! -f "$CLIENTS_DB" ] || [ ! -s "$CLIENTS_DB" ]; then
        echo -e "${RED}Нет клиентов для удаления${NC}"
        return
    fi
    echo -e "
${BLUE}--- Удаление клиента ---${NC}"
    local names=()
    local i=1
    while IFS='|' read -r name client_user client_password cc_choice down up || [[ -n "$name$client_user$client_password$cc_choice$down$up" ]]; do
        if [[ -n "$name" ]]; then
            echo "$i) $name"
            names+=("$name")
            ((i++))
        fi
    done < "$CLIENTS_DB"
    echo ""
    read -p "Номер клиента для удаления (пустая строка — назад): " DEL_NUM
    if [[ -z "$DEL_NUM" ]]; then return; fi
    if [[ "$DEL_NUM" =~ ^[1-9][0-9]{0,8}$ ]] && [ "$DEL_NUM" -le "${#names[@]}" ]; then
        local idx=$((DEL_NUM - 1))
        local DEL_NAME="${names[$idx]}"
        valid_name "$DEL_NAME" || { echo -e "${RED}Недопустимое имя клиента в базе${NC}" >&2; return; }
        if (( ${#names[@]} == 1 )); then
            echo -e "${RED}Нельзя удалить последнего клиента: серверу нужна хотя бы одна учётная запись${NC}"
            return
        fi
        local tmp_db db_backup
        db_backup=$(mktemp "${CLIENTS_DB}.backup.XXXXXX") || return
        cp -p "$CLIENTS_DB" "$db_backup" || { rm -f "$db_backup"; return; }
        tmp_db=$(mktemp "${CLIENTS_DB}.XXXXXX") || { rm -f "$db_backup"; return; }
        if ! awk -F'|' -v n="$DEL_NAME" '$1 != n' "$CLIENTS_DB" > "$tmp_db" || [[ ! -s "$tmp_db" ]] || ! chmod 600 "$tmp_db" || ! mv -f "$tmp_db" "$CLIENTS_DB"; then
            rm -f "$tmp_db" "$db_backup"
            echo -e "${RED}Не удалось подготовить базу клиентов. Удаление отменено.${NC}" >&2
            return
        fi
        if ! rebuild_client_profiles; then
            if ! mv -f "$db_backup" "$CLIENTS_DB"; then
                echo -e "${RED}Не удалось восстановить базу клиентов. Резервная копия: $db_backup${NC}" >&2
                return
            fi
            rebuild_client_profiles || echo -e "${RED}Не удалось восстановить профили клиентов${NC}" >&2
            echo -e "${RED}Клиент не удалён: не удалось пересоздать профили${NC}" >&2
            return
        fi
        if ! save_server_config; then
            if ! mv -f "$db_backup" "$CLIENTS_DB"; then
                echo -e "${RED}Не удалось восстановить базу клиентов. Резервная копия: $db_backup${NC}" >&2
                return
            fi
            rebuild_client_profiles || echo -e "${RED}Не удалось восстановить профили клиентов${NC}" >&2
            echo -e "${RED}Клиент '$DEL_NAME' не удалён: конфигурацию сервера не удалось перезагрузить${NC}"
            return
        fi
        rm -f "$db_backup"
        rm -f "${CLIENTS_DIR:?}/${DEL_NAME}.yaml" "${CLIENT_EXPORT_DIR:?}/${DEL_NAME}_hysteria.yaml"
        echo -e "${GREEN}Клиент '$DEL_NAME' успешно удалён${NC}"
    else
        echo -e "${RED}Недопустимый выбор${NC}"
    fi
}

modify_settings() {
    load_settings
    if [[ ! -s "$CLIENTS_DB" ]]; then
        echo -e "${YELLOW}Добавьте хотя бы одного клиента перед изменением настроек сервера${NC}"
        return
    fi
    local settings_backup settings_write_failed=false
    settings_backup=$(mktemp "${SETTINGS_FILE}.backup.XXXXXX") || return
    cp -p "$SETTINGS_FILE" "$settings_backup" || { rm -f "$settings_backup"; return; }
    echo -e "
${BLUE}--- Настройки сервера ---${NC}"
    echo "1) Изменить основной порт ($PORT)"
    echo "2) Изменить/выключить диапазон port hopping (${HOP_RANGE:-выключен})"
    echo "3) Изменить маскировку ($MASQ_DOMAIN)"
    echo "4) Изменить обфускацию (${OBFS_ENABLED:-false}, тип=${OBFS_TYPE:-нет})"
    echo "0) Назад"
    read -p "Выбор: " MOD_CHOICE
    case $MOD_CHOICE in
        1)
            read -p "Новый основной порт (например, 443): " NEW_PORT
            if [[ -n "$NEW_PORT" ]] && valid_port "$NEW_PORT"; then
                if [[ -n "$HOP_RANGE" ]] && port_in_range "$NEW_PORT" "$HOP_RANGE"; then
                    echo -e "${RED}Основной порт должен находиться вне диапазона port hopping${NC}"
                    rm -f "$settings_backup"
                    return
                fi
                write_setting PORT "$NEW_PORT"
                PORT=$NEW_PORT
            elif [[ -n "$NEW_PORT" ]]; then
                echo -e "${RED}Недопустимый порт${NC}"; rm -f "$settings_backup"; return
            fi
            ;;
        2)
            echo -e "
${YELLOW}Текущий диапазон: ${HOP_RANGE:-нет}  |  Метод: ${HOP_METHOD:-нет}${NC}"
            read -p "Новый диапазон (например, 20000-50000) или '0' для отключения: " NEW_RANGE
            if [[ "$NEW_RANGE" == "0" ]]; then
                write_setting HOP_RANGE ""
                write_setting HOP_METHOD ""
                write_setting FIREWALL_BACKEND ""
                HOP_RANGE=""
                HOP_METHOD=""
            elif [[ -n "$NEW_RANGE" ]] && valid_range "$NEW_RANGE"; then
                ! port_in_range "$PORT" "$NEW_RANGE" || { echo -e "${RED}Основной порт должен находиться вне диапазона${NC}"; rm -f "$settings_backup"; return; }
                echo -e "
Метод port hopping:"
                echo "1) Native (Hysteria сама управляет firewall — рекомендуется)"
                echo "2) Через iptables"
                echo "3) Через nftables"
                read -p "Выбор [1-3]: " HOP_CHOICE
                case "$HOP_CHOICE" in
                    2) NEW_METHOD="iptables"; NEW_FW="iptables"; CMD_CHECK="iptables" ;;
                    3) NEW_METHOD="nftables"; NEW_FW="nftables"; CMD_CHECK="nft" ;;
                    1|'') NEW_METHOD="native"; NEW_FW=""; CMD_CHECK="" ;;
                    *) echo -e "${RED}Недопустимый метод port hopping${NC}"; rm -f "$settings_backup"; return ;;
                esac
                if [[ -n "$CMD_CHECK" ]] && ! command -v "$CMD_CHECK" >/dev/null 2>&1; then
                    FIREWALL_BACKEND=$NEW_FW
                    install_deps || { FIREWALL_BACKEND=""; rm -f "$settings_backup"; echo -e "${RED}Настройки не изменены: зависимости не установлены${NC}" >&2; return; }
                fi
                write_setting HOP_RANGE "$NEW_RANGE"
                HOP_RANGE=$NEW_RANGE
                write_setting HOP_METHOD "$NEW_METHOD"
                HOP_METHOD=$NEW_METHOD
                if [[ -n "$NEW_FW" ]]; then
                    write_setting FIREWALL_BACKEND "$NEW_FW"
                    FIREWALL_BACKEND=$NEW_FW
                else
                    write_setting FIREWALL_BACKEND ""
                    FIREWALL_BACKEND=""
                fi
            elif [[ -n "$NEW_RANGE" ]]; then
                echo -e "${RED}Недопустимый диапазон портов${NC}"; rm -f "$settings_backup"; return
            fi
            ;;
        3)
            read -p "Новый домен маскировки: " MASQ_DOMAIN
            valid_host "$MASQ_DOMAIN" || { echo -e "${RED}Недопустимый домен${NC}"; rm -f "$settings_backup"; return; }
            write_setting MASQ_DOMAIN "$MASQ_DOMAIN"
            ;;
        4)
            echo -e "
Текущее состояние: включена=${OBFS_ENABLED:-false}, тип=${OBFS_TYPE:-нет}"
            echo "1) Выключить"
            echo "2) Включить Salamander (рекомендуется)"
            echo "3) Включить Gecko"
            read -p "Выбор [1-3]: " OBFS_MOD
            case "$OBFS_MOD" in
                1)
                    write_setting OBFS_ENABLED false
                    write_setting OBFS_TYPE ""
                    OBFS_ENABLED="false"; OBFS_TYPE=""
                    ;;
                2)
                    NEW_PWD=$(random_secret) || { echo -e "${RED}Не удалось сгенерировать пароль обфускации${NC}" >&2; rm -f "$settings_backup"; return; }
                    write_setting OBFS_ENABLED true
                    write_setting OBFS_TYPE salamander
                    write_setting OBFS_PASSWORD "$NEW_PWD"
                    write_setting OBFS_MIN_PKT ""
                    write_setting OBFS_MAX_PKT ""
                    OBFS_ENABLED="true"; OBFS_TYPE="salamander"; OBFS_PASSWORD=$NEW_PWD
                    ;;
                3)
                    NEW_PWD=$(random_secret) || { echo -e "${RED}Не удалось сгенерировать пароль обфускации${NC}" >&2; rm -f "$settings_backup"; return; }
                    read -p "Gecko minPacketSize [512]: " NEW_MIN
                    read -p "Gecko maxPacketSize [1200]: " NEW_MAX
                    NEW_MIN=${NEW_MIN:-512}; NEW_MAX=${NEW_MAX:-1200}
                    [[ "$NEW_MIN" =~ ^[1-9][0-9]{0,3}$ && "$NEW_MAX" =~ ^[1-9][0-9]{0,3}$ ]] && (( NEW_MIN <= NEW_MAX && NEW_MAX <= 2048 )) || { echo -e "${RED}Укажите размеры от 1 до 2048 без ведущих нулей; минимальный размер не должен превышать максимальный${NC}"; rm -f "$settings_backup"; return; }
                    write_setting OBFS_ENABLED true
                    write_setting OBFS_TYPE gecko
                    write_setting OBFS_PASSWORD "$NEW_PWD"
                    write_setting OBFS_MIN_PKT "$NEW_MIN"
                    write_setting OBFS_MAX_PKT "$NEW_MAX"
                    OBFS_ENABLED="true"; OBFS_TYPE="gecko"; OBFS_PASSWORD=$NEW_PWD
                    OBFS_MIN_PKT=$NEW_MIN; OBFS_MAX_PKT=$NEW_MAX
                    ;;
            esac
            ;;
        0) rm -f "$settings_backup"; return ;;
        *) echo "Недопустимый выбор"; rm -f "$settings_backup"; return ;;
    esac
    if [[ "$settings_write_failed" == true ]]; then
        if mv -f "$settings_backup" "$SETTINGS_FILE"; then
            echo -e "${RED}Не удалось записать настройки. Предыдущие настройки восстановлены${NC}" >&2
        else
            echo -e "${RED}Не удалось восстановить настройки. Резервная копия: $settings_backup${NC}" >&2
        fi
        return
    fi
    if save_server_config; then
        if rebuild_client_profiles; then
            rm -f "$settings_backup"
            echo -e "${GREEN}Настройки обновлены. Конфигурации клиентов и QR-ссылки пересозданы${NC}"
        else
            mv -f "$settings_backup" "$SETTINGS_FILE"
            save_server_config >/dev/null 2>&1 || true
            rebuild_client_profiles >/dev/null 2>&1 || true
            echo -e "${RED}Настройки восстановлены: профили клиентов не удалось пересоздать${NC}"
        fi
    else
        if ! mv -f "$settings_backup" "$SETTINGS_FILE"; then
            echo -e "${RED}Не удалось восстановить настройки. Резервная копия: $settings_backup${NC}" >&2
            return
        fi
        rebuild_client_profiles >/dev/null 2>&1 || true
        echo -e "${RED}Настройки не применены. Проверьте сообщение об ошибке выше${NC}"
    fi
}

uninstall_hysteria() {
    if ! systemctl stop hysteria; then
        echo -e "${RED}Не удалось остановить сервис Hysteria. Файлы не удалены.${NC}" >&2
        return 1
    fi
    if ! systemctl disable hysteria; then
        echo -e "${RED}Не удалось отключить автозапуск Hysteria. Файлы не удалены.${NC}" >&2
        return 1
    fi
    cleanup_firewall
    local failed=false
    rm -rf -- "$HYSTERIA_DIR" || failed=true
    rm -f -- /etc/systemd/system/hysteria.service /etc/systemd/system/hysteria.service.previous "$BIN_PATH" "${BIN_PATH}.previous" || failed=true
    systemctl daemon-reload || failed=true
    if [[ "$failed" == true ]]; then
        echo -e "${RED}Удаление выполнено не полностью. Проверьте сообщения об ошибках и оставшиеся файлы Hysteria.${NC}" >&2
        return 1
    fi
    echo -e "${GREEN}Файлы Hysteria и сервиса удалены${NC}"
}

update_manager() {
    local tmp_file snapshot_json snapshot_sha snapshot_date snapshot_date_local downloaded_at timezone_label
    if ! command -v curl >/dev/null 2>&1; then
        echo -e "${RED}Команда curl не найдена. Обновление менеджера невозможно${NC}"
        return
    fi
    tmp_file=$(mktemp "${SCRIPT_PATH}.update.XXXXXX") || {
        echo -e "${RED}Не удалось создать временный файл обновления${NC}"
        return
    }
    echo -e "${GREEN}Проверка обновлений менеджера...${NC}"
    if ! curl -q --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 15 --max-time 120 \
        -o "$tmp_file" "$MANAGER_RAW_URL"; then
        rm -f "$tmp_file"
        echo -e "${RED}Не удалось скачать обновление по публичной raw-ссылке${NC}"
        return
    fi
    if [[ ! -s "$tmp_file" ]]; then
        rm -f "$tmp_file"
        echo -e "${RED}Сервер вернул пустой файл обновления${NC}"
        return
    fi
    timezone_label=$(date '+%Z (%z)' 2>/dev/null || printf 'локальная зона недоступна')
    downloaded_at=$(date "+%Y-%m-%d %H:%M:%S %Z (%z)" 2>/dev/null || printf 'время недоступно')
    if snapshot_json=$(curl -q --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 15 --max-time 30 \
        -A 'hysteria-manager' "$MANAGER_COMMITS_API_URL"); then
        if command -v jq >/dev/null 2>&1; then
            snapshot_sha=$(printf '%s' "$snapshot_json" | jq -r '.[0].sha // empty' 2>/dev/null)
            snapshot_date=$(printf '%s' "$snapshot_json" | jq -r '.[0].commit.committer.date // empty' 2>/dev/null)
        fi
    fi
    if [[ -n "$snapshot_sha" && -n "$snapshot_date" ]]; then
        snapshot_date_local=$(date -d "$snapshot_date" '+%Y-%m-%d %H:%M:%S %Z (%z)' 2>/dev/null || printf '%s (локальная зона: %s)' "$snapshot_date" "$timezone_label")
        echo -e "${GREEN}Снимок скрипта: ${snapshot_date_local}, commit ${snapshot_sha:0:12}${NC}"
    else
        echo -e "${YELLOW}Снимок загружен: ${downloaded_at}; дату коммита получить не удалось${NC}"
    fi
    if [[ "$(head -n 1 "$tmp_file")" != '#!/bin/bash' ]] || ! grep -Fxq '# Hysteria 2 Manager' "$tmp_file"; then
        rm -f "$tmp_file"
        echo -e "${RED}Загруженный файл не похож на скрипт Hysteria 2 Manager. Текущий файл сохранён.${NC}"
        return
    fi
    if ! bash -n "$tmp_file"; then
        rm -f "$tmp_file"
        echo -e "${RED}Новая версия не прошла синтаксическую проверку. Текущий скрипт сохранён.${NC}"
        return
    fi
    if cmp -s "$tmp_file" "$SCRIPT_PATH"; then
        rm -f "$tmp_file"
        echo -e "${GREEN}Установлена последняя версия менеджера${NC}"
        return
    fi
    chmod --reference="$SCRIPT_PATH" "$tmp_file" 2>/dev/null || chmod 755 "$tmp_file"
    if ! mv -f "$tmp_file" "$SCRIPT_PATH"; then
        rm -f "$tmp_file"
        echo -e "${RED}Не удалось заменить файл скрипта${NC}"
        return
    fi
    echo -e "${GREEN}Скрипт обновлён${NC}"
    echo -e "${GREEN}Перезапуск...${NC}"
    exec bash "$SCRIPT_PATH"
}

# MAIN LOOP
if [ ! -f "$BIN_PATH" ]; then
    install_hysteria
fi
if [[ ! -f "$SETTINGS_FILE" || ! -f "$CLIENTS_DB" || ! -f "$CONFIG_FILE" ]]; then
    die "Найден бинарник Hysteria, но файлы менеджера неполны. Автоматическое управление остановлено, чтобы не изменить существующую установку. Сначала сделайте резервную копию $HYSTERIA_DIR и проверьте настройки, базу клиентов и конфигурацию сервера."
fi

while true; do
    echo -e "
${BLUE}Менеджер Hysteria 2${NC}"
    echo "1) Добавить клиента"
    echo "2) Список клиентов / QR"
    echo "3) Удалить клиента"
    echo "4) Настройки сервера"
    echo "5) Обновить ядро Hysteria"
    echo "7) Удалить Hysteria"
    echo "99) Обновить скрипт"
    echo "0) Выход"
    read -p "Выбор: " MAIN_CHOICE || { echo; break; }
    case $MAIN_CHOICE in
        1) add_client ;;
        2) list_clients ;;
        3) delete_client ;;
        4) modify_settings ;;
        5) update_hysteria ;;
        99) update_manager ;;
        7)
            read -p "Вы уверены? [y/N]: " CONFIRM
            if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
                uninstall_hysteria
                break
            fi
            ;;
        0) exit 0 ;;
        *) echo -e "${RED}Недопустимый выбор${NC}" ;;
    esac
done
