#!/usr/bin/env bash
# IntelSOC Linux collector. Ubuntu/Debian with systemd only.
set -Eeuo pipefail
umask 077

SERVER_HOST="${INTELSOC_SERVER_HOST:-Pareezyy.local}"
SERVER_IP="${INTELSOC_SERVER_IP:-192.168.1.6}"
SERVER_PORT="${INTELSOC_SERVER_PORT:-8445}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CA_SOURCE="$SCRIPT_DIR/intelsoc-caddy-root.crt"
CA_PATH="/usr/local/share/ca-certificates/intelsoc/intelsoc-caddy-root.crt"
CONFIG_FILE="/etc/fluent-bit/fluent-bit.conf"
ENV_FILE="/etc/default/fluent-bit"
DROPIN_DIR="/etc/systemd/system/fluent-bit.service.d"
DROPIN_FILE="$DROPIN_DIR/10-intelsoc-environment.conf"
AUDIT_RULE="/etc/audit/rules.d/80-intelsoc-identity.rules"
STATE_DIR="/var/lib/fluent-bit/intelsoc"
MIGRATE=0
DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    --migrate-existing) MIGRATE=1 ;;
    --dry-run) DRY_RUN=1 ;;
    *) echo "Unknown argument: $arg" >&2; exit 2 ;;
  esac
done

step(){ printf '\n==> %s\n' "$*"; }
die(){ echo "ERROR: $*" >&2; exit 1; }
[[ $EUID == 0 ]] || die "Run with sudo."
[[ -f "$CA_SOURCE" ]] || die "Place intelsoc-caddy-root.crt beside the installer."
[[ -r /etc/os-release ]] || die "Unsupported OS: missing os-release."
# shellcheck source=/dev/null
. /etc/os-release
[[ "${ID:-}" == ubuntu || "${ID:-}" == debian ]] || die "Only Ubuntu/Debian supported."
command -v systemctl >/dev/null || die "systemd required."
[[ "$SERVER_PORT" =~ ^[0-9]{1,5}$ ]] && (( SERVER_PORT >= 1 && SERVER_PORT <= 65535 )) || die "Invalid server port."
[[ "$SERVER_HOST" =~ ^[a-zA-Z0-9.-]+$ ]] || die "Invalid server hostname."
[[ "$SERVER_IP" =~ ^[0-9a-fA-F:.]+$ ]] || die "Invalid server IP."

# Existing agent identities must not be silently replaced or re-enrolled.
existing=0
for path in "$CONFIG_FILE" "$ENV_FILE" "$DROPIN_FILE" "$AUDIT_RULE"; do
  [[ ! -e "$path" ]] || existing=1
done
if (( DRY_RUN )); then
  step "Preflight successful (read-only). Existing files: $existing. OS: ${PRETTY_NAME:-$ID}"
  echo "Telemetry: SSH journald, sudo journald, supported auditd account/group plus keyed identity-change SYSCALL."
  echo "No process EXECVE auditing enabled."
  if (( existing )); then
    echo "Existing installation: yes; managed migration requires separate approval (--migrate-existing)."
  else
    echo "Existing installation: no; fresh installation eligible."
  fi
  exit 0
fi
if (( existing && ! MIGRATE )); then
  die "Existing Fluent Bit/IntelSOC files detected. Nothing changed. Inspect/backup first, then rerun with --migrate-existing."
fi

# A migratable installation may contain an unrelated collector; back it up before any modification.
BACKUP_DIR="/var/backups/intelsoc-agent/$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
for path in "$CONFIG_FILE" "$ENV_FILE" "$DROPIN_FILE" "$AUDIT_RULE" /etc/hosts; do
  if [[ -f "$path" ]]; then
    mkdir -p "$BACKUP_DIR$(dirname "$path")"
    cp -p -- "$path" "$BACKUP_DIR$path"
  fi
done
step "Backed up existing files to $BACKUP_DIR"
COMMITTED=0
rollback() {
  local rc="$?"
  if (( rc != 0 && COMMITTED == 0 )); then
    echo "IntelSOC install failed; restoring backed-up configuration files." >&2
    for path in "$CONFIG_FILE" "$ENV_FILE" "$DROPIN_FILE" "$AUDIT_RULE" /etc/hosts; do
      if [[ -f "$BACKUP_DIR$path" ]]; then
        cp -p -- "$BACKUP_DIR$path" "$path" || true
      elif [[ "$path" != /etc/hosts ]]; then
        rm -f -- "$path" || true
      fi
    done
    systemctl daemon-reload >/dev/null 2>&1 || true
    # Preserve the previous service state where possible.
    systemctl try-restart fluent-bit >/dev/null 2>&1 || true
    echo "Saved backup: $BACKUP_DIR" >&2
  fi
}
trap rollback EXIT

step "Installing prerequisites and approved audit collection dependencies"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl gnupg jq auditd

# Stage certificate in system trust store; HTTPS checks fail closed.
step "Configuring IntelSOC CA and endpoint hostname"
install -d -m 0755 "$(dirname "$CA_PATH")"
install -m 0644 "$CA_SOURCE" "$CA_PATH"
update-ca-certificates >/dev/null
if ! getent ahostsv4 "$SERVER_HOST" | awk '{print $1}' | grep -Fxq "$SERVER_IP"; then
  # Modify only our exact host entry, with an existing-file backup above.
  tmp_hosts="$(mktemp)"
  awk -v h="$SERVER_HOST" '{found=0; for(i=2;i<=NF;i++) if($i==h) found=1; if(!found) print}' /etc/hosts > "$tmp_hosts"
  printf '%s %s\n' "$SERVER_IP" "$SERVER_HOST" >> "$tmp_hosts"
  cat "$tmp_hosts" > /etc/hosts
  rm -f "$tmp_hosts"
fi

BASE_URL="https://${SERVER_HOST}:${SERVER_PORT}"
step "Verifying certificate, hostname, and API health"
curl --fail --silent --show-error --connect-timeout 8 --max-time 20 \
  --cacert "$CA_SOURCE" "$BASE_URL/api/v1/health" >/dev/null \
  || die "HTTPS health verification failed. Fluent Bit was not modified."

# Reuse existing device credential if present. Never echo credentials.
DEVICE_ID=""; INGEST_KEY=""
if [[ -f "$ENV_FILE" ]]; then
  DEVICE_ID="$(sed -n 's/^INTELSOC_DEVICE_ID=//p' "$ENV_FILE" | head -n 1)"
  INGEST_KEY="$(sed -n 's/^INTELSOC_INGEST_API_KEY=//p' "$ENV_FILE" | head -n 1)"
  # Legacy IntelSOC endpoints should be migrated without minting another identity.
  if [[ -n "$DEVICE_ID" && -z "$INGEST_KEY" ]] || [[ -z "$DEVICE_ID" && -n "$INGEST_KEY" ]]; then
    die "Partial existing enrollment. Restore/repair credentials manually; no re-enrollment attempted."
  fi
fi
if [[ -z "$DEVICE_ID" ]]; then
  step "Secure endpoint enrollment"
  if [[ -n "${INTELSOC_ENROLLMENT_TOKEN:-}" ]]; then
    ENROLLMENT_TOKEN="$INTELSOC_ENROLLMENT_TOKEN"
  else
    read -rsp 'IntelSOC enrollment token: ' ENROLLMENT_TOKEN </dev/tty
    printf '\n'
  fi
  payload="$(jq -nc --arg h "$(hostname)" '{hostname:$h,platform:"linux"}')"
  response="$(curl --fail --silent --show-error --connect-timeout 8 --max-time 30 \
      --cacert "$CA_SOURCE" -X POST "$BASE_URL/api/v1/devices/enroll" \
      -H 'Content-Type: application/json' \
      -H "X-IntelSOC-Enrollment-Token: $ENROLLMENT_TOKEN" --data "$payload")" \
      || die "Enrollment failed; installer did not modify Fluent Bit."
  unset ENROLLMENT_TOKEN INTELSOC_ENROLLMENT_TOKEN
  DEVICE_ID="$(jq -er '.device_id | select(type=="string" and length>0)' <<<"$response")" || die 'Missing device_id'
  INGEST_KEY="$(jq -er '.ingest_key | select(type=="string" and length>0)' <<<"$response")" || die 'Missing ingest_key'
fi
[[ "$DEVICE_ID" =~ ^[a-zA-Z0-9-]+$ ]] || die "Unexpected device ID format."
[[ "$INGEST_KEY" =~ ^[a-zA-Z0-9._-]+$ ]] || die "Ingest credential contains unsupported characters."

step "Installing Fluent Bit from signed package repository"
install -d -m 0755 /usr/share/keyrings
curl --fail --silent --show-error --location https://packages.fluentbit.io/fluentbit.key \
  | gpg --batch --yes --dearmor -o /usr/share/keyrings/fluentbit-keyring.gpg
chmod 644 /usr/share/keyrings/fluentbit-keyring.gpg
CODENAME="${VERSION_CODENAME:-}"
[[ "$CODENAME" =~ ^[a-zA-Z0-9]+$ ]] || die "Missing/invalid OS codename."
if [[ "$ID" == ubuntu ]]; then
  repo_url="https://packages.fluentbit.io/ubuntu/$CODENAME"
else
  repo_url="https://packages.fluentbit.io/debian/$CODENAME"
fi
printf 'deb [signed-by=/usr/share/keyrings/fluentbit-keyring.gpg] %s %s main\n' "$repo_url" "$CODENAME" > /etc/apt/sources.list.d/fluent-bit.list
apt-get update
apt-get install -y fluent-bit

# Dedicated state files; do not delete any pre-existing offsets or buffer chunks.
step "Installing narrowly scoped Linux telemetry configuration"
install -d -m 0700 "$STATE_DIR" "$STATE_DIR/buffer"
install -d -m 0755 /etc/fluent-bit "$DROPIN_DIR" /etc/audit/rules.d

cat > "$CONFIG_FILE" <<EOF
# Managed by IntelSOC Linux deployment kit. Preserve raw security evidence.
[SERVICE]
    Flush             1
    Daemon            Off
    Log_Level         info
    storage.path      ${STATE_DIR}/buffer
    storage.sync      full
    storage.checksum  on

# Approved source 1: SSH authentication and related PAM messages.
[INPUT]
    Name              systemd
    Tag               intelsoc.linux.ssh
    Systemd_Filter    _SYSTEMD_UNIT=ssh.service
    Read_From_Tail    On
    DB                ${STATE_DIR}/ssh.db
    Max_Entries       20
    storage.type      filesystem

# Approved source 2: sudo authentication and elevation activity.
[INPUT]
    Name              systemd
    Tag               intelsoc.linux.sudo
    Systemd_Filter    SYSLOG_IDENTIFIER=sudo
    Read_From_Tail    On
    DB                ${STATE_DIR}/sudo.db
    Max_Entries       20
    storage.type      filesystem

# Approved source 3: auditd account/group changes and keyed identity-file writes.
# Filter to backend-supported audit types; an unsupported record would reject a batch.
[INPUT]
    Name              tail
    Tag               intelsoc.linux.audit
    Path              /var/log/audit/audit.log
    DB                ${STATE_DIR}/audit.db
    Read_from_Head    Off
    Skip_Long_Lines   On
    Mem_Buf_Limit     10MB
    storage.type      filesystem

[FILTER]
    Name              grep
    Match             intelsoc.linux.audit
    Regex             log ^type=(ADD_USER|DEL_USER|USER_MGMT|ADD_GROUP|DEL_GROUP|GRP_MGMT)([[:space:]]|$)|^type=SYSCALL[[:space:]].*key=.*intelsoc_identity_change

[OUTPUT]
    Name               http
    Match              intelsoc.linux.*
    Host               ${SERVER_HOST}
    Port               ${SERVER_PORT}
    URI                /api/v1/events/linux
    Format             json
    Json_Date_Key      false
    Header             Content-Type application/json
    Header             X-IntelSOC-Key \${INTELSOC_INGEST_API_KEY}
    Header             X-Device-ID \${INTELSOC_DEVICE_ID}
    tls                On
    tls.verify         On
    tls.verify_hostname On
    tls.ca_file        ${CA_PATH}
    Retry_Limit        False
    Log_Response_Payload Off
EOF

cat > "$ENV_FILE" <<EOF
INTELSOC_INGEST_API_KEY=${INGEST_KEY}
INTELSOC_DEVICE_ID=${DEVICE_ID}
EOF
chmod 600 "$ENV_FILE" "$CONFIG_FILE"
unset INGEST_KEY

# Do not enable broad EXECVE collection; limited to identity files and supported events.
cat > "$AUDIT_RULE" <<'EOF'
# IntelSOC: targeted identity database modifications only.
-w /etc/passwd -p wa -k intelsoc_identity_change
-w /etc/group -p wa -k intelsoc_identity_change
-w /etc/shadow -p wa -k intelsoc_identity_change
-w /etc/gshadow -p wa -k intelsoc_identity_change
EOF
chmod 640 "$AUDIT_RULE"

# Validate Fluent Bit before restarting service. Keep rollback copies available.
FB_BIN="$(command -v fluent-bit || true)"
if [[ -z "$FB_BIN" && -x /opt/fluent-bit/bin/fluent-bit ]]; then FB_BIN=/opt/fluent-bit/bin/fluent-bit; fi
[[ -n "$FB_BIN" ]] || die "Fluent Bit binary missing. Restore from $BACKUP_DIR."
# Explicitly load this managed configuration, regardless of package defaults.
cat > "$DROPIN_FILE" <<EOF
[Service]
EnvironmentFile=/etc/default/fluent-bit
ExecStart=
ExecStart=${FB_BIN} -c ${CONFIG_FILE}
EOF
chmod 644 "$DROPIN_FILE"
step "Validating Fluent Bit configuration"
set -a
# shellcheck source=/dev/null
. "$ENV_FILE"
set +a
"$FB_BIN" --dry-run -c "$CONFIG_FILE" || die "Fluent Bit validation failed. Restore from $BACKUP_DIR."
unset INTELSOC_INGEST_API_KEY INTELSOC_DEVICE_ID

step "Enabling targeted audit rules and collector service"
systemctl enable auditd
systemctl is-active --quiet auditd || systemctl start auditd
augenrules --load || die "Audit rules not loaded. Restore from $BACKUP_DIR."
systemctl daemon-reload
systemctl enable fluent-bit
systemctl restart fluent-bit
systemctl is-active --quiet fluent-bit || die "Fluent Bit failed to start. Restore from $BACKUP_DIR."
systemctl is-enabled --quiet fluent-bit || die "Fluent Bit is not enabled."

COMMITTED=1
step "IntelSOC Linux deployment complete"
echo "Device ID: $DEVICE_ID"
echo "Service: fluent-bit active and enabled"
echo "Telemetry: SSH, sudo, account/group audit, keyed identity changes"
echo "Process EXECVE: disabled until approved validation"
echo "Backup: $BACKUP_DIR"
echo "Server: $BASE_URL"
echo "NEXT: generate a benign SSH/sudo event and confirm stored Linux device_id and raw_event in PostgreSQL."