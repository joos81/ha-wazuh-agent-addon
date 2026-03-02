#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

log() { echo "[wazuh-agent] $*"; }

OPTS="/data/options.json"

CONF="/var/ossec/etc/ossec.conf"
KEYS="/var/ossec/etc/client.keys"

PERSIST_DIR="/data/ossec/etc"
PERSIST_KEYS="${PERSIST_DIR}/client.keys"

LOGFILE="/config/home-assistant.log"

# ----------------------------
# Read options
# ----------------------------
if [[ ! -f "$OPTS" ]]; then
  log "ERROR: options.json not found"
  exit 1
fi

# Helper: jq -> string, trims null/empty
jq_str() {
  local key="$1"
  local val
  val="$(jq -r "$key" "$OPTS" 2>/dev/null || true)"
  if [[ "$val" == "null" ]]; then
    echo ""
  else
    echo "$val"
  fi
}

MANAGER_ADDRESS="$(jq_str '.manager_address')"
AGENT_NAME="$(jq_str '.agent_name')"
AGENT_GROUP="$(jq_str '.agent_group // ""')"

ENROLLMENT_PORT="$(jq -r '.enrollment_port // 1515' "$OPTS")"
COMM_PORT="$(jq -r '.communication_port // 1514' "$OPTS")"

ENROLLMENT_KEY="$(jq_str '.enrollment_key')"
FORCE_REENROLL="$(jq -r '.force_reenroll // false' "$OPTS")"
DEBUG_DUMP="$(jq -r '.debug_dump_config // false' "$OPTS")"

log "Starting"
log "manager=$MANAGER_ADDRESS agent=$AGENT_NAME"
log "enrollment_port=$ENROLLMENT_PORT comm_port=$COMM_PORT"
log "enrollment_key_set=$([[ -n "$ENROLLMENT_KEY" ]] && echo yes || echo no)"
log "agent_group=$AGENT_GROUP"
log "force_reenroll=$FORCE_REENROLL debug_dump_config=$DEBUG_DUMP"

# ----------------------------
# Required checks (prod)
# ----------------------------
if [[ -z "$MANAGER_ADDRESS" ]]; then
  log "ERROR: manager_address missing"
  exit 1
fi
if [[ -z "$AGENT_NAME" ]]; then
  log "ERROR: agent_name missing"
  exit 1
fi
if [[ -z "$ENROLLMENT_KEY" ]]; then
  log "ERROR: enrollment_key missing"
  exit 1
fi

# ----------------------------
# Port validation
# ----------------------------
is_port() {
  local p="$1"
  [[ "$p" =~ ^[0-9]+$ ]] || return 1
  (( p >= 1 && p <= 65535 )) || return 1
  return 0
}

if ! is_port "$ENROLLMENT_PORT"; then
  log "ERROR: enrollment_port must be 1..65535 (got: $ENROLLMENT_PORT)"
  exit 1
fi
if ! is_port "$COMM_PORT"; then
  log "ERROR: communication_port must be 1..65535 (got: $COMM_PORT)"
  exit 1
fi

# ----------------------------
# Ensure Wazuh agent exists (installed in image)
# ----------------------------
if [[ ! -x /var/ossec/bin/wazuh-control ]] || [[ ! -f "$CONF" ]]; then
  log "ERROR: Wazuh agent not present. (Expected /var/ossec/bin/wazuh-control and $CONF)"
  log "This image should include wazuh-agent. Rebuild the add-on."
  exit 1
fi

# ----------------------------
# Persist dir + optional force reenroll
# ----------------------------
mkdir -p "$PERSIST_DIR"

if [[ "$FORCE_REENROLL" == "true" ]]; then
  log "Force re-enroll enabled: wiping persisted client.keys"
  rm -f "$PERSIST_KEYS"
fi

# Ensure persisted file exists with sane perms
touch "$PERSIST_KEYS"
chmod 640 "$PERSIST_KEYS" || true
chown root:wazuh "$PERSIST_KEYS" 2>/dev/null || true

# ----------------------------
# If persisted keys exist, restore into live KEYS
# If not, we'll enroll and then copy from live -> persisted
# (NO symlink; avoid weirdness on HA /data mounts)
# ----------------------------
if [[ -s "$PERSIST_KEYS" ]]; then
  log "Persisted client.keys exists; restoring into $KEYS"
  cp -f "$PERSIST_KEYS" "$KEYS" || true
  chmod 640 "$KEYS" || true
  chown root:wazuh "$KEYS" 2>/dev/null || true
fi

# ----------------------------
# Set manager address/port for communication
# ----------------------------
# Replace first <address>...</address>
sed -i "0,/<address>.*<\/address>/{s|<address>.*</address>|<address>${MANAGER_ADDRESS}</address>|}" "$CONF" || true

# Replace first <port>...</port> if present; if not present, we do nothing (safe)
sed -i "0,/<port>[0-9]\+<\/port>/{s|<port>[0-9]\+</port>|<port>${COMM_PORT}</port>|}" "$CONF" || true

# ----------------------------
# Add HA log source (file if exists, else journald)
# Journald requires <location>journald</location> to avoid warnings
# ----------------------------
if grep -q "WAZUH-HA" "$CONF"; then
  log "HA localfile already present"
else
  if [[ -f "$LOGFILE" ]]; then
    log "Using file log source: $LOGFILE"
    awk -v lf="$LOGFILE" '
      /<\/ossec_config>/ && !done {
        print "  <!-- WAZUH-HA: Home Assistant log file -->"
        print "  <localfile>"
        print "    <log_format>syslog</log_format>"
        print "    <location>" lf "</location>"
        print "  </localfile>"
        done=1
      }
      { print }
    ' "$CONF" > /tmp/ossec.conf && mv /tmp/ossec.conf "$CONF"
  else
    log "Using journald log source"
    awk '
      /<\/ossec_config>/ && !done {
        print "  <!-- WAZUH-HA: Home Assistant journald -->"
        print "  <localfile>"
        print "    <log_format>journald</log_format>"
        print "    <location>journald</location>"
        print "  </localfile>"
        done=1
      }
      { print }
    ' "$CONF" > /tmp/ossec.conf && mv /tmp/ossec.conf "$CONF"
  fi
fi

# ----------------------------
# Disable auto-enrollment block in ossec.conf (critical)
# Otherwise wazuh-agentd can attempt enroll with no password/hostname agent name
# ----------------------------
if grep -q "<enrollment>" "$CONF"; then
  log "Disabling <enrollment> block in ossec.conf"
  awk '
    BEGIN{skip=0}
    /<enrollment>/{skip=1; next}
    /<\/enrollment>/{skip=0; next}
    { if(!skip) print }
  ' "$CONF" > /tmp/ossec.conf && mv /tmp/ossec.conf "$CONF"
fi

# ----------------------------
# Enrollment only if no persisted keys (and live keys empty)
# ----------------------------
if [[ ! -s "$PERSIST_KEYS" ]]; then
  log "No persisted client.keys; enrolling now"

  if [[ -n "$AGENT_GROUP" ]]; then
    /var/ossec/bin/agent-auth -m "$MANAGER_ADDRESS" -p "$ENROLLMENT_PORT" -A "$AGENT_NAME" -G "$AGENT_GROUP" -P "$ENROLLMENT_KEY"
  else
    /var/ossec/bin/agent-auth -m "$MANAGER_ADDRESS" -p "$ENROLLMENT_PORT" -A "$AGENT_NAME" -P "$ENROLLMENT_KEY"
  fi

  if [[ -s "$KEYS" ]]; then
    log "Enrollment complete; persisting client.keys"
    cp -f "$KEYS" "$PERSIST_KEYS" || true
    chmod 640 "$PERSIST_KEYS" || true
    chown root:wazuh "$PERSIST_KEYS" 2>/dev/null || true
  else
    log "ERROR: Enrollment reported success but live client.keys is missing/empty."
    exit 1
  fi
fi

# ----------------------------
# Optional debug dump (log-visible; no container attach needed)
# ----------------------------
if [[ "$DEBUG_DUMP" == "true" ]]; then
  log "DEBUG: options.json:"
  cat "$OPTS" || true

  log "DEBUG: persisted keys:"
  ls -la "$PERSIST_DIR" || true
  wc -c "$PERSIST_KEYS" 2>/dev/null || true

  log "DEBUG: live /var/ossec/etc:"
  ls -la /var/ossec/etc || true
  wc -c "$KEYS" 2>/dev/null || true

  log "DEBUG: ossec.conf key lines:"
  grep -nE "WAZUH-HA|<localfile>|journald|<address>|<port>|<enrollment>" "$CONF" || true
fi

# ----------------------------
# Start agent
# ----------------------------
log "Starting agent"
if /var/ossec/bin/wazuh-control status >/dev/null 2>&1; then
  /var/ossec/bin/wazuh-control restart || true
else
  /var/ossec/bin/wazuh-control start || true
fi

log "Status:"
/var/ossec/bin/wazuh-control status || true

log "Tailing log..."
tail -f /var/ossec/logs/ossec.log
