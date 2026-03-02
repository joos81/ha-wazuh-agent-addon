#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "[wazuh-agent] Starting"

OPTS="/data/options.json"

CONF="/var/ossec/etc/ossec.conf"
KEYS="/var/ossec/etc/client.keys"

# Add-on persistent area (survives reinstall unless user wipes data)
ADDON_DATA="/data"
PERSIST_DIR="${ADDON_DATA}/ossec/etc"
PERSIST_KEYS="${PERSIST_DIR}/client.keys"
DEBUG_DIR="${ADDON_DATA}/debug"

LOGFILE="/config/home-assistant.log"

# ----------------------------
# Read options
# ----------------------------
if [ ! -f "$OPTS" ]; then
  echo "[wazuh-agent] ERROR: options.json not found at $OPTS"
  exit 1
fi

MANAGER_ADDRESS="$(jq -r '.manager_address // empty' "$OPTS")"
AGENT_NAME="$(jq -r '.agent_name // empty' "$OPTS")"
AGENT_GROUP="$(jq -r '.agent_group // ""' "$OPTS")"
ENROLLMENT_PORT="$(jq -r '.enrollment_port // 1515' "$OPTS")"
COMM_PORT="$(jq -r '.communication_port // 1514' "$OPTS")"
ENROLLMENT_KEY="$(jq -r '.enrollment_key // empty' "$OPTS")"
FORCE_REENROLL="$(jq -r '.force_reenroll // false' "$OPTS")"
DEBUG_DUMP="$(jq -r '.debug_dump_config // true' "$OPTS")"

echo "[wazuh-agent] manager=$MANAGER_ADDRESS agent=$AGENT_NAME"
echo "[wazuh-agent] enrollment_port=$ENROLLMENT_PORT comm_port=$COMM_PORT"
echo "[wazuh-agent] enrollment_key_set=$([ -n "$ENROLLMENT_KEY" ] && echo yes || echo no)"
echo "[wazuh-agent] agent_group=$AGENT_GROUP"
echo "[wazuh-agent] force_reenroll=$FORCE_REENROLL debug_dump_config=$DEBUG_DUMP"

# ----------------------------
# Required checks
# ----------------------------
if [ -z "$MANAGER_ADDRESS" ]; then
  echo "[wazuh-agent] ERROR: manager_address missing"
  exit 1
fi
if [ -z "$AGENT_NAME" ]; then
  echo "[wazuh-agent] ERROR: agent_name missing"
  exit 1
fi
if [ -z "$ENROLLMENT_KEY" ]; then
  echo "[wazuh-agent] ERROR: enrollment_key missing"
  exit 1
fi

# ----------------------------
# Ensure config exists
# ----------------------------
if [ ! -f "$CONF" ]; then
  echo "[wazuh-agent] ERROR: ossec.conf not found at $CONF"
  exit 1
fi

# ----------------------------
# Prepare persistent folders
# ----------------------------
mkdir -p "$PERSIST_DIR"
mkdir -p "$DEBUG_DIR"

# ----------------------------
# Force re-enroll wipes persisted keys + runtime keys
# ----------------------------
if [ "$FORCE_REENROLL" = "true" ]; then
  echo "[wazuh-agent] Force re-enroll enabled: wiping persisted and runtime client.keys"
  rm -f "$PERSIST_KEYS"
  rm -f "$KEYS"
fi

# ----------------------------
# Ensure manager address/port
# ----------------------------
# Replace FIRST <address>...</address>
sed -i "0,/<address>.*<\/address>/{s|<address>.*<\/address>|<address>${MANAGER_ADDRESS}</address>|}" "$CONF" || true
# Replace default 1514 if present
sed -i "s|<port>1514</port>|<port>${COMM_PORT}</port>|" "$CONF" || true

# ----------------------------
# Disable container-noise modules (DO NOT TOUCH SCA)
# ----------------------------
for tag in syscheck rootcheck syscollector; do
  if grep -q "<${tag}>" "$CONF"; then
    if awk "/<${tag}>/{f=1} f&&/<disabled>/{print; exit} /<\/${tag}>/{f=0}" "$CONF" | grep -q "<disabled>"; then
      sed -i "0,/<${tag}>/{s/<disabled>no<\/disabled>/<disabled>yes<\/disabled>/}" "$CONF" || true
    else
      awk -v t="$tag" '
        $0 ~ "<"t">" && !done[t] { print; print "    <disabled>yes</disabled>"; done[t]=1; next }
        { print }
      ' "$CONF" > /tmp/ossec.conf && mv /tmp/ossec.conf "$CONF"
    fi
  fi
done

# ----------------------------
# Add HA log source
# Prefer file if exists, otherwise journald
# Journald: add <location>journald</location>
# ----------------------------
if grep -q "WAZUH-HA" "$CONF"; then
  echo "[wazuh-agent] HA localfile already present"
else
  if [ -f "$LOGFILE" ]; then
    echo "[wazuh-agent] Using file log source: $LOGFILE"
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
    echo "[wazuh-agent] Using journald log source"
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
# CRITICAL: Remove <enrollment> block from ossec.conf
# Prevents agentd from trying to enroll again without password (and random name)
# ----------------------------
if grep -q "<enrollment>" "$CONF"; then
  echo "[wazuh-agent] Removing <enrollment> block from ossec.conf"
  awk '
    BEGIN{skip=0}
    /<enrollment>/{skip=1; next}
    /<\/enrollment>/{skip=0; next}
    { if(!skip) print }
  ' "$CONF" > /tmp/ossec.conf && mv /tmp/ossec.conf "$CONF"
fi

# ----------------------------
# If persisted keys exist -> restore to runtime
# ----------------------------
if [ -s "$PERSIST_KEYS" ]; then
  echo "[wazuh-agent] Persisted client.keys exists; restoring to runtime"
  cp -f "$PERSIST_KEYS" "$KEYS"
else
  echo "[wazuh-agent] No persisted client.keys; performing enrollment"
  rm -f "$KEYS"

  if [ -n "$AGENT_GROUP" ]; then
    /var/ossec/bin/agent-auth -m "$MANAGER_ADDRESS" -p "$ENROLLMENT_PORT" -A "$AGENT_NAME" -G "$AGENT_GROUP" -P "$ENROLLMENT_KEY"
  else
    /var/ossec/bin/agent-auth -m "$MANAGER_ADDRESS" -p "$ENROLLMENT_PORT" -A "$AGENT_NAME" -P "$ENROLLMENT_KEY"
  fi

  # After agent-auth, runtime keys MUST exist and be non-empty
  if [ -s "$KEYS" ]; then
    cp -f "$KEYS" "$PERSIST_KEYS"
    echo "[wazuh-agent] Enrollment complete; client.keys persisted"
  else
    echo "[wazuh-agent] ERROR: Enrollment reported success but /var/ossec/etc/client.keys is missing/empty."
    echo "[wazuh-agent] This usually means agent-auth couldn't write keys inside container."
    exit 1
  fi
fi

# ----------------------------
# Debug dump to /data (host-readable at /data/addons/data/<slug>/debug/)
# ----------------------------
if [ "$DEBUG_DUMP" = "true" ]; then
  cp -f "$CONF" "${DEBUG_DIR}/ossec.conf" || true
  cp -f "$CONF" "${DEBUG_DIR}/ossec.conf.bak" 2>/dev/null || true

  # redact keys before dumping (avoid secrets leak)
  if [ -f "$PERSIST_KEYS" ]; then
    cp -f "$PERSIST_KEYS" "${DEBUG_DIR}/client.keys.redacted" || true
    sed -i 's/^\([0-9]\+\) \([^ ]\+\) .*/\1 \2 **REDACTED**/' "${DEBUG_DIR}/client.keys.redacted" || true
  fi

  echo "[wazuh-agent] Debug written to ${DEBUG_DIR} (host: /data/addons/data/<slug>/debug/)"
fi

# ----------------------------
# Start agent
# ----------------------------
echo "[wazuh-agent] Starting agent"
if /var/ossec/bin/wazuh-control restart; then
  true
else
  /var/ossec/bin/wazuh-control start || true
fi

echo "[wazuh-agent] Status:"
/var/ossec/bin/wazuh-control status || true

echo "[wazuh-agent] Tailing log..."
tail -f /var/ossec/logs/ossec.log
