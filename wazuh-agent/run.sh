#!/usr/bin/env bash
set -euo pipefail

echo "[wazuh-agent] Starting"

OPTS="/data/options.json"
CONF="/var/ossec/etc/ossec.conf"
HA_LOG_FILE="/config/home-assistant.log"

if [ ! -f "$OPTS" ]; then
  echo "[wazuh-agent] ERROR: options.json not found"
  exit 1
fi

MANAGER_ADDRESS="$(jq -r '.manager_address' "$OPTS")"
AGENT_NAME="$(jq -r '.agent_name' "$OPTS")"
AGENT_GROUP="$(jq -r '.agent_group // ""' "$OPTS")"
ENROLLMENT_PORT="$(jq -r '.enrollment_port' "$OPTS")"
COMM_PORT="$(jq -r '.communication_port' "$OPTS")"
ENROLLMENT_KEY="$(jq -r '.enrollment_key' "$OPTS")"

echo "[wazuh-agent] manager_address=$MANAGER_ADDRESS"
echo "[wazuh-agent] agent_name=$AGENT_NAME"
echo "[wazuh-agent] agent_group=$AGENT_GROUP"
echo "[wazuh-agent] enrollment_port=$ENROLLMENT_PORT"
echo "[wazuh-agent] enrollment_key_set=$([ -n "$ENROLLMENT_KEY" ] && echo yes || echo no)"

# Required fields
if [ -z "$MANAGER_ADDRESS" ] || [ "$MANAGER_ADDRESS" = "null" ]; then
  echo "[wazuh-agent] ERROR: manager_address missing"
  exit 1
fi

if [ -z "$AGENT_NAME" ] || [ "$AGENT_NAME" = "null" ]; then
  echo "[wazuh-agent] ERROR: agent_name missing"
  exit 1
fi

if [ -z "$ENROLLMENT_KEY" ] || [ "$ENROLLMENT_KEY" = "null" ]; then
  echo "[wazuh-agent] ERROR: enrollment_key missing"
  exit 1
fi

# Install Wazuh Agent
apt-get update
apt-get install -y wazuh-agent

# Update manager address
sed -i "s|<address>.*</address>|<address>${MANAGER_ADDRESS}</address>|" "$CONF"

# Disable container-noisy modules
for tag in syscheck rootcheck; do
  if grep -q "<${tag}>" "$CONF"; then
    sed -i "0,/<${tag}>/{s/<disabled>no<\/disabled>/<disabled>yes<\/disabled>/}" "$CONF" || true
  fi
done

##############################################
# HA LOG INGEST (AUTO: file OR journald)
##############################################

add_localfile() {
  TYPE="$1"
  VALUE="$2"
  MARKER="$3"

  if grep -q "$MARKER" "$CONF"; then
    echo "[wazuh-agent] HA localfile already configured"
    return
  fi

  echo "[wazuh-agent] Adding HA localfile ($TYPE)"

  awk -v type="$TYPE" -v val="$VALUE" -v marker="$MARKER" '
    /<\/ossec_config>/ && !done {
      print "  <!-- " marker " -->"
      print "  <localfile>"
      print "    <log_format>syslog</log_format>"
      if (type == "file") {
        print "    <location>" val "</location>"
      } else {
        print "    <command>" val "</command>"
      }
      print "  </localfile>"
      done=1
    }
    { print }
  ' "$CONF" > /tmp/ossec.conf

  mv /tmp/ossec.conf "$CONF"
}

if [ -f "$HA_LOG_FILE" ]; then
  echo "[wazuh-agent] Using HA log file"
  add_localfile "file" "$HA_LOG_FILE" "WAZUH_HA_FILE"
else
  echo "[wazuh-agent] No HA log file found, using journald"

  if command -v journalctl >/dev/null 2>&1; then
    JOURNAL_CMD="journalctl -f -o short-iso CONTAINER_NAME=homeassistant --no-pager"
    add_localfile "command" "$JOURNAL_CMD" "WAZUH_HA_JOURNAL"
  else
    echo "[wazuh-agent] ERROR: journalctl not available"
  fi
fi

##############################################
# Persistent client.keys
##############################################

mkdir -p /data/ossec/etc

if [ -f /var/ossec/etc/client.keys ] && [ ! -L /var/ossec/etc/client.keys ]; then
  cp -n /var/ossec/etc/client.keys /data/ossec/etc/client.keys || true
fi

rm -f /var/ossec/etc/client.keys
ln -s /data/ossec/etc/client.keys /var/ossec/etc/client.keys

KEYS="/data/ossec/etc/client.keys"

##############################################
# Enrollment (only if not enrolled)
##############################################

if [ ! -s "$KEYS" ]; then
  echo "[wazuh-agent] Enrolling agent..."

  if [ -n "$AGENT_GROUP" ]; then
    /var/ossec/bin/agent-auth -m "$MANAGER_ADDRESS" \
      -p "$ENROLLMENT_PORT" \
      -A "$AGENT_NAME" \
      -G "$AGENT_GROUP" \
      -P "$ENROLLMENT_KEY"
  else
    /var/ossec/bin/agent-auth -m "$MANAGER_ADDRESS" \
      -p "$ENROLLMENT_PORT" \
      -A "$AGENT_NAME" \
      -P "$ENROLLMENT_KEY"
  fi
else
  echo "[wazuh-agent] Already enrolled"
fi

##############################################
# Start agent
##############################################

echo "[wazuh-agent] Starting Wazuh agent..."
/var/ossec/bin/wazuh-control start
/var/ossec/bin/wazuh-control status || true

echo "[wazuh-agent] Tailing log..."
tail -f /var/ossec/logs/ossec.log
