#!/usr/bin/env bash
set -euo pipefail

echo "[wazuh-agent] Starting"

OPTS="/data/options.json"
if [ ! -f "$OPTS" ]; then
  echo "[wazuh-agent] ERROR: options.json not found at $OPTS"
  exit 1
fi

echo "[wazuh-agent] Raw options:"
cat "$OPTS" || true

MANAGER_ADDRESS="$(jq -r '.manager_address' "$OPTS")"
AGENT_NAME="$(jq -r '.agent_name' "$OPTS")"
AGENT_GROUP="$(jq -r '.agent_group // ""' "$OPTS")"        # ✅ optional
ENROLLMENT_PORT="$(jq -r '.enrollment_port' "$OPTS")"
COMM_PORT="$(jq -r '.communication_port' "$OPTS")"
ENROLLMENT_KEY="$(jq -r '.enrollment_key' "$OPTS")"        # ✅ required

echo "[wazuh-agent] manager_address=$MANAGER_ADDRESS"
echo "[wazuh-agent] agent_name=$AGENT_NAME"
echo "[wazuh-agent] agent_group=$AGENT_GROUP"
echo "[wazuh-agent] enrollment_port=$ENROLLMENT_PORT comm_port=$COMM_PORT"
echo "[wazuh-agent] enrollment_key_set=$([ -n "$ENROLLMENT_KEY" ] && echo yes || echo no)"

# Required validations
if [ -z "$MANAGER_ADDRESS" ] || [ "$MANAGER_ADDRESS" = "null" ]; then
  echo "[wazuh-agent] ERROR: manager_address is missing"
  exit 1
fi
if [ -z "$AGENT_NAME" ] || [ "$AGENT_NAME" = "null" ]; then
  echo "[wazuh-agent] ERROR: agent_name is missing"
  exit 1
fi
if [ -z "$ENROLLMENT_KEY" ] || [ "$ENROLLMENT_KEY" = "null" ]; then
  echo "[wazuh-agent] ERROR: enrollment_key is missing"
  exit 1
fi

# deps (should be in image, but safe)
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends curl ca-certificates gnupg jq
rm -rf /var/lib/apt/lists/*

# install agent if needed
if [ ! -x /var/ossec/bin/wazuh-control ]; then
  echo "[wazuh-agent] Installing Wazuh Agent..."
  curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
  echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
  apt-get update
  apt-get install -y wazuh-agent
  rm -rf /var/lib/apt/lists/*
else
  echo "[wazuh-agent] Wazuh Agent already installed"
fi

# best-effort manager address update
CONF="/var/ossec/etc/ossec.conf"
if [ -f "$CONF" ]; then
  echo "[wazuh-agent] Updating ossec.conf manager address..."
  sed -i "s|<address>.*</address>|<address>${MANAGER_ADDRESS}</address>|" "$CONF" || true
fi

echo "[wazuh-agent] Running agent enrollment..."
if [ -n "$AGENT_GROUP" ]; then
  echo "[wazuh-agent] Enrolling with group: $AGENT_GROUP"
  /var/ossec/bin/agent-auth -m "$MANAGER_ADDRESS" -p "$ENROLLMENT_PORT" -A "$AGENT_NAME" -G "$AGENT_GROUP" -P "$ENROLLMENT_KEY"
else
  echo "[wazuh-agent] Enrolling without group"
  /var/ossec/bin/agent-auth -m "$MANAGER_ADDRESS" -p "$ENROLLMENT_PORT" -A "$AGENT_NAME" -P "$ENROLLMENT_KEY"
fi

echo "[wazuh-agent] Starting Wazuh agent..."
/var/ossec/bin/wazuh-control start || true
/var/ossec/bin/wazuh-control status || true

tail -f /var/ossec/logs/ossec.log
