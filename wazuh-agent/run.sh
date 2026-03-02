#!/usr/bin/env bash
set -euo pipefail

echo "[wazuh-agent] Starting"

OPTS="/data/options.json"
if [ ! -f "$OPTS" ]; then
  echo "[wazuh-agent] ERROR: options.json not found at $OPTS"
  exit 1
fi

MANAGER_ADDRESS="$(jq -r '.manager_address' "$OPTS")"
AGENT_NAME="$(jq -r '.agent_name' "$OPTS")"
AGENT_GROUP="$(jq -r '.agent_group' "$OPTS")"
ENROLLMENT_PORT="$(jq -r '.enrollment_port' "$OPTS")"
COMM_PORT="$(jq -r '.communication_port' "$OPTS")"
ENROLLMENT_KEY="$(jq -r '.enrollment_key' "$OPTS")"

echo "[wazuh-agent] manager_address=$MANAGER_ADDRESS"
echo "[wazuh-agent] agent_name=$AGENT_NAME"
echo "[wazuh-agent] agent_group=$AGENT_GROUP"
echo "[wazuh-agent] enrollment_port=$ENROLLMENT_PORT comm_port=$COMM_PORT"
echo "[wazuh-agent] enrollment_key_set=$([ -n "$ENROLLMENT_KEY" ] && echo yes || echo no)"

# Ensure deps exist
apt-get update
apt-get install -y --no-install-recommends curl ca-certificates gnupg jq
rm -rf /var/lib/apt/lists/*

# Install Wazuh agent only once
if ! command -v wazuh-agent >/dev/null 2>&1; then
  echo "[wazuh-agent] Installing Wazuh Agent..."
  curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
  echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list

  apt-get update
  apt-get install -y wazuh-agent
  rm -rf /var/lib/apt/lists/*
else
  echo "[wazuh-agent] Wazuh Agent already installed"
fi

# Configure manager address (basic)
CONF="/var/ossec/etc/ossec.conf"
if [ -f "$CONF" ]; then
  echo "[wazuh-agent] Updating ossec.conf manager address..."
  # Replace existing <address> if present; otherwise this is a no-op (we'll enroll anyway)
  sed -i "s|<address>.*</address>|<address>${MANAGER_ADDRESS}</address>|" "$CONF" || true
fi

# Enrollment (if key provided)
if [ -n "$ENROLLMENT_KEY" ]; then
  echo "[wazuh-agent] Running agent enrollment..."
  /var/ossec/bin/agent-auth -m "$MANAGER_ADDRESS" -p "$ENROLLMENT_PORT" -A "$AGENT_NAME" -G "$AGENT_GROUP" -P "$ENROLLMENT_KEY" || {
    echo "[wazuh-agent] Enrollment failed"
    exit 1
  }
else
  echo "[wazuh-agent] Skipping enrollment (no enrollment_key set)"
fi

echo "[wazuh-agent] Starting wazuh-agent service..."
/var/ossec/bin/wazuh-control start || true

# Show status and keep alive
/var/ossec/bin/wazuh-control status || true
tail -f /var/ossec/logs/ossec.log
