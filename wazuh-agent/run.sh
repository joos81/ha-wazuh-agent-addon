# Enrollment (if key provided)
if [ -n "$ENROLLMENT_KEY" ]; then
  echo "[wazuh-agent] Running agent enrollment..."

  if [ -n "$AGENT_GROUP" ]; then
    echo "[wazuh-agent] Enrolling with group $AGENT_GROUP"
    /var/ossec/bin/agent-auth -m "$MANAGER_ADDRESS" \
      -p "$ENROLLMENT_PORT" \
      -A "$AGENT_NAME" \
      -G "$AGENT_GROUP" \
      -P "$ENROLLMENT_KEY"
  else
    echo "[wazuh-agent] Enrolling without group"
    /var/ossec/bin/agent-auth -m "$MANAGER_ADDRESS" \
      -p "$ENROLLMENT_PORT" \
      -A "$AGENT_NAME" \
      -P "$ENROLLMENT_KEY"
  fi

else
  echo "[wazuh-agent] Skipping enrollment (no enrollment_key set)"
fi
