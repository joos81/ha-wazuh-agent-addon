# HA Wazuh Agent Add-on

Home Assistant Add-on that runs a Wazuh Agent, enrolls it to a Wazuh Manager, and forwards logs (journald or optional HA log file).

## Notes
- Persisted agent keys are stored under the add-on data directory (`/data/...` inside container, `/addon_configs/<slug>/...` on host).
- Auto-enrollment in `ossec.conf` is removed to prevent the agent from re-enrolling without a password.
