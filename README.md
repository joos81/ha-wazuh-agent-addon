# HA Wazuh Agent Add-on

Security logging and host visibility for Home Assistant using **Wazuh**.

This Home Assistant add-on runs a **Wazuh Agent** inside HA OS and forwards
structured security-relevant events to a **Wazuh Manager**.

Primary goal: **as native as possible** for any Home Assistant installation —
no HA-side custom integrations required.

---

## What is Wazuh?

Wazuh is an open-source security monitoring platform that provides:

- Log analysis
- File integrity monitoring (FIM)
- Security configuration assessment (SCA)
- Intrusion detection
- Threat detection & alerting
- Centralized event correlation

In simple terms:

> Wazuh turns raw logs into structured, searchable, security-relevant events.

It is widely used in enterprise environments as a SIEM (Security Information and Event Management) and host-based intrusion detection system.

Official project: https://github.com/wazuh/wazuh

---

## Why would you want this in Home Assistant?

Home Assistant today generates logs.

But logs ≠ security telemetry.

There is currently no native:

- Structured security event pipeline
- Centralized threat visibility
- Host integrity monitoring
- Compliance-style baseline checks
- Long-term security event correlation

This add-on enables Home Assistant to act as a **monitored system** inside a broader security architecture.

---

## Architectural Motivation

This add-on directly relates to the Home Assistant architectural discussion:

https://github.com/home-assistant/architecture/discussions/1346

That proposal explores improving structured security logging inside Home Assistant core.

Until native security telemetry is standardized, this add-on provides:

- Immediate structured log forwarding
- Security event classification
- Optional baseline security assessment (SCA)
- Centralized monitoring through Wazuh

This add-on does **not** replace future HA-native security logging.
It provides a **production-ready solution today**.

---

## What This Add-on Does

This add-on:

- Installs the official Wazuh Agent
- Enrolls it to your Wazuh Manager
- Forwards Home Assistant logs (journald or file)
- Persists enrollment keys safely
- Prevents auto-enrollment loops
- Provides a low-noise “minimal” security profile

It does **not**:

- Modify Wazuh source code
- Replace Home Assistant logging
- Act as a Wazuh Manager
- Perform aggressive host scanning (in minimal mode)

---

## Example: What You See in Wazuh

Once connected, Home Assistant becomes a monitored node.

You can see:

- Agent start/stop events
- Structured HA log events
- Authentication anomalies
- Service restarts
- Baseline configuration scoring (SCA)
- Event correlation with other infrastructure

Screenshot:
https://github.com/user-attachments/assets/fbb9f901-ae09-4563-8b36-2a25d44387f5

---

## Architecture Overview

Home Assistant OS  
→ HA Wazuh Agent (Add-on)  
→ Encrypted TCP (1514)  
→ Wazuh Manager  
→ Wazuh Indexer / Dashboard

---

## Security Profiles

### Minimal (default)

Designed specifically for Home Assistant OS.

- Disables:
  - syscheck (FIM)
  - rootcheck
  - syscollector
  - agent-upgrade
  - command collectors (df, netstat, last)
- Keeps:
  - Log forwarding
  - Security Configuration Assessment (SCA)

Minimal mode focuses on **telemetry and visibility**, not host scanning.

---

### Standard

For advanced users.

- Enables default Wazuh modules
- Performs file integrity monitoring
- Behaves like a traditional Linux agent

Use only if you understand HA OS container constraints.

---

## Threat Model

This add-on improves visibility, not immunity.

It helps detect:

- Service crashes and restarts
- Suspicious log patterns
- Authentication anomalies
- Configuration drift
- Cross-infrastructure attack signals

It does not prevent:

- Zero-day vulnerabilities
- Physical access attacks
- Compromise of Wazuh Manager

Security is layered.

---

## License & Upstream Notice

This project is licensed under the **MIT License**.

It installs and runs the official **Wazuh Agent**, which is licensed under **GPLv2**.

This add-on does not modify or redistribute Wazuh source code.
All trademarks belong to their respective owners.
