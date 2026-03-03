# HA Wazuh Agent Add-on

Security logging and host visibility for Home Assistant using Wazuh.

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

This add-on enables Home Assistant to act like a monitored system within a broader security architecture.

---

## Architectural Motivation

This add-on directly relates to the architectural discussion:

👉 https://github.com/home-assistant/architecture/discussions/1346

That proposal explores improving structured security logging inside Home Assistant.

Until native security telemetry is standardized in HA core, this add-on provides:

- Immediate structured log forwarding
- Security event classification
- Optional baseline security assessment (SCA)
- Centralized monitoring through Wazuh

It is not meant to replace future HA-native security logging —  
but to provide a production-ready solution today.

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

<img width="1597" height="898" alt="image" src="https://github.com/user-attachments/assets/fbb9f901-ae09-4563-8b36-2a25d44387f5" />

---

## Who Is This For?

This add-on is useful if you:

- Run Home Assistant in a production-like environment
- Care about security visibility
- Already use Wazuh or want to
- Operate a homelab with centralized logging
- Want to experiment with structured HA security telemetry

It may not be necessary for:

- Small single-device hobby setups
- Air-gapped non-networked deployments

---

## What You Get

- ✅ Wazuh Agent enrolled to your manager
- ✅ Structured HA log forwarding
- ✅ Persistent enrollment keys (`/data/ossec/etc/client.keys`)
- ✅ Optional minimal-noise security profile
- ✅ Clean restart behavior
- ✅ Production-grade configuration validation

---
