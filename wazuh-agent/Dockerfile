ARG BUILD_FROM
FROM ${BUILD_FROM}

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ENV DEBIAN_FRONTEND=noninteractive

# Base deps + Wazuh agent installed at build time (production-grade)
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
     curl ca-certificates gnupg jq \
  && rm -rf /var/lib/apt/lists/*

# Wazuh repo + key (non-interactive)
RUN curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
    | gpg --batch --yes --dearmor -o /usr/share/keyrings/wazuh.gpg \
  && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt stable main" \
     > /etc/apt/sources.list.d/wazuh.list

RUN apt-get update \
  && apt-get install -y --no-install-recommends wazuh-agent \
  && rm -rf /var/lib/apt/lists/*

COPY run.sh /run.sh
RUN chmod +x /run.sh

CMD ["/run.sh"]
