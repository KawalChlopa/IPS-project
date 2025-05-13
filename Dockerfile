FROM python:3.10-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 iptables \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir watchdog

COPY suricata-monitor.py /opt/suricata-monitor.py
RUN chmod +x /opt/suricata-monitor.py

ENTRYPOINT ["python", "-u", "/opt/suricata-monitor.py"]
