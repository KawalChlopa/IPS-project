FROM python:3.10-slim

# Instalacja wymaganych bibliotek
RUN pip install --no-cache-dir watchdog

# Kopiowanie skryptu monitorującego
COPY suricata-monitor.py /opt/suricata-monitor.py

# Ustawienie pliku jako wykonywalnego
RUN chmod +x /opt/suricata-monitor.py

# Komenda uruchamiająca skrypt
CMD ["python", "/opt/suricata-monitor.py", "--interval", "1.0"]
