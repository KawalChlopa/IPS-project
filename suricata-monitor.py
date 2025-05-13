#!/usr/bin/env python3

import os
import time
import datetime
import argparse
import json
import re
import subprocess
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class FastLogHandler(FileSystemEventHandler):
    def __init__(self, output_log, rules_file, log_dir="/var/log/suricata"):
        self.output_log = output_log
        self.log_dir = log_dir

        # Load JSON rules
        try:
            with open(rules_file) as f:
                self.rules = json.load(f)
        except Exception as e:
            print(f"Error loading rules: {e}")
            self.rules = []

        # Track last read position in fast.log
        fast_log = os.path.join(log_dir, "fast.log")
        if os.path.exists(fast_log):
            start = os.path.getsize(fast_log)
        else:
            start = 0
        self.file_positions = { fast_log: start }

        # Ping counters and which IPs have been blocked
        self.ping_counts = {}
        self.ping_blocked = set()

    def on_modified(self, event):
        if event.is_directory or not event.src_path.endswith("fast.log"):
            return
        self._read_new_lines(event.src_path)

    def _read_new_lines(self, path):
        # get file size and last position
        try:
            current_size = os.path.getsize(path)
            last_pos = self.file_positions.get(path, 0)
        except OSError:
            return

        if current_size <= last_pos:
            return

        with open(path, 'r', errors='ignore') as f:
            f.seek(last_pos)
            for line in f:
                self.process_line(line.rstrip('\n'))

        self.file_positions[path] = current_size

    def process_line(self, line):
        # debug output
        print(f"[DEBUG LINE] {line}")

        # ignore IPv6 pings
        if "{IPv6-ICMP}" in line:
            return

        # ignore echo-replies (type 0)
        if "{ICMP}" in line and re.search(r":0\s+->", line):
            return

        # handle echo-requests (type 8)
        m = re.search(r"\{ICMP\}\s+(?P<ip>\d+\.\d+\.\d+\.\d+):8\s+->", line)
        if m:
            ip = m.group("ip")
            cnt = self.ping_counts.get(ip, 0) + 1
            self.ping_counts[ip] = cnt
            print(f"[DEBUG] IPv4 echo-request #{cnt} from {ip}")

            if cnt > 10 and ip not in self.ping_blocked:
                # insert DROP rule
                result = subprocess.run(
                    ["iptables","-I","INPUT","-s", ip, "-j","DROP"],
                    capture_output=True, text=True
                )
                print(f"[DEBUG IPTABLES rc={result.returncode}] {result.stderr.strip()}")
                if result.returncode == 0:
                    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    msg = f"IP {ip} ping threshold exceeded, blocked"
                    with open(self.output_log,'a') as out:
                        out.write(f"[{ts}] [ACTION] {msg}\n")
                    print(f"[ACTION] {msg}")
                    self.ping_blocked.add(ip)
                else:
                    print(f"[ERROR] could not block {ip}: {result.stderr.strip()}")
            return

        # only handle real Suricata alerts
        if "[**]" not in line:
            return

        # write alert to output log
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert_msg = f"[{ts}] {line}"
        with open(self.output_log,'a') as out:
            out.write(alert_msg + "\n")
        print(alert_msg)

        # apply JSON-defined rules
        for rule in self.rules:
            pat = rule.get("pattern","")
            match = re.search(pat, line)
            if not match:
                continue
            ip = match.groupdict().get("ip")
            if not ip:
                continue

            result = subprocess.run(
                ["iptables","-I","INPUT","-s", ip, "-j","DROP"],
                capture_output=True, text=True
            )
            print(f"[DEBUG IPTABLES rc={result.returncode}] {result.stderr.strip()}")
            if result.returncode == 0:
                ts2 = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                msg2 = f"IP {ip} blocked for {rule.get('duration',600)}s"
                with open(self.output_log,'a') as out:
                    out.write(f"[{ts2}] [ACTION] {msg2}\n")
                print(f"[ACTION] {msg2}")
            else:
                print(f"[ERROR] could not block {ip}: {result.stderr.strip()}")

def main():
    parser = argparse.ArgumentParser(description="Monitor Suricata fast.log and act on alerts")
    parser.add_argument("--output-log", default="/opt/log/suricata-monitor.log",
                        help="path to write actions log")
    parser.add_argument("--rules", default="/etc/suricata-actions.json",
                        help="JSON file with regex patterns & durations")
    parser.add_argument("--interval", type=float, default=1.0,
                        help="fallback polling interval")
    parser.add_argument("--log-directory", default="/var/log/suricata",
                        help="where fast.log lives")
    args = parser.parse_args()

    handler = FastLogHandler(args.output_log, args.rules, args.log_directory)
    observer = Observer()
    observer.schedule(handler, path=args.log_directory, recursive=False)
    observer.start()
    print("Monitoring Suricata fast.log...")

    try:
        while True:
            # fallback: re-read any new lines periodically
            for path in list(handler.file_positions):
                if os.path.exists(path):
                    handler._read_new_lines(path)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    main()
