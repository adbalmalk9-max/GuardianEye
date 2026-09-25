import argparse
import datetime as dt
import json
import os
import platform
import re
import socket
import time
from collections import defaultdict, deque
from pathlib import Path

import psutil
import requests

AGENT_VERSION = "1.0"
DEFAULT_INTERVAL = 10
WINDOW_SECONDS = 60

AUTH_FAILURE_RE = re.compile(
    r"Failed password .*? from (?P<ip>(?:\d{1,3}\.){3}\d{1,3})|"
    r"authentication failure.*?(?:rhost=|from\s+)(?P<ip2>(?:\d{1,3}\.){3}\d{1,3})|"
    r"Invalid user .*? from (?P<ip3>(?:\d{1,3}\.){3}\d{1,3})",
    re.IGNORECASE,
)
WEB_LINE_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+"(?P<method>[A-Z]+)\s+(?P<path>.*?)\s+HTTP/[^"]+"\s+(?P<status>\d{3})\s+(?P<size>\S+)',
)
SQLI_RE = re.compile(r"(?:union\s+select|select\s+.+\s+from|or\s+1=1|information_schema|sleep\s*\(|benchmark\s*\()", re.I)
TRAVERSAL_RE = re.compile(r"(?:\.\./|%2e%2e%2f|%252e%252e%252f)", re.I)
CMD_INJECTION_RE = re.compile(r"(?:;\s*(?:id|whoami|uname|cat)\b|\|\s*(?:id|whoami|uname)\b|\$\([^)]*\)|`[^`]+`)", re.I)
SCANNER_UA_RE = re.compile(r"(?:sqlmap|nikto|nmap|masscan|dirbuster|gobuster|ffuf|wpscan|acunetix)", re.I)


class AgentError(Exception):
    pass


class GuardianAgent:
    def __init__(self, config):
        self.config = config
        self.supabase_url = str(config["supabase_url"]).rstrip("/")
        self.anon_key = str(config["supabase_anon_key"])
        self.system_id = str(config["system_id"])
        self.ingest_token = str(config["ingest_token"])
        self.interval = int(config.get("interval_seconds", DEFAULT_INTERVAL))
        self.log_paths = [Path(p) for p in config.get("log_paths", self.default_log_paths())]
        self.positions = {}
        self.auth_failures = defaultdict(deque)
        self.http_rate = defaultdict(deque)
        self.port_observations = defaultdict(deque)
        self.sent_heartbeats = 0
        self.sent_events = 0

    @staticmethod
    def default_log_paths():
        candidates = [
            "/var/log/auth.log",
            "/var/log/secure",
            "/var/log/nginx/access.log",
            "/var/log/apache2/access.log",
        ]
        return [p for p in candidates if Path(p).exists()]

    def headers(self):
        return {
            "apikey": self.anon_key,
            "Authorization": f"Bearer {self.anon_key}",
            "Content-Type": "application/json",
        }

    def rpc(self, function_name, payload):
        url = f"{self.supabase_url}/rest/v1/rpc/{function_name}"
        response = requests.post(url, headers=self.headers(), json=payload, timeout=12)
        if response.status_code >= 400:
            raise AgentError(f"Supabase RPC {function_name} failed: HTTP {response.status_code} {response.text[:300]}")
        return response.json() if response.text else None

    def send_heartbeat(self):
        vm = psutil.virtual_memory()
        try:
            cpu = psutil.cpu_percent(interval=0.2)
        except Exception:
            cpu = None
        payload = {
            "p_ingest_token": self.ingest_token,
            "p_hostname": socket.gethostname(),
            "p_os_name": platform.platform(),
            "p_agent_version": AGENT_VERSION,
            "p_cpu_percent": cpu,
            "p_memory_percent": vm.percent,
            "p_open_connections": len(psutil.net_connections(kind="inet")),
            "p_monitored_logs": [str(p) for p in self.log_paths],
        }
        self.rpc("ingest_agent_heartbeat", payload)
        self.sent_heartbeats += 1

    def emit_event(self, attack_type, severity, source_ip, evidence, event_type="security_detection", confidence=0.9, source_port=None, dest_port=None, protocol="TCP", raw_data=None):
        payload = {
            "p_ingest_token": self.ingest_token,
            "p_event_time": dt.datetime.now(dt.timezone.utc).isoformat(),
            "p_event_type": event_type,
            "p_attack_type": attack_type,
            "p_severity": severity,
            "p_confidence": float(confidence),
            "p_source_ip": source_ip,
            "p_source_port": source_port,
            "p_dest_port": dest_port,
            "p_protocol": protocol,
            "p_evidence": evidence[:1800],
            "p_detected_by": f"GuardianEye Agent {AGENT_VERSION}",
            "p_raw_data": raw_data or {},
        }
        self.rpc("ingest_security_event", payload)
        self.sent_events += 1

    def trim(self, dq):
        cutoff = time.time() - WINDOW_SECONDS
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    def detect_auth_failure(self, line):
        match = AUTH_FAILURE_RE.search(line)
        if not match:
            return
        ip = match.group("ip") or match.group("ip2") or match.group("ip3")
        if not ip:
            return
        now = time.time()
        dq = self.auth_failures[ip]
        dq.append((now, line.strip()[:500]))
        self.trim(dq)
        if len(dq) == 5 or len(dq) % 10 == 0:
            severity = "High" if len(dq) >= 10 else "Medium"
            self.emit_event(
                "Brute Force",
                severity,
                ip,
                f"{len(dq)} failed authentication attempts from {ip} in {WINDOW_SECONDS} seconds. Latest: {line.strip()}",
                confidence=0.96,
                dest_port=22,
                protocol="TCP",
                raw_data={"failed_attempts_window": len(dq)},
            )

    def detect_web_event(self, line):
        match = WEB_LINE_RE.match(line.strip())
        if not match:
            return
        ip = match.group("ip")
        method = match.group("method")
        path = match.group("path")
        status = int(match.group("status"))
        now = time.time()

        rate = self.http_rate[ip]
        rate.append((now, path))
        self.trim(rate)

        if SQLI_RE.search(path):
            self.emit_event(
                "SQL Injection Pattern",
                "High",
                ip,
                f"HTTP {method} {path} returned {status}; query/path matched a SQL injection pattern.",
                confidence=0.91,
                dest_port=80,
                protocol="TCP",
                raw_data={"method": method, "path": path, "status": status},
            )
        elif TRAVERSAL_RE.search(path):
            self.emit_event(
                "Path Traversal",
                "High",
                ip,
                f"HTTP {method} {path} returned {status}; path traversal pattern detected.",
                confidence=0.94,
                dest_port=80,
                protocol="TCP",
                raw_data={"method": method, "path": path, "status": status},
            )
        elif CMD_INJECTION_RE.search(path):
            self.emit_event(
                "Command Injection Pattern",
                "High",
                ip,
                f"HTTP {method} {path} returned {status}; command execution pattern detected.",
                confidence=0.89,
                dest_port=80,
                protocol="TCP",
                raw_data={"method": method, "path": path, "status": status},
            )
        elif SCANNER_UA_RE.search(line):
            self.emit_event(
                "Web Scanner Activity",
                "Medium",
                ip,
                f"Scanner-like user-agent or probe pattern observed in web access log: {line.strip()}",
                confidence=0.84,
                dest_port=80,
                protocol="TCP",
                raw_data={"path": path, "status": status},
            )
        elif len(rate) >= 120 and len(rate) % 30 == 0:
            self.emit_event(
                "HTTP Flood / High Rate",
                "Medium",
                ip,
                f"Observed {len(rate)} HTTP requests from {ip} in {WINDOW_SECONDS} seconds.",
                confidence=0.78,
                dest_port=80,
                protocol="TCP",
                raw_data={"request_count_window": len(rate)},
            )

    def monitor_network_connections(self):
        try:
            connections = psutil.net_connections(kind="inet")
        except Exception:
            return
        now = time.time()
        for conn in connections:
            if not conn.raddr or not conn.laddr:
                continue
            remote_ip = getattr(conn.raddr, "ip", None) if hasattr(conn.raddr, "ip") else conn.raddr[0]
            local_port = getattr(conn.laddr, "port", None) if hasattr(conn.laddr, "port") else conn.laddr[1]
            if not remote_ip or not local_port:
                continue
            dq = self.port_observations[remote_ip]
            dq.append((now, int(local_port), conn.status))
            self.trim(dq)
            unique_ports = {item[1] for item in dq}
            if len(unique_ports) >= 12 and len(unique_ports) % 6 == 0:
                self.emit_event(
                    "Port Scan (Observed Connections)",
                    "Medium",
                    remote_ip,
                    f"Observed one remote source touching {len(unique_ports)} local ports within {WINDOW_SECONDS} seconds. This detection uses established/visible connections only.",
                    confidence=0.72,
                    protocol="TCP",
                    raw_data={"ports": sorted(unique_ports)[:80]},
                )

    def read_new_lines(self, path):
        try:
            size = path.stat().st_size
        except OSError:
            return []
        pos = self.positions.get(str(path), 0)
        if size < pos:
            pos = 0
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                handle.seek(pos)
                lines = handle.readlines()
                self.positions[str(path)] = handle.tell()
                return lines
        except (OSError, PermissionError):
            return []

    def process_logs(self):
        for path in self.log_paths:
            for line in self.read_new_lines(path):
                if "auth" in path.name.lower() or "secure" in str(path).lower():
                    self.detect_auth_failure(line)
                if "access.log" in path.name.lower():
                    self.detect_web_event(line)

    def run_once(self):
        self.process_logs()
        self.monitor_network_connections()
        self.send_heartbeat()

    def run(self):
        print(f"GuardianEye Agent {AGENT_VERSION} started for system {self.system_id}")
        print(f"Monitoring logs: {[str(p) for p in self.log_paths]}")
        while True:
            started = time.time()
            try:
                self.run_once()
                print(f"[{dt.datetime.now().isoformat(timespec='seconds')}] heartbeat={self.sent_heartbeats} events={self.sent_events}")
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                print(f"Agent cycle error: {exc}")
            elapsed = time.time() - started
            time.sleep(max(1, self.interval - elapsed))


def load_config(path):
    with open(path, "r", encoding="utf-8") as handle:
        config = json.load(handle)
    required = ["supabase_url", "supabase_anon_key", "system_id", "ingest_token"]
    missing = [k for k in required if not str(config.get(k, "")).strip()]
    if missing:
        raise AgentError(f"Missing config fields: {', '.join(missing)}")
    return config


def main():
    parser = argparse.ArgumentParser(description="GuardianEye defensive monitoring agent")
    parser.add_argument("--config", required=True, help="Path to agent_config.json")
    parser.add_argument("--once", action="store_true", help="Run one collection cycle and exit")
    args = parser.parse_args()
    config = load_config(args.config)
    agent = GuardianAgent(config)
    if args.once:
        agent.run_once()
    else:
        agent.run()


if __name__ == "__main__":
    main()
