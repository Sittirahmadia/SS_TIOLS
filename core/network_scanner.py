"""
SS-Tools Ultimate - Network Connection Scanner
Scans active network connections for suspicious cheat server communication.
"""
import os
import re
import socket
import subprocess
from typing import List, Dict, Optional

from core.database import CheatDatabase
from core.keyword_detector import KeywordDetector
from core.utils import ScanResult, ScanProgress, logger

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class NetworkScanner:
    """Scans network connections for cheat-related communication."""

    # Known suspicious IPs / IP ranges (C2 servers, cheat license servers)
    SUSPICIOUS_PORTS = {
        4444: "Metasploit default",
        5555: "Common backdoor",
        1337: "Hacker culture port",
        31337: "Elite backdoor",
        6667: "IRC (potential C2)",
        6697: "IRC SSL (potential C2)",
        8443: "Alt HTTPS (potential C2)",
        9999: "Common malware port",
    }

    def __init__(self, progress: ScanProgress = None):
        self.db = CheatDatabase()
        self.detector = KeywordDetector()
        self.progress = progress or ScanProgress()

    def scan(self) -> List[ScanResult]:
        """Scan all active network connections."""
        results = []
        if not PSUTIL_AVAILABLE:
            return results

        self.progress.start("Network Scanner", 3)

        # 1. Check active connections
        self.progress.update("Scanning connections...")
        results.extend(self._scan_connections())

        # 2. Check DNS cache for cheat domains
        self.progress.update("Scanning DNS cache...")
        results.extend(self._scan_dns_cache())

        # 3. Check hosts file modifications
        self.progress.update("Checking hosts file...")
        results.extend(self._check_hosts_file())

        return results

    def _scan_connections(self) -> List[ScanResult]:
        """Scan active TCP/UDP connections."""
        results = []
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port
                    local_port = conn.laddr.port if conn.laddr else 0
                    pid = conn.pid or 0

                    # Get process name
                    proc_name = ""
                    try:
                        if pid:
                            proc_name = psutil.Process(pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                    # Check for suspicious ports
                    if remote_port in self.SUSPICIOUS_PORTS:
                        results.append(ScanResult(
                            scanner="NetworkScanner",
                            category="suspicious_port",
                            name=f"Port {remote_port}",
                            description=f"Connection to suspicious port {remote_port} ({self.SUSPICIOUS_PORTS[remote_port]})",
                            severity=70,
                            evidence=f"{remote_ip}:{remote_port} (PID: {pid}, Process: {proc_name})",
                            details={"pid": pid, "process": proc_name,
                                     "remote_ip": remote_ip, "remote_port": remote_port},
                        ))

                    # Reverse DNS lookup for suspicious domains
                    try:
                        hostname = socket.gethostbyaddr(remote_ip)[0]
                        url_results = self.detector.scan_url(
                            hostname, filepath=f"Connection:{remote_ip}"
                        )
                        for r in url_results:
                            r.scanner = "NetworkScanner"
                            r.details["pid"] = pid
                            r.details["process"] = proc_name
                            r.details["remote_ip"] = remote_ip
                            r.description = f"[Network] {r.description}"
                            r.severity = min(r.severity + 10, 100)
                        results.extend(url_results)
                    except (socket.herror, socket.gaierror, OSError):
                        pass

                    # Check if Java process is connecting to unusual IPs
                    if proc_name.lower() in ('java.exe', 'javaw.exe'):
                        # Java connecting to non-standard Minecraft ports
                        standard_mc_ports = {25565, 19132, 443, 80, 8080}
                        if remote_port not in standard_mc_ports and remote_port > 1024:
                            results.append(ScanResult(
                                scanner="NetworkScanner",
                                category="java_unusual_connection",
                                name=f"Java:{remote_ip}:{remote_port}",
                                description=f"Java process connecting to unusual port {remote_port}",
                                severity=45,
                                evidence=f"{remote_ip}:{remote_port} (PID: {pid})",
                                details={"pid": pid, "remote_ip": remote_ip},
                            ))

        except Exception as e:
            logger.debug(f"Connection scan error: {e}")
        return results

    def _scan_dns_cache(self) -> List[ScanResult]:
        """Scan DNS resolver cache for cheat domains."""
        results = []
        try:
            proc = subprocess.run(
                ["ipconfig", "/displaydns"],
                capture_output=True, text=True, timeout=15
            )
            if proc.returncode == 0:
                # Extract domain names from DNS cache
                domains = re.findall(r'Record Name\s*:\s*(.+)', proc.stdout)
                for domain in domains:
                    domain = domain.strip()
                    url_results = self.detector.scan_url(domain, filepath="DNS Cache")
                    for r in url_results:
                        r.scanner = "NetworkScanner"
                        r.category = "dns_cache"
                        r.description = f"[DNS Cache] {r.description}"
                        r.severity = min(r.severity + 5, 100)
                    results.extend(url_results)
        except Exception as e:
            logger.debug(f"DNS cache scan error: {e}")
        return results

    def _check_hosts_file(self) -> List[ScanResult]:
        """Check hosts file for suspicious modifications."""
        results = []
        hosts_path = os.path.join(
            os.environ.get("SystemRoot", "C:\\Windows"),
            "System32", "drivers", "etc", "hosts"
        )
        try:
            if os.path.exists(hosts_path):
                from core.utils import safe_read_file
                content = safe_read_file(hosts_path)
                if content:
                    lines = content.split('\n')
                    custom_entries = [l.strip() for l in lines
                                     if l.strip() and not l.strip().startswith('#')
                                     and 'localhost' not in l.lower()]
                    if custom_entries:
                        # Check if any entries block anti-cheat domains
                        anticheat_domains = [
                            "anticheat", "battleye", "easyanticheat",
                            "vanguard", "fairfight",
                        ]
                        for entry in custom_entries:
                            for ac in anticheat_domains:
                                if ac in entry.lower():
                                    results.append(ScanResult(
                                        scanner="NetworkScanner",
                                        category="hosts_modification",
                                        name="Anti-Cheat Block",
                                        description=f"Hosts file blocks anti-cheat domain: {entry}",
                                        severity=90,
                                        filepath=hosts_path,
                                        evidence=entry,
                                    ))
                            # Also scan for general cheat indicators
                            text_results = self.detector.scan_text(
                                entry, source="hosts", filepath=hosts_path
                            )
                            for r in text_results:
                                r.scanner = "NetworkScanner"
                                r.category = "hosts_cheat"
                            results.extend(text_results)
        except Exception as e:
            logger.debug(f"Hosts file check error: {e}")
        return results

    def get_connections_info(self) -> List[Dict]:
        """Get all active connections with process info."""
        connections = []
        if not PSUTIL_AVAILABLE:
            return connections
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.raddr:
                    proc_name = ""
                    try:
                        if conn.pid:
                            proc_name = psutil.Process(conn.pid).name()
                    except Exception:
                        pass
                    connections.append({
                        "pid": conn.pid or 0,
                        "process": proc_name,
                        "local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                        "remote": f"{conn.raddr.ip}:{conn.raddr.port}",
                        "status": conn.status,
                    })
        except Exception:
            pass
        return connections
