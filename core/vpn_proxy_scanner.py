"""
SS-Tools Ultimate - VPN/Proxy Scanner
Detects VPN and proxy services running on the system.
Scans: Network services, registered VPN clients, proxy settings, VPN drivers.
"""
import os
import socket
import subprocess
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.database import CheatDatabase
from core.utils import ScanResult, ScanProgress, logger


class VPNProxyScanner:
    """Detects VPN and proxy services running."""

    # Known VPN client processes
    VPN_PROCESSES = {
        "openvpn.exe": ("OpenVPN", 50),
        "expressvpn.exe": ("ExpressVPN", 60),
        "nordvpn.exe": ("NordVPN", 60),
        "mullvad.exe": ("Mullvad VPN", 50),
        "windscribe.exe": ("Windscribe", 50),
        "surfshark.exe": ("Surfshark", 60),
        "protonvpn.exe": ("ProtonVPN", 60),
        "cyberghost.exe": ("CyberGhost", 60),
        "bitdefender.exe": ("Bitdefender VPN", 40),
        "avast.exe": ("Avast VPN", 40),
        "vpngate.exe": ("VPN Gate", 50),
        "hotspotshield.exe": ("Hotspot Shield", 50),
        "tunnelbear.exe": ("TunnelBear", 50),
    }

    # Common VPN ports
    VPN_PORTS = [
        (1194, "OpenVPN"),
        (1723, "PPTP VPN"),
        (500, "IPSec/IKEv1"),
        (4500, "IPSec/IKEv2"),
        (1701, "L2TP VPN"),
        (443, "VPN over HTTPS"),
    ]

    # Known proxy software
    PROXY_PROCESSES = {
        "ccproxy.exe": ("CCProxy", 40),
        "tinyproxy.exe": ("Tiny Proxy", 40),
        "squid.exe": ("Squid Proxy", 40),
        "fiddler.exe": ("Fiddler", 50),
        "charles.exe": ("Charles Proxy", 50),
        "mitmproxy.exe": ("MitmProxy", 60),
    }

    # Proxy registry paths
    PROXY_REGISTRY_PATHS = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
    ]

    def __init__(self, progress: ScanProgress = None):
        self.db = CheatDatabase()
        self.progress = progress or ScanProgress()

    def scan(self) -> List[ScanResult]:
        """Run full VPN/Proxy scan."""
        results = []
        self.progress.start("VPN/Proxy Scanner", 4)

        try:
            # Scan running processes
            self.progress.update("Scanning VPN/Proxy processes...")
            results.extend(self._scan_vpn_processes())
            results.extend(self._scan_proxy_processes())

            # Scan network connections
            self.progress.update("Scanning network connections...")
            results.extend(self._scan_vpn_connections())

            # Scan registry
            self.progress.update("Scanning proxy registry settings...")
            results.extend(self._scan_proxy_registry())

            # Scan installed software
            self.progress.update("Scanning installed VPN software...")
            results.extend(self._scan_installed_vpn())

        except Exception as e:
            logger.warning(f"VPN/Proxy Scanner failed: {e}")
            results.append(ScanResult(
                scanner="VPNProxyScanner",
                category="scanner_error",
                name="VPN/Proxy Scanner Error",
                description=f"VPN/Proxy scanner encountered error: {str(e)}",
                severity=0,
            ))

        return results

    def _scan_vpn_processes(self) -> List[ScanResult]:
        """Scan for running VPN processes."""
        results = []
        
        try:
            proc = subprocess.run(
                ["tasklist", "/fo", "csv"],
                capture_output=True, text=True, timeout=10
            )
            
            if proc.returncode == 0:
                lines = proc.stdout.strip().split('\n')
                for line in lines[1:]:
                    line = line.replace('"', '')
                    parts = line.split(',')
                    if len(parts) >= 2:
                        process_name = parts[0].strip().lower()
                        
                        # Check against known VPN processes
                        for vpn_exe, (vpn_name, severity) in self.VPN_PROCESSES.items():
                            if vpn_exe.lower() in process_name:
                                results.append(ScanResult(
                                    scanner="VPNProxyScanner",
                                    category="vpn_detected",
                                    name=vpn_name,
                                    description=f"VPN software detected running: {vpn_name}",
                                    severity=severity,
                                    evidence=f"Process: {process_name}",
                                    details={"process_name": process_name, "software": vpn_name}
                                ))
                                break
        except Exception as e:
            logger.debug(f"VPN process scan error: {e}")

        return results

    def _scan_proxy_processes(self) -> List[ScanResult]:
        """Scan for running proxy processes."""
        results = []
        
        try:
            proc = subprocess.run(
                ["tasklist", "/fo", "csv"],
                capture_output=True, text=True, timeout=10
            )
            
            if proc.returncode == 0:
                lines = proc.stdout.strip().split('\n')
                for line in lines[1:]:
                    line = line.replace('"', '')
                    parts = line.split(',')
                    if len(parts) >= 2:
                        process_name = parts[0].strip().lower()
                        
                        # Check against known proxy processes
                        for proxy_exe, (proxy_name, severity) in self.PROXY_PROCESSES.items():
                            if proxy_exe.lower() in process_name:
                                results.append(ScanResult(
                                    scanner="VPNProxyScanner",
                                    category="proxy_detected",
                                    name=proxy_name,
                                    description=f"Proxy software detected running: {proxy_name}",
                                    severity=severity,
                                    evidence=f"Process: {process_name}",
                                    details={"process_name": process_name, "software": proxy_name}
                                ))
                                break
        except Exception as e:
            logger.debug(f"Proxy process scan error: {e}")

        return results

    def _scan_vpn_connections(self) -> List[ScanResult]:
        """Scan for active VPN network connections."""
        results = []
        
        try:
            proc = subprocess.run(
                ["netstat", "-ano"],
                capture_output=True, text=True, timeout=15
            )
            
            if proc.returncode == 0:
                for line in proc.stdout.strip().split('\n'):
                    line = line.strip()
                    if not line or "Proto" in line:
                        continue
                    
                    parts = line.split()
                    if len(parts) >= 4:
                        local_addr = parts[1] if len(parts) > 1 else ""
                        remote_addr = parts[2] if len(parts) > 2 else ""
                        
                        # Check for VPN ports
                        for port, service in self.VPN_PORTS:
                            if f":{port}" in remote_addr or f":{port}" in local_addr:
                                results.append(ScanResult(
                                    scanner="VPNProxyScanner",
                                    category="vpn_connection",
                                    name=service,
                                    description=f"Possible {service} connection detected on port {port}",
                                    severity=40,
                                    evidence=f"Connection: {remote_addr}",
                                    details={"port": port, "service": service, "address": remote_addr}
                                ))
                                break  # Avoid duplicate findings per port
        except Exception as e:
            logger.debug(f"VPN connection scan error: {e}")

        return results

    def _scan_proxy_registry(self) -> List[ScanResult]:
        """Scan Windows registry for proxy settings."""
        results = []
        
        try:
            import winreg
            
            for path in self.PROXY_REGISTRY_PATHS:
                try:
                    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, access=winreg.KEY_READ)
                    try:
                        proxy_server, _ = winreg.QueryValueEx(key, "ProxyServer")
                        proxy_enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
                        
                        if proxy_enable == 1 and proxy_server:
                            results.append(ScanResult(
                                scanner="VPNProxyScanner",
                                category="proxy_enabled",
                                name="Proxy Enabled",
                                description=f"HTTP Proxy enabled in Windows: {proxy_server}",
                                severity=50,
                                evidence=f"Proxy server: {proxy_server}",
                                details={"proxy_server": proxy_server, "registry_path": path}
                            ))
                    except WindowsError:
                        pass
                    finally:
                        winreg.CloseKey(key)
                except OSError:
                    pass
        except Exception as e:
            logger.debug(f"Proxy registry scan error: {e}")

        return results

    def _scan_installed_vpn(self) -> List[ScanResult]:
        """Scan installed VPN/Proxy software."""
        results = []
        
        try:
            import winreg
            
            uninstall_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, uninstall_path, access=winreg.KEY_READ)
            
            index = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, index)
                    subkey = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{uninstall_path}\\{subkey_name}")
                    
                    try:
                        display_name = winreg.QueryValueEx(subkey, "DisplayName")[0].lower()
                        
                        # Check for VPN/Proxy keywords
                        vpn_keywords = ["vpn", "proxy", "openvpn", "expressvpn", "nordvpn"]
                        for keyword in vpn_keywords:
                            if keyword in display_name:
                                results.append(ScanResult(
                                    scanner="VPNProxyScanner",
                                    category="vpn_installed",
                                    name=display_name[:50],
                                    description=f"VPN/Proxy software installed: {display_name}",
                                    severity=30,
                                    evidence=f"Registry key: {subkey_name}",
                                    details={"software": display_name, "registry_key": subkey_name}
                                ))
                                break
                    except:
                        pass
                    finally:
                        winreg.CloseKey(subkey)
                    
                    index += 1
                except OSError:
                    break
            
            winreg.CloseKey(key)
        except Exception as e:
            logger.debug(f"Installed VPN scan error: {e}")

        return results
