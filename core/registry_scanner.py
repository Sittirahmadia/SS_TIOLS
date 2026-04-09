"""
SS-Tools Ultimate - Registry Scanner
Scans Windows Registry for cheat client installations and suspicious registry keys.
Detects: Registry entries from cheat clients, malware signatures, suspicious software.
"""
import winreg
import struct
from pathlib import Path
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.database import CheatDatabase
from core.utils import ScanResult, ScanProgress, logger, file_hash_md5


class RegistryScanner:
    """Scans Windows Registry for cheat-related entries."""

    # Common registry paths to scan
    REGISTRY_PATHS = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]

    def __init__(self, progress: ScanProgress = None):
        self.db = CheatDatabase()
        self.progress = progress or ScanProgress()

    def scan(self) -> List[ScanResult]:
        """Run full registry scan."""
        results = []
        self.progress.start("Registry Scanner", len(self.REGISTRY_PATHS))

        try:
            for hkey, path in self.REGISTRY_PATHS:
                self.progress.update(f"Scanning {path}...")
                try:
                    results.extend(self._scan_registry_path(hkey, path))
                except Exception as e:
                    logger.debug(f"Registry scan error at {path}: {e}")
                    pass
        except Exception as e:
            logger.warning(f"Registry Scanner failed: {e}")
            results.append(ScanResult(
                scanner="RegistryScanner",
                category="scanner_error",
                name="Registry Scanner Error",
                description=f"Registry scanner encountered error: {str(e)}",
                severity=0,
            ))

        return results

    def _scan_registry_path(self, hkey: int, path: str) -> List[ScanResult]:
        """Scan a specific registry path for cheat-related entries."""
        results = []

        try:
            key = winreg.OpenKey(hkey, path, access=winreg.KEY_READ)
        except OSError:
            # Path doesn't exist or access denied
            return results

        try:
            # Scan subkeys
            index = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, index)
                    subkey_path = f"{path}\\{subkey_name}"
                    
                    # Check subkey name against cheat database
                    results.extend(self._check_registry_entry(
                        hkey, subkey_path, subkey_name
                    ))
                    index += 1
                except OSError:
                    break

            # Scan values in current key
            index = 0
            while True:
                try:
                    value_name, value_data, value_type = winreg.EnumValue(key, index)
                    
                    # Check value against cheat database
                    if value_name and isinstance(value_data, str):
                        results.extend(self._check_registry_value(
                            path, value_name, value_data
                        ))
                    index += 1
                except OSError:
                    break

        finally:
            winreg.CloseKey(key)

        return results

    def _check_registry_entry(self, hkey: int, path: str, name: str) -> List[ScanResult]:
        """Check a registry entry against cheat signatures."""
        results = []
        name_lower = name.lower()

        # Check against cheat client names
        for client in self.db.cheat_clients:
            client_name = client["name"].lower()
            if client_name in name_lower:
                results.append(ScanResult(
                    scanner="RegistryScanner",
                    category="cheat_client_registry",
                    name=client["name"],
                    description=f"Cheat client registry entry found: {client['name']} ({path})",
                    severity=client.get("severity", 100),
                    evidence=f"Registry path: {path}",
                    details={"registry_path": path, "entry_name": name}
                ))
                return results  # Avoid duplicate results

            # Check aliases
            for alias in client.get("aliases", []):
                if alias.lower() in name_lower:
                    results.append(ScanResult(
                        scanner="RegistryScanner",
                        category="cheat_client_alias_registry",
                        name=client["name"],
                        description=f"Cheat client alias in registry: {alias} ({path})",
                        severity=client.get("severity", 100),
                        evidence=f"Registry path: {path}, Alias: {alias}",
                        details={"registry_path": path, "alias": alias}
                    ))
                    return results

        # Check for suspicious uninstall entries
        if "Uninstall" in path:
            try:
                key = winreg.OpenKey(hkey, path, access=winreg.KEY_READ)
                try:
                    display_name = winreg.QueryValueEx(key, "DisplayName")[0]
                    display_name_lower = display_name.lower()

                    # Check display name against keywords
                    for keyword in self.db.suspicious_keywords:
                        if keyword.lower() in display_name_lower:
                            results.append(ScanResult(
                                scanner="RegistryScanner",
                                category="suspicious_uninstall",
                                name=display_name[:50],
                                description=f"Suspicious uninstall entry: {display_name}",
                                severity=60,
                                evidence=f"Registry path: {path}",
                                details={"display_name": display_name, "registry_path": path}
                            ))
                            break
                except WindowsError:
                    pass
                finally:
                    winreg.CloseKey(key)
            except Exception:
                pass

        return results

    def _check_registry_value(self, path: str, name: str, data: str) -> List[ScanResult]:
        """Check a registry value against cheat signatures."""
        results = []
        data_lower = data.lower()
        name_lower = name.lower()

        # Check for cheat client paths
        for client in self.db.cheat_clients:
            client_name = client["name"].lower()
            if client_name in data_lower or client_name in name_lower:
                results.append(ScanResult(
                    scanner="RegistryScanner",
                    category="cheat_client_path_registry",
                    name=client["name"],
                    description=f"Cheat client path in registry: {client['name']}",
                    severity=client.get("severity", 90),
                    evidence=f"Path: {data[:100]}",
                    details={"value_name": name, "value_data": data[:200], "registry_path": path}
                ))
                return results

        # Check for suspicious startup entries
        if "Run" in path and data_lower.startswith("http"):
            results.append(ScanResult(
                scanner="RegistryScanner",
                category="suspicious_startup_url",
                name="Suspicious Startup URL",
                description=f"Suspicious URL in startup entry: {name}",
                severity=70,
                evidence=f"URL: {data[:100]}",
                details={"value_name": name, "url": data, "registry_path": path}
            ))

        return results

    def get_installed_software(self) -> List[Dict]:
        """Get list of installed software from registry."""
        software_list = []
        uninstall_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]

        for hkey, path in uninstall_paths:
            try:
                key = winreg.OpenKey(hkey, path, access=winreg.KEY_READ)
                index = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, index)
                        subkey_path = f"{path}\\{subkey_name}"
                        subkey = winreg.OpenKey(hkey, subkey_path, access=winreg.KEY_READ)
                        
                        try:
                            display_name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                            display_version = ""
                            try:
                                display_version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                            except:
                                pass
                            
                            software_list.append({
                                "name": display_name,
                                "version": display_version,
                                "registry_key": subkey_name
                            })
                        except:
                            pass
                        finally:
                            winreg.CloseKey(subkey)
                        
                        index += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except OSError:
                pass

        return software_list
