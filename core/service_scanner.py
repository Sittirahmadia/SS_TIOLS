"""
SS-Tools Ultimate - Service Scanner
Detects suspicious Windows services that may be related to cheats or malware.
Scans: Service names, executable paths, registry entries, startup types.
"""
import subprocess
import os
import re
from pathlib import Path
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.database import CheatDatabase
from core.utils import ScanResult, ScanProgress, logger, file_hash_md5


class ServiceScanner:
    """Detects suspicious Windows services."""

    # Suspicious service keywords
    SUSPICIOUS_SERVICE_PATTERNS = [
        r".*cheat.*",
        r".*hack.*",
        r".*crack.*",
        r".*trainer.*",
        r".*mod.*loader.*",
        r".*inject.*",
        r".*hook.*",
        r".*proxy.*",
        r".*socks.*",
        r".*vpn.*",
    ]

    def __init__(self, progress: ScanProgress = None):
        self.db = CheatDatabase()
        self.progress = progress or ScanProgress()

    def scan(self) -> List[ScanResult]:
        """Run full service scan."""
        results = []
        self.progress.start("Service Scanner", 2)

        try:
            # Get all services
            self.progress.update("Enumerating Windows services...")
            services = self._get_all_services()

            # Scan each service
            self.progress.update("Analyzing service details...")
            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = [
                    executor.submit(self._check_service, service)
                    for service in services
                ]
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        results.extend(result)

        except Exception as e:
            logger.warning(f"Service Scanner failed: {e}")
            results.append(ScanResult(
                scanner="ServiceScanner",
                category="scanner_error",
                name="Service Scanner Error",
                description=f"Service scanner encountered error: {str(e)}",
                severity=0,
            ))

        return results

    def _get_all_services(self) -> List[Dict]:
        """Get list of all Windows services."""
        services = []

        try:
            proc = subprocess.run(
                ["wmic", "service", "list", "brief"],
                capture_output=True, text=True, timeout=30
            )

            if proc.returncode == 0:
                lines = proc.stdout.strip().split('\n')
                for line in lines[1:]:  # Skip header
                    parts = line.split()
                    if len(parts) >= 2:
                        name = parts[0].strip()
                        state = parts[1].strip() if len(parts) > 1 else ""
                        services.append({"name": name, "state": state})
        except Exception as e:
            logger.debug(f"Error getting services: {e}")

        return services

    def _check_service(self, service: Dict) -> Optional[List[ScanResult]]:
        """Check a single service for suspicious indicators."""
        results = []
        service_name = service.get("name", "").lower()

        try:
            # Check service name against database
            for client in self.db.cheat_clients:
                if client["name"].lower() in service_name:
                    results.append(ScanResult(
                        scanner="ServiceScanner",
                        category="cheat_service",
                        name=client["name"],
                        description=f"Cheat client service detected: {service['name']}",
                        severity=client.get("severity", 100),
                        evidence=f"Service name: {service['name']}, State: {service.get('state', 'unknown')}",
                        details={"service_name": service["name"], "state": service.get("state")}
                    ))
                    return results

            # Check against suspicious patterns
            for pattern in self.SUSPICIOUS_SERVICE_PATTERNS:
                if re.match(pattern, service_name):
                    results.append(ScanResult(
                        scanner="ServiceScanner",
                        category="suspicious_service",
                        name=service["name"],
                        description=f"Suspicious service detected: {service['name']}",
                        severity=70,
                        evidence=f"Pattern match: {pattern}",
                        details={"service_name": service["name"], "pattern": pattern}
                    ))
                    return results

            # Get service executable path and verify
            path_info = self._get_service_info(service["name"])
            if path_info:
                results.extend(self._check_service_path(service["name"], path_info))

        except Exception as e:
            logger.debug(f"Error checking service {service.get('name')}: {e}")

        return results if results else None

    def _get_service_info(self, service_name: str) -> Optional[Dict]:
        """Get detailed information about a service."""
        try:
            proc = subprocess.run(
                ["sc", "qc", service_name],
                capture_output=True, text=True, timeout=10
            )

            if proc.returncode == 0:
                info = {"name": service_name}
                for line in proc.stdout.split('\n'):
                    if "BINARY_PATH_NAME" in line:
                        parts = line.split(':', 1)
                        if len(parts) > 1:
                            info["path"] = parts[1].strip()
                    elif "DISPLAY_NAME" in line:
                        parts = line.split(':', 1)
                        if len(parts) > 1:
                            info["display_name"] = parts[1].strip()
                    elif "START_TYPE" in line:
                        parts = line.split(':', 1)
                        if len(parts) > 1:
                            info["start_type"] = parts[1].strip()

                return info if info.get("path") else None
        except Exception:
            pass

        return None

    def _check_service_path(self, service_name: str, path_info: Dict) -> List[ScanResult]:
        """Check service executable path for suspicious indicators."""
        results = []
        exe_path = path_info.get("path", "").strip('"')

        if not exe_path or not os.path.exists(exe_path):
            return results

        try:
            # Check path for suspicious locations
            suspicious_paths = [
                r".*\appdata\.*",
                r".*\temp\.*",
                r".*\downloads\.*",
                r".*\users\.*\\appdata\roaming\.*",
            ]

            exe_path_lower = exe_path.lower()
            for pattern in suspicious_paths:
                if re.match(pattern, exe_path_lower):
                    results.append(ScanResult(
                        scanner="ServiceScanner",
                        category="suspicious_service_path",
                        name=service_name,
                        description=f"Service executable in suspicious location: {service_name}",
                        severity=75,
                        evidence=f"Path: {exe_path}",
                        details={"service_name": service_name, "exe_path": exe_path}
                    ))
                    return results

            # Get file hash
            try:
                file_hash = file_hash_md5(exe_path)
                if file_hash:
                    # Check against known hashes
                    for sig in self.db.kernel_driver_signatures:
                        if sig.get("hash") and file_hash in sig.get("hash", ""):
                            results.append(ScanResult(
                                scanner="ServiceScanner",
                                category="known_malware_service",
                                name=service_name,
                                description=f"Service executable matches known malware: {service_name}",
                                severity=100,
                                evidence=f"Hash: {file_hash}",
                                details={"service_name": service_name, "hash": file_hash}
                            ))
                            return results
            except Exception:
                pass

        except Exception as e:
            logger.debug(f"Error checking service path: {e}")

        return results
