"""
SS-Tools Ultimate - GPU Driver Scanner
Detects graphics driver versions, updates, and suspicious GPU-related software.
Scans: NVIDIA/AMD/Intel drivers, driver versions, GPU software, suspicious GPU modifications.
"""
import subprocess
import re
from typing import List, Dict, Optional
from pathlib import Path

from core.database import CheatDatabase
from core.utils import ScanResult, ScanProgress, logger, file_hash_md5


class GPUDriverScanner:
    """Scans GPU drivers for suspicious indicators."""

    def __init__(self, progress: ScanProgress = None):
        self.db = CheatDatabase()
        self.progress = progress or ScanProgress()

    def scan(self) -> List[ScanResult]:
        """Run full GPU driver scan."""
        results = []
        self.progress.start("GPU Driver Scanner", 3)

        try:
            # Detect GPU type and driver
            self.progress.update("Detecting GPU and drivers...")
            gpu_info = self._detect_gpu()
            
            if gpu_info:
                # Scan NVIDIA drivers
                if gpu_info.get("nvidia"):
                    results.extend(self._scan_nvidia_driver(gpu_info["nvidia"]))
                
                # Scan AMD drivers
                if gpu_info.get("amd"):
                    results.extend(self._scan_amd_driver(gpu_info["amd"]))
                
                # Scan Intel drivers
                if gpu_info.get("intel"):
                    results.extend(self._scan_intel_driver(gpu_info["intel"]))

            # Scan GPU-related software
            self.progress.update("Scanning GPU software...")
            results.extend(self._scan_gpu_software())

            # Scan GPU drivers files for modifications
            self.progress.update("Analyzing driver files...")
            results.extend(self._scan_driver_files())

        except Exception as e:
            logger.warning(f"GPU Driver Scanner failed: {e}")
            results.append(ScanResult(
                scanner="GPUDriverScanner",
                category="scanner_error",
                name="GPU Driver Scanner Error",
                description=f"GPU scanner encountered error: {str(e)}",
                severity=0,
            ))

        return results

    def _detect_gpu(self) -> Optional[Dict]:
        """Detect installed GPUs and drivers."""
        gpu_info = {}

        # Detect NVIDIA GPU
        try:
            proc = subprocess.run(
                ["nvidia-smi", "--query-gpu=name,driver_version", "--format=csv,noheader"],
                capture_output=True, text=True, timeout=10
            )
            
            if proc.returncode == 0 and proc.stdout.strip():
                parts = proc.stdout.strip().split(',')
                if len(parts) >= 2:
                    gpu_info["nvidia"] = {
                        "name": parts[0].strip(),
                        "driver_version": parts[1].strip()
                    }
        except Exception:
            pass

        # Detect AMD GPU
        try:
            proc = subprocess.run(
                ["wmic", "path", "win32_videocontroller", "get", "name,driverversion"],
                capture_output=True, text=True, timeout=10
            )
            
            if proc.returncode == 0:
                for line in proc.stdout.split('\n')[1:]:
                    if "AMD" in line or "Radeon" in line:
                        parts = line.split()
                        gpu_info["amd"] = {
                            "name": line.strip(),
                            "driver_version": parts[-1] if parts else "unknown"
                        }
                        break
        except Exception:
            pass

        # Detect Intel GPU
        try:
            proc = subprocess.run(
                ["wmic", "path", "win32_videocontroller", "get", "name,driverversion"],
                capture_output=True, text=True, timeout=10
            )
            
            if proc.returncode == 0:
                for line in proc.stdout.split('\n')[1:]:
                    if "Intel" in line:
                        parts = line.split()
                        gpu_info["intel"] = {
                            "name": line.strip(),
                            "driver_version": parts[-1] if parts else "unknown"
                        }
                        break
        except Exception:
            pass

        return gpu_info if gpu_info else None

    def _scan_nvidia_driver(self, nvidia_info: Dict) -> List[ScanResult]:
        """Scan NVIDIA driver for issues."""
        results = []
        driver_version = nvidia_info.get("driver_version", "")

        # Check for known vulnerable driver versions
        vulnerable_versions = [
            "361.43", "362.06", "364.72", "370.28", "372.54",  # Examples of known vulnerable versions
        ]

        for vuln_version in vulnerable_versions:
            if vuln_version in driver_version:
                results.append(ScanResult(
                    scanner="GPUDriverScanner",
                    category="vulnerable_driver",
                    name="Vulnerable NVIDIA Driver",
                    description=f"Vulnerable NVIDIA driver version detected: {driver_version}",
                    severity=70,
                    evidence=f"Driver version {driver_version} has known vulnerabilities",
                    details={"vendor": "NVIDIA", "version": driver_version, "vulnerability": vuln_version}
                ))
                return results

        # Check for outdated driver (older than 1 year)
        try:
            version_parts = driver_version.split('.')
            if version_parts and len(version_parts[0]) >= 3:
                major_version = int(version_parts[0])
                if major_version < 450:  # Rough check for old drivers
                    results.append(ScanResult(
                        scanner="GPUDriverScanner",
                        category="outdated_driver",
                        name="Outdated NVIDIA Driver",
                        description=f"NVIDIA driver version {driver_version} is outdated",
                        severity=40,
                        evidence=f"Driver version {driver_version} may lack security patches",
                        details={"vendor": "NVIDIA", "version": driver_version, "recommendation": "Update driver"}
                    ))
        except Exception:
            pass

        return results

    def _scan_amd_driver(self, amd_info: Dict) -> List[ScanResult]:
        """Scan AMD driver for issues."""
        results = []
        driver_version = amd_info.get("driver_version", "")

        # Check for known vulnerable AMD driver versions
        vulnerable_versions = [
            "15.12", "16.1", "16.2", "16.3", "16.40",  # Examples
        ]

        for vuln_version in vulnerable_versions:
            if vuln_version in driver_version:
                results.append(ScanResult(
                    scanner="GPUDriverScanner",
                    category="vulnerable_driver",
                    name="Vulnerable AMD Driver",
                    description=f"Vulnerable AMD driver version detected: {driver_version}",
                    severity=70,
                    evidence=f"Driver version {driver_version} has known vulnerabilities",
                    details={"vendor": "AMD", "version": driver_version, "vulnerability": vuln_version}
                ))
                return results

        return results

    def _scan_intel_driver(self, intel_info: Dict) -> List[ScanResult]:
        """Scan Intel GPU driver for issues."""
        results = []
        driver_version = intel_info.get("driver_version", "")

        # Intel drivers older than specific versions may have vulnerabilities
        try:
            version_parts = driver_version.split('.')
            if version_parts and len(version_parts) > 0:
                major_version = int(version_parts[0])
                if major_version < 26:  # Rough check
                    results.append(ScanResult(
                        scanner="GPUDriverScanner",
                        category="outdated_driver",
                        name="Outdated Intel GPU Driver",
                        description=f"Intel GPU driver version {driver_version} is outdated",
                        severity=35,
                        evidence=f"Driver version {driver_version} may lack security patches",
                        details={"vendor": "Intel", "version": driver_version}
                    ))
        except Exception:
            pass

        return results

    def _scan_gpu_software(self) -> List[ScanResult]:
        """Scan for suspicious GPU-related software."""
        results = []

        try:
            # Check for GPU overclock/modification software
            gpu_tools = {
                "NVIDIA GeForce Experience": 20,
                "AMD Radeon Software": 20,
                "GPU-Z": 30,  # GPU monitoring tool
                "Afterburner": 40,  # GPU overclocking tool (may be used for cheats)
                "MSI Afterburner": 40,
                "GPU Tweak": 40,
                "Sapphire TriXX": 40,
                "HWiNFO": 20,
            }

            proc = subprocess.run(
                ["wmic", "product", "list", "brief"],
                capture_output=True, text=True, timeout=30
            )

            if proc.returncode == 0:
                installed_software = proc.stdout.lower()
                
                for software, severity in gpu_tools.items():
                    software_lower = software.lower()
                    if software_lower in installed_software:
                        # Only flag overclocking tools with higher severity
                        if severity >= 40:
                            results.append(ScanResult(
                                scanner="GPUDriverScanner",
                                category="gpu_modification_tool",
                                name=software,
                                description=f"GPU modification/overclocking tool detected: {software}",
                                severity=severity,
                                evidence=f"Software {software} can modify GPU behavior",
                                details={"software": software, "category": "gpu_tool"}
                            ))
        except Exception as e:
            logger.debug(f"GPU software scan error: {e}")

        return results

    def _scan_driver_files(self) -> List[ScanResult]:
        """Scan GPU driver files for modifications."""
        results = []

        # Common GPU driver paths
        driver_paths = [
            Path("C:/Windows/System32/drivers/nvlddmkm.sys"),  # NVIDIA
            Path("C:/Windows/System32/drivers/amdkmdag.sys"),  # AMD
            Path("C:/Program Files/NVIDIA Corporation"),
            Path("C:/Program Files (x86)/AMD"),
        ]

        for driver_path in driver_paths:
            if driver_path.exists():
                try:
                    # Check file modification time (very recent modifications are suspicious)
                    import os
                    import time
                    
                    stat_info = os.stat(str(driver_path))
                    mod_time = stat_info.st_mtime
                    current_time = time.time()
                    days_since_mod = (current_time - mod_time) / (24 * 3600)
                    
                    if days_since_mod < 1:  # Modified in last 24 hours
                        results.append(ScanResult(
                            scanner="GPUDriverScanner",
                            category="recent_driver_modification",
                            name=driver_path.name,
                            description=f"GPU driver file recently modified: {driver_path.name}",
                            severity=65,
                            evidence=f"File modified {days_since_mod:.2f} hours ago",
                            details={"file": str(driver_path), "days_since_modification": days_since_mod}
                        ))
                except Exception as e:
                    logger.debug(f"Error checking driver file: {e}")

        return results
