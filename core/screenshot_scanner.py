"""
SS-Tools Ultimate - Screenshot Scanner
Detects screenshot attempts in Minecraft using multi-layer detection.
Monitors: Keybind triggers, memory patterns, clipboard operations, file creation.
"""
import os
import re
import time
import ctypes
import psutil
import threading
import subprocess
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Set
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
import json

from core.database import CheatDatabase
from core.utils import ScanResult, ScanProgress, logger, file_hash_md5


class ScreenshotDetector:
    """Detects screenshot operations and keybinds."""
    
    # Common screenshot keybinds
    SCREENSHOT_KEYBINDS = {
        # Direct keycodes
        0x2C: "Print Screen (F13)",
        0x44: "F12",
        0x2A: "Print Screen",
        # Minecraft default
        0x44: "F12 (Minecraft Default)",
        # Common custom binds
        "shift+print": "Shift+Print Screen",
        "shift+f12": "Shift+F12",
        "ctrl+shift+s": "Ctrl+Shift+S (Screenshot)",
        "alt+print": "Alt+Print Screen",
        "windows+print": "Windows+Print Screen",
        "rshift": "Right Shift",
        "f2": "F2 (Minecraft F2)",
    }
    
    # Screenshot tool processes
    SCREENSHOT_TOOLS = {
        "screenpresso.exe": "Screenpresso",
        "sharex.exe": "ShareX",
        "greenshot.exe": "Greenshot",
        "snagit.exe": "SnagIt",
        "lightshot.exe": "Lightshot",
        "gyazo.exe": "Gyazo",
        "imgur.exe": "Imgur",
        "puush.exe": "Puush",
        "dropbox.exe": "Dropbox (Screenshot)",
        "printscreen.exe": "PrintScreen Utility",
    }
    
    # Memory patterns for screenshot libraries
    SCREENSHOT_PATTERNS = [
        b"SCREENSHOT",
        b"screenshot",
        b"Print Screen",
        b"PrintScreen",
        b"Capture Screen",
        b"SaveScreenshot",
        b"TakeScreenshot",
        b"ScreenCapture",
        b"GDI_SCREENSHOT",
        b"D3D_SCREENSHOT",
        b"OpenGL_SCREENSHOT",
        b"Vulkan_SCREENSHOT",
    ]

    def __init__(self):
        self.detection_events: List[Dict] = []
        self.minecraft_pids: Set[int] = set()
        self.last_screenshot_time: float = 0
        self.screenshot_count: int = 0

    def detect_keybind_press(self) -> Optional[str]:
        """Detect screenshot keybind press via Windows API."""
        try:
            # Check for Print Screen key
            if ctypes.windll.user32.GetAsyncKeyState(0x2C) & 0x8000:
                return "Print Screen"
            
            # Check for F12
            if ctypes.windll.user32.GetAsyncKeyState(0x7B) & 0x8000:
                return "F12"
            
            # Check for Shift key combinations
            if ctypes.windll.user32.GetAsyncKeyState(0xA1) & 0x8000:  # Right Shift
                return "Right Shift (Custom Bind)"
            
            # Check for Ctrl+Shift+S
            ctrl = ctypes.windll.user32.GetAsyncKeyState(0x11) & 0x8000
            shift = ctypes.windll.user32.GetAsyncKeyState(0x10) & 0x8000
            s_key = ctypes.windll.user32.GetAsyncKeyState(0x53) & 0x8000
            if ctrl and shift and s_key:
                return "Ctrl+Shift+S"
            
            # Check for F2 (Minecraft screenshot)
            if ctypes.windll.user32.GetAsyncKeyState(0x71) & 0x8000:
                return "F2 (Minecraft)"
                
        except Exception as e:
            logger.debug(f"Keybind detection error: {e}")
        
        return None

    def detect_clipboard_screenshot(self) -> bool:
        """Detect if screenshot was copied to clipboard."""
        try:
            proc = subprocess.run(
                ["powershell", "-Command", "([System.Windows.Forms.Clipboard]::GetImage()) -ne $null"],
                capture_output=True, text=True, timeout=5
            )
            return "True" in proc.stdout
        except Exception:
            pass
        return False

    def detect_file_creation(self, watch_dir: str = None) -> Optional[Path]:
        """Detect recent screenshot file creation."""
        if not watch_dir:
            watch_dir = str(Path.home() / "Pictures")
        
        if not os.path.exists(watch_dir):
            return None
        
        try:
            current_time = time.time()
            screenshot_exts = {".png", ".jpg", ".bmp"}
            
            for file in Path(watch_dir).iterdir():
                if file.suffix.lower() in screenshot_exts:
                    file_time = os.path.getmtime(str(file))
                    # File created in last 2 seconds
                    if current_time - file_time < 2:
                        return file
        except Exception as e:
            logger.debug(f"File detection error: {e}")
        
        return None

    def analyze_memory_patterns(self, pid: int) -> List[str]:
        """Analyze process memory for screenshot patterns."""
        findings = []
        
        try:
            # Try to read process memory (requires admin)
            proc = psutil.Process(pid)
            memory_maps = proc.memory_maps()
            
            for mmap in memory_maps:
                # Check for suspicious DLLs
                if "gdi32" in mmap.path.lower() or "user32" in mmap.path.lower():
                    findings.append(f"GDI/USER32 library loaded: {mmap.path}")
                if "dxgi" in mmap.path.lower() or "d3d" in mmap.path.lower():
                    findings.append(f"DirectX library loaded: {mmap.path}")
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
        except Exception as e:
            logger.debug(f"Memory pattern analysis error: {e}")
        
        return findings


class ScreenshotScanner:
    """Scans for screenshot operations in Minecraft."""

    def __init__(self, progress: ScanProgress = None):
        self.db = CheatDatabase()
        self.progress = progress or ScanProgress()
        self.detector = ScreenshotDetector()
        self.minecraft_process: Optional[psutil.Process] = None
        self.monitoring_active = False

    def scan(self) -> List[ScanResult]:
        """Run screenshot detection scan."""
        results = []
        self.progress.start("Screenshot Scanner", 5)

        try:
            # 1. Find Minecraft process
            self.progress.update("Finding Minecraft process...")
            self.minecraft_process = self._find_minecraft()
            
            if not self.minecraft_process:
                return results  # Minecraft not running
            
            # 2. Detect running screenshot tools
            self.progress.update("Scanning for screenshot tools...")
            results.extend(self._detect_screenshot_tools())
            
            # 3. Check keybind configuration
            self.progress.update("Analyzing keybind configuration...")
            results.extend(self._analyze_keybinds())
            
            # 4. Monitor for active screenshot attempts
            self.progress.update("Monitoring for screenshot attempts...")
            results.extend(self._monitor_screenshot_attempts())
            
            # 5. Analyze memory patterns
            self.progress.update("Analyzing memory patterns...")
            results.extend(self._analyze_minecraft_memory())

        except Exception as e:
            logger.warning(f"Screenshot Scanner failed: {e}")
            results.append(ScanResult(
                scanner="ScreenshotScanner",
                category="scanner_error",
                name="Screenshot Scanner Error",
                description=f"Screenshot scanner encountered error: {str(e)}",
                severity=0,
            ))

        return results

    def _find_minecraft(self) -> Optional[psutil.Process]:
        """Find running Minecraft process."""
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                if 'java' in proc.name().lower():
                    try:
                        cmdline = proc.cmdline()
                        if any('minecraft' in arg.lower() for arg in cmdline):
                            return proc
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
        except Exception as e:
            logger.debug(f"Minecraft process detection error: {e}")
        
        return None

    def _detect_screenshot_tools(self) -> List[ScanResult]:
        """Detect running screenshot tools."""
        results = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                proc_name = proc.name().lower()
                
                for tool_exe, tool_name in self.detector.SCREENSHOT_TOOLS.items():
                    if tool_exe.replace(".exe", "") in proc_name:
                        results.append(ScanResult(
                            scanner="ScreenshotScanner",
                            category="screenshot_tool_running",
                            name=tool_name,
                            description=f"Screenshot tool detected running: {tool_name}",
                            severity=75,
                            evidence=f"Process: {proc_name}",
                            details={"tool": tool_name, "process": proc_name, "pid": proc.pid}
                        ))
                        break
        except Exception as e:
            logger.debug(f"Screenshot tool detection error: {e}")
        
        return results

    def _analyze_keybinds(self) -> List[ScanResult]:
        """Analyze Minecraft keybind configuration."""
        results = []
        
        try:
            # Minecraft keybinds are stored in options.txt
            minecraft_dirs = [
                Path.home() / ".minecraft" / "options.txt",
                Path.home() / "AppData" / "Roaming" / ".minecraft" / "options.txt",
            ]
            
            for options_file in minecraft_dirs:
                if options_file.exists():
                    try:
                        with open(options_file, 'r') as f:
                            content = f.read().lower()
                            
                            # Look for screenshot keybind
                            if "key_screenshot" in content:
                                # Extract keybind value
                                match = re.search(r'key_screenshot:(\d+)', content)
                                if match:
                                    keycode = int(match.group(1))
                                    keybind_name = self._get_keycode_name(keycode)
                                    
                                    # Check if it's a suspicious keybind
                                    if keycode < 0:  # Negative = modified keybind
                                        results.append(ScanResult(
                                            scanner="ScreenshotScanner",
                                            category="modified_screenshot_keybind",
                                            name="Modified Screenshot Keybind",
                                            description=f"Non-default screenshot keybind detected: {keybind_name}",
                                            severity=60,
                                            evidence=f"Keybind: {keybind_name} (code: {keycode})",
                                            details={"keycode": keycode, "keybind": keybind_name}
                                        ))
                    except Exception as e:
                        logger.debug(f"Keybind analysis error: {e}")
        except Exception as e:
            logger.debug(f"Keybind file detection error: {e}")
        
        return results

    def _monitor_screenshot_attempts(self) -> List[ScanResult]:
        """Monitor for active screenshot attempts (real-time)."""
        results = []
        
        try:
            # Monitor for 3 seconds
            for _ in range(30):  # 30 * 100ms = 3 seconds
                # Check keybind press
                keybind = self.detector.detect_keybind_press()
                if keybind:
                    results.append(ScanResult(
                        scanner="ScreenshotScanner",
                        category="screenshot_keybind_triggered",
                        name="Screenshot Keybind Detected",
                        description=f"Screenshot keybind pressed: {keybind}",
                        severity=80,
                        evidence=f"Triggered: {keybind}",
                        details={"keybind": keybind, "timestamp": datetime.now().isoformat()}
                    ))
                
                # Check clipboard
                if self.detector.detect_clipboard_screenshot():
                    results.append(ScanResult(
                        scanner="ScreenshotScanner",
                        category="screenshot_clipboard_detected",
                        name="Screenshot in Clipboard",
                        description="Screenshot image detected in system clipboard",
                        severity=85,
                        evidence="Image data found in clipboard",
                        details={"timestamp": datetime.now().isoformat()}
                    ))
                
                # Check file creation
                screenshot_file = self.detector.detect_file_creation()
                if screenshot_file:
                    results.append(ScanResult(
                        scanner="ScreenshotScanner",
                        category="screenshot_file_created",
                        name="Screenshot File Created",
                        description=f"Screenshot file detected: {screenshot_file.name}",
                        severity=90,
                        evidence=f"File: {screenshot_file}",
                        filepath=str(screenshot_file),
                        details={"filename": screenshot_file.name, "path": str(screenshot_file)}
                    ))
                
                time.sleep(0.1)  # 100ms check interval
        except Exception as e:
            logger.debug(f"Screenshot attempt monitoring error: {e}")
        
        return results

    def _analyze_minecraft_memory(self) -> List[ScanResult]:
        """Analyze Minecraft process memory for screenshot patterns."""
        results = []
        
        if not self.minecraft_process:
            return results
        
        try:
            findings = self.detector.analyze_memory_patterns(self.minecraft_process.pid)
            for finding in findings:
                results.append(ScanResult(
                    scanner="ScreenshotScanner",
                    category="minecraft_memory_pattern",
                    name="Memory Pattern Detected",
                    description=f"Suspicious memory pattern in Minecraft: {finding}",
                    severity=65,
                    evidence=finding,
                    details={"pid": self.minecraft_process.pid, "pattern": finding}
                ))
        except Exception as e:
            logger.debug(f"Memory analysis error: {e}")
        
        return results

    def _get_keycode_name(self, keycode: int) -> str:
        """Convert keycode to human-readable name."""
        keycode_map = {
            0x2C: "Print Screen",
            0x44: "F12",
            0x71: "F2",
            0x10: "Shift",
            0xA1: "Right Shift",
            0x11: "Ctrl",
            0x12: "Alt",
        }
        return keycode_map.get(keycode, f"Key {keycode}")

    def start_background_monitoring(self) -> threading.Thread:
        """Start background screenshot monitoring."""
        def monitor():
            self.monitoring_active = True
            while self.monitoring_active:
                try:
                    # Continuous monitoring
                    results = self._monitor_screenshot_attempts()
                    if results:
                        logger.info(f"Screenshot attempts detected: {len(results)}")
                except Exception as e:
                    logger.debug(f"Background monitoring error: {e}")
                
                time.sleep(1)
        
        thread = threading.Thread(target=monitor, daemon=True)
        thread.start()
        return thread

    def stop_background_monitoring(self):
        """Stop background screenshot monitoring."""
        self.monitoring_active = False
