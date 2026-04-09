"""
SS-Tools Ultimate - Keybind Detector
Detects and analyzes custom screenshot keybinds.
Monitors: Minecraft options.txt, Windows registry, key presses.
"""
import re
import json
import ctypes
import threading
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class KeybindAnalyzer:
    """Analyzes keybind configurations for screenshot triggers."""
    
    # Minecraft keybind names that affect screenshots
    SCREENSHOT_RELATED_BINDS = [
        "key_screenshot",
        "key_toggle_perspective",
        "key_fullscreen",
        "key_menu",
    ]
    
    # Default Minecraft keycodes
    DEFAULT_KEYCODES = {
        "key_screenshot": 44,  # F2
        "key_toggle_perspective": 62,
    }
    
    # Suspicious keycodes (commonly remapped)
    SUSPICIOUS_REMAP_PATTERNS = [
        -1,  # Unbound
        0,   # None
        999, # Custom/cheat tool bind
    ]
    
    # Virtual key codes
    VKEY_MAP = {
        0x08: "Backspace",
        0x09: "Tab",
        0x0D: "Enter",
        0x10: "Shift",
        0x11: "Ctrl",
        0x12: "Alt",
        0x13: "Pause",
        0x14: "Caps Lock",
        0x1B: "Escape",
        0x20: "Space",
        0x21: "Page Up",
        0x22: "Page Down",
        0x23: "End",
        0x24: "Home",
        0x25: "Left Arrow",
        0x26: "Up Arrow",
        0x27: "Right Arrow",
        0x28: "Down Arrow",
        0x2C: "Print Screen",
        0x2D: "Insert",
        0x2E: "Delete",
        0x30: "0",
        0x31: "1",
        0x32: "2",
        0x33: "3",
        0x34: "4",
        0x35: "5",
        0x36: "6",
        0x37: "7",
        0x38: "8",
        0x39: "9",
        0x41: "A",
        0x42: "B",
        0x43: "C",
        0x44: "D",
        0x45: "E",
        0x46: "F",
        0x47: "G",
        0x48: "H",
        0x49: "I",
        0x4A: "J",
        0x4B: "K",
        0x4C: "L",
        0x4D: "M",
        0x4E: "N",
        0x4F: "O",
        0x50: "P",
        0x51: "Q",
        0x52: "R",
        0x53: "S",
        0x54: "T",
        0x55: "U",
        0x56: "V",
        0x57: "W",
        0x58: "X",
        0x59: "Y",
        0x5A: "Z",
        0x70: "F1",
        0x71: "F2",
        0x72: "F3",
        0x73: "F4",
        0x74: "F5",
        0x75: "F6",
        0x76: "F7",
        0x77: "F8",
        0x78: "F9",
        0x79: "F10",
        0x7A: "F11",
        0x7B: "F12",
        0xA0: "Left Shift",
        0xA1: "Right Shift",
        0xA2: "Left Ctrl",
        0xA3: "Right Ctrl",
        0xA4: "Left Alt",
        0xA5: "Right Alt",
    }
    
    def __init__(self):
        self.detected_binds: Dict[str, Dict] = {}
        self.key_press_history: List[Dict] = []
        self.max_history = 50
    
    def analyze_minecraft_options(self) -> Dict[str, List[Dict]]:
        """Analyze Minecraft options.txt for keybind configurations."""
        findings = {
            'suspicious': [],
            'modified': [],
            'normal': []
        }
        
        minecraft_dirs = [
            Path.home() / ".minecraft",
            Path.home() / "AppData" / "Roaming" / ".minecraft",
        ]
        
        for mc_dir in minecraft_dirs:
            options_file = mc_dir / "options.txt"
            
            if not options_file.exists():
                continue
            
            try:
                with open(options_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if not line or ':' not in line:
                            continue
                        
                        key, value = line.split(':', 1)
                        key = key.strip()
                        value = value.strip()
                        
                        # Check if it's a keybind entry
                        if key.startswith('key_'):
                            try:
                                keycode = int(value)
                                
                                # Get default keycode
                                default_code = self.DEFAULT_KEYCODES.get(key, None)
                                keyname = self.VKEY_MAP.get(keycode, f"Key_{keycode}")
                                
                                binding_info = {
                                    'bind_name': key,
                                    'keycode': keycode,
                                    'keyname': keyname,
                                    'default': default_code,
                                    'is_default': keycode == default_code,
                                    'file': str(options_file)
                                }
                                
                                # Categorize
                                if key in self.SCREENSHOT_RELATED_BINDS:
                                    if keycode in self.SUSPICIOUS_REMAP_PATTERNS:
                                        findings['suspicious'].append(binding_info)
                                    elif keycode != default_code:
                                        findings['modified'].append(binding_info)
                                    else:
                                        findings['normal'].append(binding_info)
                                else:
                                    findings['normal'].append(binding_info)
                                
                                self.detected_binds[key] = binding_info
                            
                            except ValueError:
                                pass  # Not a valid keycode
            
            except Exception as e:
                logger.error(f"Error reading Minecraft options: {e}")
        
        return findings
    
    def detect_key_press(self, vkey: int) -> Optional[str]:
        """Detect if specific virtual key is pressed."""
        try:
            if ctypes.windll.user32.GetAsyncKeyState(vkey) & 0x8000:
                return self.VKEY_MAP.get(vkey, f"Key_{vkey}")
        except Exception:
            pass
        return None
    
    def monitor_key_presses(self, duration_seconds: int = 5) -> List[Dict]:
        """Monitor key presses for specified duration."""
        self.key_press_history = []
        
        # Monitor specific keys
        keys_to_monitor = [
            0x2C,  # Print Screen
            0x71,  # F2
            0x7B,  # F12
            0xA1,  # Right Shift
            0x10,  # Shift
            0x11,  # Ctrl
            0x12,  # Alt
        ]
        
        import time
        start_time = time.time()
        
        while (time.time() - start_time) < duration_seconds:
            for vkey in keys_to_monitor:
                keyname = self.detect_key_press(vkey)
                if keyname:
                    event = {
                        'key': keyname,
                        'vkey': vkey,
                        'timestamp': datetime.now().isoformat(),
                        'unix_time': time.time()
                    }
                    self.key_press_history.append(event)
                    logger.debug(f"Key pressed: {keyname}")
            
            time.sleep(0.05)  # 50ms polling
        
        return self.key_press_history
    
    def analyze_key_patterns(self) -> List[Dict]:
        """Analyze key press patterns for suspicious behavior."""
        suspicious_patterns = []
        
        # Pattern 1: Rapid key presses (possible automation)
        if len(self.key_press_history) > 5:
            for i in range(len(self.key_press_history) - 5):
                time_span = (
                    self.key_press_history[i + 5]['unix_time'] - 
                    self.key_press_history[i]['unix_time']
                )
                
                # 6 key presses in less than 1 second = suspicious
                if time_span < 1.0:
                    suspicious_patterns.append({
                        'pattern': 'rapid_keypresses',
                        'keys': [k['key'] for k in self.key_press_history[i:i+6]],
                        'time_span': time_span,
                        'severity': 70
                    })
        
        # Pattern 2: Screenshot keybind pressed (obvious indicator)
        screenshot_keys = ['F2', 'Print Screen', 'F12']
        for event in self.key_press_history:
            if event['key'] in screenshot_keys:
                suspicious_patterns.append({
                    'pattern': 'screenshot_keybind_pressed',
                    'key': event['key'],
                    'timestamp': event['timestamp'],
                    'severity': 85
                })
        
        return suspicious_patterns
    
    def detect_macro_recording(self) -> bool:
        """Detect if macro recorder might be active."""
        try:
            # Check for common macro recorder processes
            import psutil
            macro_tools = [
                "autohotkey", "autoit", "lua", "macro",
                "recorder", "logitech", "razer"
            ]
            
            for proc in psutil.process_iter(['name']):
                proc_name = proc.name().lower()
                if any(tool in proc_name for tool in macro_tools):
                    return True
        except Exception:
            pass
        
        return False


class KeybindDetector:
    """Main keybind detection service."""
    
    def __init__(self):
        self.analyzer = KeybindAnalyzer()
        self.monitoring_active = False
        self.monitor_thread: Optional[threading.Thread] = None
    
    def full_keybind_analysis(self) -> Dict:
        """Perform full keybind analysis."""
        return {
            'options_analysis': self.analyzer.analyze_minecraft_options(),
            'macro_detected': self.analyzer.detect_macro_recording(),
            'detected_binds': self.analyzer.detected_binds
        }
    
    def monitor_keybinds(self, duration_seconds: int = 5) -> Dict:
        """Monitor keybinds for specified duration."""
        key_presses = self.analyzer.monitor_key_presses(duration_seconds)
        patterns = self.analyzer.analyze_key_patterns()
        
        return {
            'key_presses': key_presses,
            'suspicious_patterns': patterns,
            'total_keys_pressed': len(key_presses),
            'macro_detected': self.analyzer.detect_macro_recording()
        }
    
    def start_background_monitoring(self):
        """Start background keybind monitoring."""
        def monitor():
            self.monitoring_active = True
            while self.monitoring_active:
                analysis = self.monitor_keybinds(duration_seconds=60)
                if analysis['suspicious_patterns']:
                    logger.warning(f"Suspicious keybind patterns detected: {analysis['suspicious_patterns']}")
        
        self.monitor_thread = threading.Thread(target=monitor, daemon=True)
        self.monitor_thread.start()
    
    def stop_background_monitoring(self):
        """Stop background keybind monitoring."""
        self.monitoring_active = False
