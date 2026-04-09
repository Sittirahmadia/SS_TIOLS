"""
SS-Tools Ultimate - Behavior Analyzer
Detects suspicious behavior patterns and activity sequences.
Multi-layer detection: Memory patterns, system calls, file operations, network activity.
"""
import os
import re
import time
import psutil
import threading
import subprocess
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Set
from datetime import datetime, timedelta
from collections import defaultdict, deque
import logging

logger = logging.getLogger(__name__)


class BehaviorPattern:
    """Defines a suspicious behavior pattern."""
    
    def __init__(self, name: str, indicators: List[str], severity: int = 70):
        self.name = name
        self.indicators = indicators
        self.severity = severity
        self.detection_count = 0
        self.last_detection_time: Optional[float] = None
    
    def matches(self, events: List[str]) -> bool:
        """Check if pattern matches the events."""
        event_str = " ".join(events).lower()
        for indicator in self.indicators:
            if indicator.lower() not in event_str:
                return False
        return True


class BehaviorAnalyzer:
    """Analyzes system behavior for suspicious patterns."""
    
    # Define suspicious behavior patterns
    BEHAVIOR_PATTERNS = [
        BehaviorPattern(
            "Screenshot Tool Activity",
            ["screenshot", "capture", "print screen", "share", "upload"],
            severity=85
        ),
        BehaviorPattern(
            "Screen Recording",
            ["screen", "record", "capture", "video", "encode"],
            severity=80
        ),
        BehaviorPattern(
            "Clipboard Manipulation",
            ["clipboard", "paste", "copy", "buffer", "image"],
            severity=70
        ),
        BehaviorPattern(
            "File Exfiltration",
            ["download", "upload", "ftp", "http", "send", "transmit"],
            severity=90
        ),
        BehaviorPattern(
            "Macro/Automation",
            ["macro", "automate", "script", "record", "replay", "bind"],
            severity=75
        ),
        BehaviorPattern(
            "Process Injection",
            ["inject", "hook", "patch", "modify", "dll", "load"],
            severity=100
        ),
        BehaviorPattern(
            "Memory Tampering",
            ["memory", "heap", "stack", "pointers", "patch", "modify"],
            severity=95
        ),
        BehaviorPattern(
            "Registry Modification",
            ["registry", "hkey", "regedit", "software", "modify"],
            severity=65
        ),
    ]
    
    # Memory signatures for suspicious tools
    MEMORY_SIGNATURES = {
        b"cheat": "Cheat Tool Reference",
        b"hack": "Hack Tool Reference",
        b"screenshot": "Screenshot Capability",
        b"record": "Recording Capability",
        b"inject": "Injection Capability",
        b"hook": "Hook Capability",
        b"bypass": "Bypass Capability",
    }
    
    def __init__(self):
        self.event_history: deque = deque(maxlen=1000)  # Last 1000 events
        self.pattern_detections: Dict[str, int] = defaultdict(int)
        self.minecraft_pid: Optional[int] = None
        self.suspicious_processes: Set[int] = set()
        self.session_start = time.time()
    
    def record_event(self, event_type: str, event_data: str = ""):
        """Record a system event."""
        event = {
            'type': event_type,
            'data': event_data,
            'timestamp': time.time(),
            'time_str': datetime.now().isoformat()
        }
        self.event_history.append(event)
    
    def find_minecraft_process(self) -> Optional[int]:
        """Find Minecraft process ID."""
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                if 'java' in proc.name().lower():
                    cmdline = proc.cmdline()
                    if any('minecraft' in arg.lower() for arg in cmdline):
                        self.minecraft_pid = proc.pid
                        return proc.pid
        except Exception as e:
            logger.debug(f"Minecraft process detection error: {e}")
        
        return None
    
    def analyze_process_behavior(self, pid: int) -> List[Dict]:
        """Analyze process behavior for suspicious indicators."""
        findings = []
        
        try:
            proc = psutil.Process(pid)
            
            # Get process info
            proc_info = {
                'pid': pid,
                'name': proc.name(),
                'cmdline': ' '.join(proc.cmdline()),
                'create_time': proc.create_time(),
                'memory': proc.memory_info().rss / 1024 / 1024,  # MB
            }
            
            # Check for suspicious command line arguments
            suspicious_args = [
                'screenshot', 'capture', 'record', 'stream',
                'inject', 'hook', 'bypass', 'cheat',
                'mod', 'hack', 'crack', 'keybind'
            ]
            
            for arg in proc.cmdline():
                arg_lower = arg.lower()
                if any(sus in arg_lower for sus in suspicious_args):
                    findings.append({
                        'type': 'suspicious_argument',
                        'process': proc.name(),
                        'argument': arg,
                        'severity': 75
                    })
            
            # Check memory usage anomalies (very high memory = suspicious)
            if proc_info['memory'] > 2048:  # > 2GB
                findings.append({
                    'type': 'high_memory_usage',
                    'process': proc.name(),
                    'memory_mb': proc_info['memory'],
                    'severity': 60
                })
            
            # Get open files
            try:
                open_files = proc.open_files()
                for f in open_files:
                    f_lower = f.path.lower()
                    # Check for screenshot/capture files
                    if any(ext in f_lower for ext in ['.png', '.jpg', '.bmp', '.tmp', '.log']):
                        if 'screenshot' in f_lower or 'capture' in f_lower:
                            findings.append({
                                'type': 'screenshot_file_open',
                                'process': proc.name(),
                                'file': f.path,
                                'severity': 85
                            })
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            # Check network connections
            try:
                connections = proc.net_connections()
                for conn in connections:
                    if conn.status == 'ESTABLISHED':
                        # Check for suspicious remote IPs/domains
                        if conn.raddr:
                            remote_ip = conn.raddr.ip
                            # Flag if uploading to suspicious servers
                            if self._is_suspicious_ip(remote_ip):
                                findings.append({
                                    'type': 'suspicious_network_connection',
                                    'process': proc.name(),
                                    'remote_ip': remote_ip,
                                    'remote_port': conn.raddr.port,
                                    'severity': 80
                                })
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
        
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logger.debug(f"Process analysis error: {e}")
        
        return findings
    
    def analyze_system_events(self) -> List[Dict]:
        """Analyze recent system events for behavior patterns."""
        findings = []
        
        # Convert event history to strings for pattern matching
        recent_events = []
        for event in list(self.event_history)[-50:]:  # Last 50 events
            recent_events.append(f"{event['type']}:{event['data']}")
        
        # Check patterns
        for pattern in self.BEHAVIOR_PATTERNS:
            if pattern.matches(recent_events):
                self.pattern_detections[pattern.name] += 1
                
                findings.append({
                    'type': 'behavior_pattern_detected',
                    'pattern': pattern.name,
                    'indicators': pattern.indicators,
                    'detection_count': self.pattern_detections[pattern.name],
                    'severity': pattern.severity
                })
        
        return findings
    
    def analyze_minecraft_memory(self) -> List[Dict]:
        """Analyze Minecraft process memory for suspicious signatures."""
        findings = []
        
        if not self.minecraft_pid:
            return findings
        
        try:
            proc = psutil.Process(self.minecraft_pid)
            
            # Get memory maps
            try:
                memory_maps = proc.memory_maps()
                for mmap in memory_maps:
                    mmap_lower = mmap.path.lower()
                    
                    # Check for suspicious DLLs
                    suspicious_dlls = [
                        'dinput', 'dxgi', 'd3d', 'gdi32', 'user32',
                        'kernel32', 'ntdll', 'msvcrt',
                        'cheat', 'hack', 'mod', 'patch'
                    ]
                    
                    for dll in suspicious_dlls:
                        if dll in mmap_lower:
                            findings.append({
                                'type': 'suspicious_dll_loaded',
                                'dll': mmap.path,
                                'severity': 70
                            })
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
        
        except Exception as e:
            logger.debug(f"Memory analysis error: {e}")
        
        return findings
    
    def detect_behavior_sequence(self) -> Optional[Dict]:
        """Detect suspicious behavior sequences."""
        if len(self.event_history) < 10:
            return None
        
        recent_events = list(self.event_history)[-20:]
        
        # Sequence 1: Screenshot attempt followed by upload
        screenshot_then_upload = False
        for i, event in enumerate(recent_events[:-1]):
            if 'screenshot' in event['type'].lower():
                for j in range(i+1, min(i+5, len(recent_events))):
                    if 'upload' in recent_events[j]['type'].lower() or \
                       'network' in recent_events[j]['type'].lower():
                        screenshot_then_upload = True
                        break
        
        if screenshot_then_upload:
            return {
                'sequence': 'screenshot_exfiltration',
                'severity': 95,
                'description': 'Screenshot captured and immediately sent over network'
            }
        
        # Sequence 2: Multiple screenshot attempts in short time
        screenshot_events = [e for e in recent_events if 'screenshot' in e['type'].lower()]
        if len(screenshot_events) >= 3:
            time_span = screenshot_events[-1]['timestamp'] - screenshot_events[0]['timestamp']
            if time_span < 10:  # 3+ screenshots in 10 seconds
                return {
                    'sequence': 'rapid_screenshots',
                    'severity': 80,
                    'description': f'Multiple screenshots in {time_span:.1f} seconds',
                    'count': len(screenshot_events)
                }
        
        return None
    
    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP is suspicious (known C2 server, etc)."""
        # This would connect to a threat intelligence database in production
        # For now, flag private IPs being used for uploads
        private_ranges = [
            '192.168.',
            '10.',
            '172.16.',
            '127.0.',
            'localhost'
        ]
        
        # If connecting to localhost or private IP with screenshot activity, it's suspicious
        return any(ip.startswith(p) for p in private_ranges)
    
    def get_behavior_score(self) -> int:
        """Calculate overall behavior suspicion score (0-100)."""
        score = 0
        
        # Base score from pattern detections
        if self.pattern_detections:
            avg_detections = sum(self.pattern_detections.values()) / len(self.pattern_detections)
            score += min(int(avg_detections * 5), 30)
        
        # Add points for specific patterns
        if 'Screenshot Tool Activity' in self.pattern_detections:
            score += 30
        if 'Process Injection' in self.pattern_detections:
            score += 40
        if 'File Exfiltration' in self.pattern_detections:
            score += 35
        
        # Check for behavior sequences
        sequence = self.detect_behavior_sequence()
        if sequence:
            score += 20
        
        return min(score, 100)
    
    def get_session_summary(self) -> Dict:
        """Get behavior analysis summary for session."""
        return {
            'session_duration': time.time() - self.session_start,
            'total_events': len(self.event_history),
            'pattern_detections': dict(self.pattern_detections),
            'behavior_score': self.get_behavior_score(),
            'suspicious_behavior_sequence': self.detect_behavior_sequence(),
            'minecraft_monitored': self.minecraft_pid is not None
        }
