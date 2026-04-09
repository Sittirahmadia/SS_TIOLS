"""
SS-Tools Ultimate - Screen Live Streamer
Background service that streams screen to web dashboard (Minecraft only).
Runs even after SS-Tools is closed - monitors and records player activities.
"""
import os
import time
import json
import base64
import psutil
import threading
import subprocess
import hashlib
from pathlib import Path
from typing import Optional, Dict, List
from datetime import datetime, timedelta
from PIL import ImageGrab
from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import logging

logger = logging.getLogger(__name__)


class ScreenCaptureManager:
    """Manages screen capture and encoding."""
    
    MINECRAFT_PROCESS_NAMES = ["java", "javaw", "minecraft"]
    MAX_CAPTURE_SIZE = (1280, 720)  # Max resolution for streaming
    CAPTURE_QUALITY = 70  # JPEG quality
    
    def __init__(self):
        self.last_capture_time = 0
        self.capture_interval = 0.5  # 500ms between captures
        self.minecraft_active = False
        self.screen_history: List[Dict] = []
        self.max_history = 100
        
    def is_minecraft_active(self) -> bool:
        """Check if Minecraft is running and focused."""
        try:
            for proc in psutil.process_iter(['name', 'pid']):
                if any(mc in proc.name().lower() for mc in self.MINECRAFT_PROCESS_NAMES):
                    try:
                        # Get active window title
                        import ctypes
                        hwnd = ctypes.windll.user32.GetForegroundWindow()
                        length = ctypes.windll.user32.GetWindowTextLength(hwnd)
                        buf = ctypes.create_unicode_buffer(length + 1)
                        ctypes.windll.user32.GetWindowText(hwnd, buf, length + 1)
                        window_title = buf.value.lower()
                        
                        if "minecraft" in window_title or "java" in window_title:
                            self.minecraft_active = True
                            return True
                    except Exception:
                        pass
        except Exception:
            pass
        
        self.minecraft_active = False
        return False
    
    def capture_screen(self) -> Optional[bytes]:
        """Capture current screen as JPEG bytes."""
        try:
            # Only capture if enough time has passed
            current_time = time.time()
            if current_time - self.last_capture_time < self.capture_interval:
                return None
            
            self.last_capture_time = current_time
            
            # Capture screen
            screen = ImageGrab.grab()
            
            # Resize to max size
            screen.thumbnail(self.MAX_CAPTURE_SIZE, Image.Resampling.LANCZOS)
            
            # Convert to JPEG bytes
            import io
            buffer = io.BytesIO()
            screen.save(buffer, format='JPEG', quality=self.CAPTURE_QUALITY)
            return buffer.getvalue()
        except Exception as e:
            logger.error(f"Screen capture error: {e}")
            return None
    
    def encode_to_base64(self, image_bytes: bytes) -> str:
        """Encode image bytes to base64 string."""
        return base64.b64encode(image_bytes).decode('utf-8')
    
    def add_to_history(self, screen_data: Dict):
        """Add captured screen to history."""
        self.screen_history.append(screen_data)
        
        # Keep only last N frames
        if len(self.screen_history) > self.max_history:
            self.screen_history.pop(0)
    
    def get_screen_history(self, limit: int = 10) -> List[Dict]:
        """Get recent screen captures."""
        return self.screen_history[-limit:] if self.screen_history else []


class ScreenLiveStreamer:
    """Main streaming service - runs in background."""
    
    def __init__(self, port: int = 5555):
        self.app = Flask(__name__)
        CORS(self.app)
        self.port = port
        self.capture_manager = ScreenCaptureManager()
        self.streaming_active = False
        self.stream_thread: Optional[threading.Thread] = None
        self.player_activities: List[Dict] = []
        self.session_start_time = datetime.now()
        
        # Setup Flask routes
        self._setup_routes()
    
    def _setup_routes(self):
        """Setup Flask API routes."""
        
        @self.app.route('/')
        def index():
            """Live stream dashboard."""
            return '''
            <!DOCTYPE html>
            <html>
            <head>
                <title>SS-Tools Live Screen Monitor</title>
                <style>
                    * { margin: 0; padding: 0; box-sizing: border-box; }
                    body { 
                        background: #0d1117; 
                        color: #c9d1d9; 
                        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
                        padding: 20px;
                    }
                    .container { max-width: 1400px; margin: 0 auto; }
                    .header { 
                        display: flex; 
                        justify-content: space-between; 
                        align-items: center; 
                        margin-bottom: 20px;
                        padding: 20px;
                        background: #161b22;
                        border-radius: 8px;
                        border: 1px solid #30363d;
                    }
                    .title { font-size: 28px; font-weight: bold; color: #58a6ff; }
                    .status { 
                        padding: 10px 20px; 
                        border-radius: 6px; 
                        background: #238636;
                        color: #fff;
                        font-weight: bold;
                    }
                    .status.inactive { background: #da3633; }
                    .grid { display: grid; grid-template-columns: 1fr 300px; gap: 20px; }
                    .stream-container { 
                        background: #0d1117; 
                        border: 2px solid #30363d; 
                        border-radius: 8px;
                        overflow: hidden;
                    }
                    .stream-image {
                        width: 100%;
                        display: block;
                        background: #161b22;
                        aspect-ratio: 16/9;
                        object-fit: contain;
                    }
                    .stream-info {
                        padding: 15px;
                        background: #161b22;
                        border-top: 1px solid #30363d;
                        font-size: 13px;
                    }
                    .info-label { color: #8b949e; margin-bottom: 5px; }
                    .sidebar { display: flex; flex-direction: column; gap: 15px; }
                    .card { 
                        background: #161b22; 
                        border: 1px solid #30363d; 
                        border-radius: 8px; 
                        padding: 15px;
                    }
                    .card-title { font-weight: bold; margin-bottom: 10px; color: #58a6ff; }
                    .stat { display: flex; justify-content: space-between; padding: 5px 0; }
                    .stat-label { color: #8b949e; }
                    .stat-value { font-weight: bold; }
                    .activity-list { max-height: 300px; overflow-y: auto; }
                    .activity-item { 
                        padding: 8px; 
                        margin: 5px 0; 
                        background: #0d1117; 
                        border-left: 3px solid #58a6ff;
                        border-radius: 3px;
                        font-size: 12px;
                    }
                    .activity-time { color: #8b949e; font-size: 11px; }
                    @media (max-width: 768px) {
                        .grid { grid-template-columns: 1fr; }
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <div class="title">🔴 SS-Tools Live Monitor</div>
                        <div class="status" id="status">OFFLINE</div>
                    </div>
                    
                    <div class="grid">
                        <div class="stream-container">
                            <img class="stream-image" id="streamImage" src="" alt="Live Screen">
                            <div class="stream-info">
                                <div class="info-label">Last Update: <span id="lastUpdate">-</span></div>
                                <div class="info-label">FPS: <span id="fps">0</span></div>
                                <div class="info-label">Minecraft: <span id="mcStatus">Checking...</span></div>
                            </div>
                        </div>
                        
                        <div class="sidebar">
                            <div class="card">
                                <div class="card-title">📊 Session Stats</div>
                                <div class="stat">
                                    <span class="stat-label">Session Duration</span>
                                    <span class="stat-value" id="sessionDuration">0m</span>
                                </div>
                                <div class="stat">
                                    <span class="stat-label">Frames Captured</span>
                                    <span class="stat-value" id="frameCount">0</span>
                                </div>
                                <div class="stat">
                                    <span class="stat-label">Screenshot Attempts</span>
                                    <span class="stat-value" id="screenshotCount">0</span>
                                </div>
                                <div class="stat">
                                    <span class="stat-label">Suspicious Activity</span>
                                    <span class="stat-value" id="suspiciousCount">0</span>
                                </div>
                            </div>
                            
                            <div class="card">
                                <div class="card-title">⚡ Recent Activity</div>
                                <div class="activity-list" id="activityList">
                                    <div style="color: #8b949e; font-size: 12px;">No activities recorded</div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <script>
                    let frameCount = 0;
                    let lastUpdateTime = Date.now();
                    let fps = 0;
                    
                    async function updateStream() {
                        try {
                            const response = await fetch('/api/stream/current');
                            const data = await response.json();
                            
                            if (data.image) {
                                document.getElementById('streamImage').src = 'data:image/jpeg;base64,' + data.image;
                                frameCount++;
                                
                                // Update FPS
                                const now = Date.now();
                                const elapsed = (now - lastUpdateTime) / 1000;
                                if (elapsed >= 1) {
                                    fps = Math.round(frameCount / elapsed);
                                    frameCount = 0;
                                    lastUpdateTime = now;
                                }
                                document.getElementById('fps').textContent = fps;
                            }
                            
                            if (data.minecraft_active) {
                                document.getElementById('status').textContent = 'LIVE';
                                document.getElementById('status').className = 'status';
                                document.getElementById('mcStatus').textContent = '✓ Running';
                            } else {
                                document.getElementById('status').textContent = 'OFFLINE';
                                document.getElementById('status').className = 'status inactive';
                                document.getElementById('mcStatus').textContent = '✗ Not Running';
                            }
                            
                            document.getElementById('lastUpdate').textContent = new Date().toLocaleTimeString();
                        } catch (error) {
                            console.error('Stream error:', error);
                        }
                    }
                    
                    async function updateStats() {
                        try {
                            const response = await fetch('/api/stats');
                            const stats = await response.json();
                            
                            document.getElementById('frameCount').textContent = stats.total_captures;
                            document.getElementById('screenshotCount').textContent = stats.screenshot_attempts;
                            document.getElementById('suspiciousCount').textContent = stats.suspicious_activities;
                            
                            const minutes = Math.floor(stats.session_duration / 60);
                            document.getElementById('sessionDuration').textContent = minutes + 'm';
                            
                            // Update activity list
                            const actList = document.getElementById('activityList');
                            if (stats.recent_activities.length > 0) {
                                actList.innerHTML = stats.recent_activities.map(act => 
                                    `<div class="activity-item">
                                        <strong>${act.type}</strong>
                                        <div class="activity-time">${new Date(act.timestamp).toLocaleTimeString()}</div>
                                    </div>`
                                ).join('');
                            }
                        } catch (error) {
                            console.error('Stats error:', error);
                        }
                    }
                    
                    // Update stream every 500ms
                    setInterval(updateStream, 500);
                    
                    // Update stats every 2 seconds
                    setInterval(updateStats, 2000);
                    
                    // Initial update
                    updateStream();
                    updateStats();
                </script>
            </body>
            </html>
            '''
        
        @self.app.route('/api/stream/current')
        def get_current_stream():
            """Get current screen capture."""
            image_bytes = self.capture_manager.capture_screen()
            
            if not image_bytes:
                # Return last captured image
                if self.capture_manager.screen_history:
                    return jsonify({
                        'image': self.capture_manager.screen_history[-1].get('image_base64'),
                        'minecraft_active': self.capture_manager.minecraft_active,
                        'timestamp': datetime.now().isoformat()
                    })
                return jsonify({'image': None, 'minecraft_active': self.capture_manager.minecraft_active})
            
            image_base64 = self.capture_manager.encode_to_base64(image_bytes)
            
            # Store in history
            self.capture_manager.add_to_history({
                'image_base64': image_base64,
                'timestamp': datetime.now().isoformat(),
                'minecraft_active': self.capture_manager.minecraft_active
            })
            
            return jsonify({
                'image': image_base64,
                'minecraft_active': self.capture_manager.minecraft_active,
                'timestamp': datetime.now().isoformat()
            })
        
        @self.app.route('/api/stats')
        def get_stats():
            """Get session statistics."""
            session_duration = (datetime.now() - self.session_start_time).total_seconds()
            
            return jsonify({
                'total_captures': len(self.capture_manager.screen_history),
                'screenshot_attempts': len([a for a in self.player_activities if a['type'] == 'Screenshot']),
                'suspicious_activities': len([a for a in self.player_activities if a.get('severity', 0) > 70]),
                'session_duration': session_duration,
                'minecraft_active': self.capture_manager.minecraft_active,
                'recent_activities': self.player_activities[-10:]
            })
        
        @self.app.route('/api/activities', methods=['POST'])
        def log_activity():
            """Log suspicious activity."""
            data = request.json
            activity = {
                'type': data.get('type', 'Unknown'),
                'description': data.get('description', ''),
                'severity': data.get('severity', 50),
                'timestamp': datetime.now().isoformat()
            }
            self.player_activities.append(activity)
            
            # Keep only last 100 activities
            if len(self.player_activities) > 100:
                self.player_activities.pop(0)
            
            return jsonify({'status': 'logged'})
        
        @self.app.route('/api/health')
        def health():
            """Health check."""
            return jsonify({
                'status': 'ok',
                'streaming': self.streaming_active,
                'minecraft_active': self.capture_manager.minecraft_active,
                'uptime': (datetime.now() - self.session_start_time).total_seconds()
            })
    
    def start_streaming(self):
        """Start screen streaming service."""
        self.streaming_active = True
        logger.info(f"Screen Live Streamer started on port {self.port}")
        
        # Run in background
        self.stream_thread = threading.Thread(
            target=lambda: self.app.run(host='0.0.0.0', port=self.port, debug=False, use_reloader=False),
            daemon=True
        )
        self.stream_thread.start()
    
    def stop_streaming(self):
        """Stop screen streaming service."""
        self.streaming_active = False
        logger.info("Screen Live Streamer stopped")


class BackgroundScreenMonitor:
    """Monitors screen even after SS-Tools is closed."""
    
    def __init__(self, port: int = 5555):
        self.streamer = ScreenLiveStreamer(port=port)
        self.monitoring_thread: Optional[threading.Thread] = None
        self.is_running = False
        
        # Config file
        self.config_file = Path.home() / ".ss-tools" / "monitor.json"
        self.config_file.parent.mkdir(exist_ok=True)
    
    def start_background_monitoring(self):
        """Start background monitoring service."""
        def monitor():
            self.is_running = True
            logger.info("Background screen monitor started")
            
            # Save config
            self._save_config({'status': 'running', 'start_time': datetime.now().isoformat()})
            
            # Start streamer
            self.streamer.start_streaming()
            
            # Keep running
            while self.is_running:
                time.sleep(1)
        
        self.monitoring_thread = threading.Thread(target=monitor, daemon=True)
        self.monitoring_thread.start()
    
    def stop_background_monitoring(self):
        """Stop background monitoring."""
        self.is_running = False
        self._save_config({'status': 'stopped', 'stop_time': datetime.now().isoformat()})
    
    def _save_config(self, config: Dict):
        """Save monitor configuration."""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f)
        except Exception as e:
            logger.error(f"Config save error: {e}")
    
    def get_stream_url(self) -> str:
        """Get streaming URL."""
        return f"http://localhost:{self.streamer.port}/"


# Global instance
_background_monitor: Optional[BackgroundScreenMonitor] = None


def start_background_screen_monitor(port: int = 5555):
    """Start global background screen monitor."""
    global _background_monitor
    _background_monitor = BackgroundScreenMonitor(port=port)
    _background_monitor.start_background_monitoring()
    return _background_monitor


def stop_background_screen_monitor():
    """Stop global background screen monitor."""
    global _background_monitor
    if _background_monitor:
        _background_monitor.stop_background_monitoring()
        _background_monitor = None


def get_background_monitor() -> Optional[BackgroundScreenMonitor]:
    """Get global background monitor instance."""
    return _background_monitor
