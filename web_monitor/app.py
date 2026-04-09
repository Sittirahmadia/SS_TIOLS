"""
SS-Tools Ultimate - Web Monitoring Dashboard
Professional web interface for monitoring Minecraft player screens in real-time.
"""
from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
import os
import json
import time
import threading
import uuid
from datetime import datetime, timedelta
from collections import deque
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder='templates', static_folder='static')
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Global state
class MonitoringSession:
    def __init__(self):
        self.sessions = {}  # player_id -> session data
        self.activity_log = deque(maxlen=1000)
        self.players_online = []
        
    def create_session(self, player_id, player_name):
        """Create new monitoring session."""
        session = {
            'id': player_id,
            'name': player_name,
            'start_time': datetime.now().isoformat(),
            'last_activity': datetime.now().isoformat(),
            'screenshot_count': 0,
            'suspicious_count': 0,
            'status': 'MONITORING',
            'behavior_score': 0,
            'current_screen': None,
            'fps': 0,
            'memory_usage': 0,
            'minecraft_active': True
        }
        self.sessions[player_id] = session
        self.players_online.append(player_id)
        return session
    
    def update_screen(self, player_id, screen_data):
        """Update player screen capture."""
        if player_id in self.sessions:
            self.sessions[player_id]['current_screen'] = screen_data
            self.sessions[player_id]['last_activity'] = datetime.now().isoformat()
    
    def log_activity(self, player_id, activity_type, severity, description):
        """Log player activity."""
        event = {
            'timestamp': datetime.now().isoformat(),
            'player_id': player_id,
            'type': activity_type,
            'severity': severity,
            'description': description
        }
        self.activity_log.append(event)
        
        if player_id in self.sessions:
            if 'screenshot' in activity_type.lower():
                self.sessions[player_id]['screenshot_count'] += 1
            if severity > 70:
                self.sessions[player_id]['suspicious_count'] += 1
            self.sessions[player_id]['behavior_score'] = min(
                self.sessions[player_id]['behavior_score'] + (severity / 100),
                100
            )

monitoring = MonitoringSession()

# ============ WEB ROUTES ============

@app.route('/')
def index():
    """Main dashboard page."""
    return render_template('dashboard.html')

@app.route('/api/players')
def get_players():
    """Get all monitored players."""
    return jsonify({
        'players': list(monitoring.sessions.values()),
        'total': len(monitoring.sessions),
        'online': len(monitoring.players_online)
    })

@app.route('/api/player/<player_id>')
def get_player(player_id):
    """Get specific player details."""
    if player_id not in monitoring.sessions:
        return jsonify({'error': 'Player not found'}), 404
    
    session = monitoring.sessions[player_id]
    return jsonify(session)

@app.route('/api/player/<player_id>/screen')
def get_player_screen(player_id):
    """Get player's current screen."""
    if player_id not in monitoring.sessions:
        return jsonify({'error': 'Player not found'}), 404
    
    screen = monitoring.sessions[player_id].get('current_screen')
    if not screen:
        return jsonify({'screen': None})
    
    return jsonify({'screen': screen})

@app.route('/api/activity')
def get_activity():
    """Get recent activity log."""
    limit = request.args.get('limit', 50, type=int)
    player_id = request.args.get('player_id', None)
    
    if player_id:
        events = [e for e in list(monitoring.activity_log) if e['player_id'] == player_id]
    else:
        events = list(monitoring.activity_log)
    
    return jsonify({
        'activities': events[-limit:],
        'total': len(events)
    })

@app.route('/api/stats')
def get_stats():
    """Get system statistics."""
    total_screenshots = sum(s['screenshot_count'] for s in monitoring.sessions.values())
    total_suspicious = sum(s['suspicious_count'] for s in monitoring.sessions.values())
    avg_behavior_score = (
        sum(s['behavior_score'] for s in monitoring.sessions.values()) /
        len(monitoring.sessions) if monitoring.sessions else 0
    )
    
    return jsonify({
        'total_players': len(monitoring.sessions),
        'online_players': len(monitoring.players_online),
        'total_screenshots': total_screenshots,
        'total_suspicious_activities': total_suspicious,
        'average_behavior_score': round(avg_behavior_score, 1),
        'timestamp': datetime.now().isoformat()
    })

# ============ WEBSOCKET EVENTS ============

@socketio.on('connect')
def on_connect():
    """Handle client connection."""
    logger.info(f"Client connected: {request.sid}")
    emit('connection_response', {'data': 'Connected to SS-Tools Monitor'})

@socketio.on('disconnect')
def on_disconnect():
    """Handle client disconnection."""
    logger.info(f"Client disconnected: {request.sid}")

@socketio.on('monitor_player')
def on_monitor_player(data):
    """Start monitoring a player."""
    player_id = data.get('player_id', str(uuid.uuid4()))
    player_name = data.get('player_name', f'Player_{player_id[:8]}')
    
    session = monitoring.create_session(player_id, player_name)
    
    emit('player_monitored', {
        'player_id': player_id,
        'session': session
    }, broadcast=True)
    
    logger.info(f"Started monitoring player: {player_name} ({player_id})")

@socketio.on('update_screen')
def on_update_screen(data):
    """Update player screen data."""
    player_id = data.get('player_id')
    screen_data = data.get('screen')
    fps = data.get('fps', 0)
    
    if player_id in monitoring.sessions:
        monitoring.update_screen(player_id, screen_data)
        monitoring.sessions[player_id]['fps'] = fps
        
        emit('screen_updated', {
            'player_id': player_id,
            'timestamp': datetime.now().isoformat()
        }, broadcast=True)

@socketio.on('log_activity')
def on_log_activity(data):
    """Log player activity."""
    player_id = data.get('player_id')
    activity_type = data.get('type')
    severity = data.get('severity', 50)
    description = data.get('description', '')
    
    monitoring.log_activity(player_id, activity_type, severity, description)
    
    emit('activity_logged', {
        'player_id': player_id,
        'activity': activity_type,
        'severity': severity,
        'timestamp': datetime.now().isoformat()
    }, broadcast=True)

@socketio.on('update_player_stats')
def on_update_player_stats(data):
    """Update player statistics."""
    player_id = data.get('player_id')
    
    if player_id in monitoring.sessions:
        monitoring.sessions[player_id].update(data)
        
        emit('player_stats_updated', {
            'player_id': player_id,
            'stats': monitoring.sessions[player_id]
        }, broadcast=True)

# ============ ERROR HANDLERS ============

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def server_error(error):
    return jsonify({'error': 'Server error'}), 500

if __name__ == '__main__':
    logger.info("SS-Tools Monitor Web Server starting...")
    socketio.run(app, host='0.0.0.0', port=5555, debug=False)
