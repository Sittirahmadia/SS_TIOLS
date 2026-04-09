# 🎮 SS-Tools Monitor - Web Dashboard

Professional web monitoring dashboard for real-time Minecraft player surveillance.

## Features

✅ **Live Screen Monitoring**
- Real-time player screen capture (500ms refresh)
- Multi-player monitoring support
- HD resolution support (up to 1280x720)

✅ **Activity Logging**
- Real-time activity feed
- Severity-based filtering
- Screenshot detection & logging
- Suspicious behavior tracking

✅ **Player Management**
- Monitor multiple players simultaneously
- Player status indicators
- Screenshot counters
- Behavior scores

✅ **Web Interface**
- Modern dark theme UI
- Real-time WebSocket updates
- Responsive design
- FPS counter

## Installation

```bash
pip install -r requirements.txt
```

## Running the Server

```bash
python3 run.py
```

Then open your browser to: **http://localhost:5555**

## API Endpoints

```
GET  /api/players                    # List all players
GET  /api/player/<id>                # Get player details
GET  /api/player/<id>/screen         # Get player's screen
GET  /api/activity                   # Get activity log
GET  /api/stats                      # Get system stats
```

## WebSocket Events

```
monitor_player           # Start monitoring a player
update_screen            # Send screen update
log_activity             # Log activity
update_player_stats      # Update player stats
```

## Integration with SS-Tools

```python
from web_monitor.app import socketio, monitoring

# Create monitoring session
monitoring.create_session('player_123', 'PlayerName')

# Update screen
monitoring.update_screen('player_123', screen_base64_data)

# Log activity
monitoring.log_activity('player_123', 'screenshot', 85, 'F2 pressed')

# Broadcast via WebSocket
socketio.emit('activity_logged', {...}, broadcast=True)
```

## Configuration

Environment variables:
```
PORT=5555                    # Server port (default: 5555)
DEBUG=False                  # Debug mode
```

## Performance

- Max players: 100+
- Screen refresh rate: 2 FPS
- Activity log buffer: 1000 events
- Memory usage: ~50-100MB

---

**Version**: v3.5.0
**Status**: Production Ready
