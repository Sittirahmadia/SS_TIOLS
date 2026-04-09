#!/usr/bin/env python3
"""
SS-Tools Ultimate - Web Monitor Server
Run this to start the web monitoring dashboard at http://localhost:5555
"""
import os
import sys
from app import app, socketio

if __name__ == '__main__':
    port = os.environ.get('PORT', 5555)
    print(f"\n" + "="*60)
    print(f"🚀 SS-Tools Monitor Web Server")
    print(f"📊 Dashboard: http://localhost:{port}")
    print(f"="*60 + "\n")
    
    socketio.run(app, host='0.0.0.0', port=int(port), debug=False)
