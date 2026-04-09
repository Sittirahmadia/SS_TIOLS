"""
SS-Tools Ultimate v3.5.0 - Main Entry Point
Enhanced version with hidden web monitoring background service.
Web dashboard runs silently on http://localhost:5555
"""
import os
import sys
import threading
import time
import logging
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ss_tools.log')
    ]
)
logger = logging.getLogger(__name__)

def start_hidden_web_monitor():
    """Start web monitoring dashboard in background (hidden)."""
    try:
        from web_monitor.app import app, socketio
        
        def run_web_server():
            logger.info("Starting hidden web monitor on port 5555...")
            # Run without debug, no console output
            socketio.run(
                app,
                host='0.0.0.0',
                port=5555,
                debug=False,
                use_reloader=False,
                log_output=False
            )
        
        # Start in background thread (daemon)
        web_thread = threading.Thread(target=run_web_server, daemon=True)
        web_thread.start()
        logger.info("✓ Hidden web monitor started successfully")
        
    except Exception as e:
        logger.error(f"Failed to start web monitor: {e}")

def main():
    """Main entry point."""
    print("="*60)
    print("🔴 SS-TOOLS ULTIMATE v3.5.0")
    print("="*60)
    print()
    print("✓ Main application starting...")
    print("✓ Web monitor running in background (hidden)")
    print("✓ Access dashboard: http://localhost:5555")
    print()
    
    # Start hidden web monitor
    start_hidden_web_monitor()
    
    # Give web server time to start
    time.sleep(2)
    
    # Now start main GUI
    try:
        from gui.main_window import QApplication, MainWindow
        
        print("✓ Loading GUI interface...")
        app = QApplication(sys.argv)
        window = MainWindow()
        window.show()
        
        logger.info("SS-Tools GUI started successfully")
        sys.exit(app.exec())
        
    except ImportError as e:
        print(f"✗ Error: Could not load GUI components: {e}")
        logger.error(f"GUI import error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"✗ Error: {e}")
        logger.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
