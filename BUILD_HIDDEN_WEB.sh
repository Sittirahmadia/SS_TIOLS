#!/bin/bash
echo "=================================================="
echo "🔴 SS-Tools Ultimate v3.5.0 - Build with Hidden Web"
echo "=================================================="
echo ""
echo "Building .exe with hidden web monitor..."
echo "Web dashboard will run silently on http://localhost:5555"
echo ""

# Install dependencies
echo "Installing build dependencies..."
pip install -q pyinstaller pywin32

# Build executable
echo "Building executable..."
pyinstaller ss_tools_hidden_web.spec --clean

echo ""
echo "✓ Build complete!"
echo ""
echo "Output: dist/SS-Tools-Ultimate.exe"
echo ""
echo "Usage:"
echo "  1. Run: SS-Tools-Ultimate.exe"
echo "  2. GUI opens normally (looks like regular SS-Tools)"
echo "  3. Web monitor runs hidden in background"
echo "  4. Access dashboard: http://localhost:5555 in Chrome"
echo ""
echo "=================================================="
