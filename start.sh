#!/bin/bash
# Clean up stale Xvfb lock files
rm -f /tmp/.X99-lock /tmp/.X11-unix/X99

# Start Xvfb virtual display
Xvfb :99 -screen 0 1280x800x24 -nolisten tcp &
sleep 2
export DISPLAY=:99

# Start the application
exec uvicorn src.main:app --host 0.0.0.0 --port 4000 --workers 1
