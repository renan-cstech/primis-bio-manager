#!/usr/bin/env bash

set -euo pipefail

# Biometric Server Management Script

WORKSPACE_PATH="/home/crsadmin/primis/primis-bio-manager"
UV_PATH="/home/crsadmin/.local/bin/uv"
SERVICE_NAME="biometric-server"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

cd "$WORKSPACE_PATH"

usage() {
    echo "Usage: $0 {register|start|stop|restart|unregister}"
    exit 1
}

if [ $# -eq 0 ]; then
    echo "Available commands:"
    echo "  register   - Register and enable the service"
    echo "  start      - Start the service"
    echo "  stop       - Stop the service"
    echo "  restart    - Restart the service"
    echo "  unregister - Unregister and remove the service"
    echo ""
    echo "Usage: $0 <command>"
    exec bash  # Launch interactive bash, keeping terminal open
fi

if [ $# -ne 1 ]; then
    usage
fi

case "$1" in
    register)
        if [ -f "$SERVICE_FILE" ]; then
            echo "Service already registered."
            exit 1
        fi

        sudo tee "$SERVICE_FILE" > /dev/null << EOF
[Unit]
Description=Biometric Device Web Server
After=network.target

[Service]
Type=simple
User=crsadmin
WorkingDirectory=${WORKSPACE_PATH}
ExecStart=${UV_PATH} run biometric_web_server.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

        sudo systemctl daemon-reload
        sudo systemctl enable "${SERVICE_NAME}"
        echo "Service registered and enabled."
        ;;
    unregister)
        if [ ! -f "$SERVICE_FILE" ]; then
            echo "Service not registered."
            exit 1
        fi

        sudo systemctl stop "${SERVICE_NAME}" || true
        sudo systemctl disable "${SERVICE_NAME}" || true
        sudo rm "$SERVICE_FILE"
        sudo systemctl daemon-reload
        echo "Service unregistered and removed."
        ;;
    start)
        sudo systemctl start "${SERVICE_NAME}"
        echo "Service started."
        ;;
    stop)
        sudo systemctl stop "${SERVICE_NAME}"
        echo "Service stopped."
        ;;
    restart)
        sudo systemctl restart "${SERVICE_NAME}"
        echo "Service restarted."
        ;;
    *)
        usage
        ;;
esac
