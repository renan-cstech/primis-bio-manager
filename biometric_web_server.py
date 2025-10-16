#!/usr/bin/env python3
"""
Biometric Device Web Server
Multi-device management system for attendance tracking
"""

from flask import Flask, render_template, jsonify, request
from flask_sock import Sock
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread, Lock
import json
import struct
import logging
from typing import Optional, Dict, Any
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Import database module
import database as db

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Configuration
SERVER_HOST = '0.0.0.0'
SERVER_PORT = 7005
WEB_PORT = 5000

# Verification Mode Constants
VERIFY_MODES = {
    1: "Fingerprint",
    2: "Password",
    3: "ID Card",
    4: "FP + Password",
    5: "FP + ID Card",
    6: "Password + FP",
    7: "ID Card + FP",
    20: "Face",
    21: "Face + ID Card",
    22: "Face + Password",
    23: "ID Card + Face",
    24: "Password + Face"
}

# IO Mode Constants
IO_MODES = {
    0: "OUT",
    1: "IN"
}

# Flask app
app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False
sock = Sock(app)

# WebSocket clients
ws_clients = set()
ws_lock = Lock()


def broadcast_ws(message_type: str, data: Any):
    """Broadcast message to all WebSocket clients"""
    message = json.dumps({'type': message_type, 'data': data})
    dead_clients = set()

    with ws_lock:
        for client in ws_clients:
            try:
                client.send(message)
            except Exception:
                dead_clients.add(client)

        for client in dead_clients:
            ws_clients.discard(client)


def log_info(message: str, color: str = Fore.CYAN):
    """Professional colored logging"""
    print(f"{color}ℹ {message}{Style.RESET_ALL}")
    logger.info(message)


def log_success(message: str):
    """Success logging"""
    print(f"{Fore.GREEN}✓ {message}{Style.RESET_ALL}")
    logger.info(message)


def log_warning(message: str):
    """Warning logging"""
    print(f"{Fore.YELLOW}⚠ {message}{Style.RESET_ALL}")
    logger.warning(message)


def log_error(message: str):
    """Error logging"""
    print(f"{Fore.RED}✗ {message}{Style.RESET_ALL}")
    logger.error(message)


def log_device(device_id: str, message: str):
    """Device-specific logging"""
    print(f"{Fore.MAGENTA}[{device_id}] {message}{Style.RESET_ALL}")
    logger.info(f"[{device_id}] {message}")


def get_verify_mode_str(verify_mode: int) -> str:
    """Get verification mode string"""
    return VERIFY_MODES.get(verify_mode, f"Unknown ({verify_mode})")


def get_io_mode_str(io_mode: int) -> str:
    """Get IO mode string"""
    return IO_MODES.get(io_mode, f"Unknown ({io_mode})")


def format_timestamp(timestamp: str) -> str:
    """Format YYYYMMDDhhmmss to YYYY-MM-DD HH:MM:SS"""
    try:
        if len(timestamp) == 14:
            return f"{timestamp[0:4]}-{timestamp[4:6]}-{timestamp[6:8]} {timestamp[8:10]}:{timestamp[10:12]}:{timestamp[12:14]}"
    except:
        pass
    return timestamp


def parse_json_body(body: bytes) -> Optional[Dict]:
    """Parse JSON from hybrid packet body"""
    if len(body) < 4:
        return None

    try:
        json_length = struct.unpack('<I', body[:4])[0]
        if len(body) < 4 + json_length:
            return None

        json_bytes = body[4:4 + json_length]
        json_str = json_bytes.decode('utf-8')
        return json.JSONDecoder().raw_decode(json_str)[0]
    except Exception as e:
        log_error(f"JSON parse error: {e}")
        return None


class BiometricRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for device communication"""

    def log_message(self, format, *args):
        """Suppress default HTTP logging"""
        pass

    def send_response_with_headers(self, response_code: str):
        """Send HTTP response"""
        self.send_response(200)
        self.send_header('response_code', response_code)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_POST(self):
        """Handle POST requests"""
        try:
            request_code = self.headers.get('request_code')
            dev_id = self.headers.get('dev_id')

            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length) if content_length > 0 else b''

            # Check device status
            if dev_id:
                device_status = db.get_device_status(dev_id)
                if device_status == 'blocked':
                    log_warning(f"Blocked device attempted connection: {dev_id}")
                    self.send_response_with_headers('ERROR_DEVICE_BLOCKED')
                    return

                # Update last seen
                db.update_device_last_seen(dev_id)

            # Handle different request types
            if request_code == 'receive_cmd':
                self.handle_receive_cmd(dev_id)
            elif request_code == 'realtime_glog':
                self.handle_realtime_glog(dev_id, body)
            elif request_code == 'realtime_door_status':
                self.handle_realtime_door_status(dev_id, body)
            elif request_code == 'send_glog_data':
                self.handle_send_glog_data(dev_id, body)
            else:
                self.send_response_with_headers('OK')

        except Exception as e:
            log_error(f"Request handling error: {e}")
            self.send_error(500, str(e))

    def handle_receive_cmd(self, dev_id: str):
        """Handle command polling - no commands needed for realtime-only mode"""
        self.send_response_with_headers('ERROR_NO_CMD')

    def handle_realtime_glog(self, dev_id: str, body: bytes):
        """Handle real-time attendance log"""
        try:
            data = parse_json_body(body)
            if not data:
                self.send_response_with_headers('OK')
                return

            user_id = data.get('user_id')
            io_time = data.get('io_time', '')

            # Convert to int if string
            verify_mode = data.get('verify_mode', 0)
            if isinstance(verify_mode, str):
                verify_mode = int(verify_mode) if verify_mode.isdigit() else 0

            io_mode = data.get('io_mode', 0)
            if isinstance(io_mode, str):
                io_mode = int(io_mode) if io_mode.isdigit() else 0

            verify_mode_str = get_verify_mode_str(verify_mode)
            io_mode_str = get_io_mode_str(io_mode)
            datetime_str = format_timestamp(io_time)

            # Log to console
            log_device(dev_id, f"User {user_id} | {io_mode_str} | {verify_mode_str} | {datetime_str}")

            # Prepare log entry
            log_entry = {
                'device_id': dev_id,
                'user_id': user_id,
                'io_mode': io_mode,
                'io_mode_str': io_mode_str,
                'verify_mode': verify_mode,
                'verify_mode_str': verify_mode_str,
                'timestamp': io_time,
                'datetime': datetime_str
            }

            # Save to database
            if db.save_log(log_entry):
                log_success(f"Saved log: {dev_id} | User {user_id}")

            # Broadcast to WebSocket clients
            broadcast_ws('new_log', log_entry)

            self.send_response_with_headers('OK')

        except Exception as e:
            log_error(f"Error handling realtime_glog: {e}")
            self.send_response_with_headers('OK')

    def handle_realtime_door_status(self, dev_id: str, body: bytes):
        """Handle real-time door status"""
        try:
            data = parse_json_body(body)
            if data:
                log_device(dev_id, f"Door status: {data}")

            self.send_response_with_headers('OK')

        except Exception as e:
            log_error(f"Error handling door status: {e}")
            self.send_response_with_headers('OK')

    def handle_send_glog_data(self, dev_id: str, body: bytes):
        """Handle batch attendance log data"""
        try:
            data = parse_json_body(body)
            if data:
                glog_count = data.get('glog_count', 0)
                log_device(dev_id, f"Batch logs received: {glog_count} records")

            self.send_response_with_headers('OK')

        except Exception as e:
            log_error(f"Error handling batch logs: {e}")
            self.send_response_with_headers('OK')


# ==============================================================================
# Flask Routes
# ==============================================================================

@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html')


@app.route('/api/status')
def api_status():
    """Get server status"""
    total_logs = db.get_logs_count()
    devices = db.get_all_devices()

    # Enhance devices with connection status
    from datetime import datetime
    now = datetime.now()

    for device in devices:
        if device['last_seen']:
            try:
                # Try multiple datetime formats
                last_seen_str = device['last_seen']
                # SQLite CURRENT_TIMESTAMP format: 'YYYY-MM-DD HH:MM:SS'
                last_seen = datetime.strptime(last_seen_str, '%Y-%m-%d %H:%M:%S')
            except ValueError:
                try:
                    # Try ISO format
                    last_seen = datetime.fromisoformat(last_seen_str)
                except:
                    # If all fails, assume offline
                    device['connection_status'] = 'offline'
                    continue

            time_diff = (now - last_seen).total_seconds()

            # Connected if seen in last 2 minutes
            if time_diff < 120:
                device['connection_status'] = 'connected'
            # Recently active if seen in last 30 minutes
            elif time_diff < 1800:
                device['connection_status'] = 'recent'
            else:
                device['connection_status'] = 'offline'
        else:
            device['connection_status'] = 'never'

    return jsonify({
        'total_logs': total_logs,
        'total_devices': len(devices),
        'devices': devices
    })


@app.route('/api/logs')
def api_logs():
    """Get attendance logs"""
    limit = request.args.get('limit', type=int)
    offset = request.args.get('offset', 0, type=int)
    device_id = request.args.get('device_id')

    logs = db.get_logs(limit=limit, offset=offset, device_id=device_id)
    total = db.get_logs_count()

    return jsonify({
        'total': total,
        'returned': len(logs),
        'logs': logs
    })


@app.route('/api/devices')
def api_devices():
    """Get all devices"""
    from datetime import datetime
    now = datetime.now()
    devices = db.get_all_devices()

    # Add connection status to each device
    for device in devices:
        if device['last_seen']:
            try:
                # Try multiple datetime formats
                last_seen_str = device['last_seen']
                # SQLite CURRENT_TIMESTAMP format: 'YYYY-MM-DD HH:MM:SS'
                last_seen = datetime.strptime(last_seen_str, '%Y-%m-%d %H:%M:%S')
            except ValueError:
                try:
                    # Try ISO format
                    last_seen = datetime.fromisoformat(last_seen_str)
                except:
                    # If all fails, assume offline
                    device['connection_status'] = 'offline'
                    continue

            time_diff = (now - last_seen).total_seconds()

            # Connected if seen in last 2 minutes
            if time_diff < 120:
                device['connection_status'] = 'connected'
            # Recently active if seen in last 30 minutes
            elif time_diff < 1800:
                device['connection_status'] = 'recent'
            else:
                device['connection_status'] = 'offline'
        else:
            device['connection_status'] = 'never'

    return jsonify({
        'total': len(devices),
        'devices': devices
    })


@app.route('/api/devices/<device_id>/status', methods=['POST'])
def api_set_device_status(device_id: str):
    """Set device status (allowed/blocked)"""
    data = request.get_json() or {}
    status = data.get('status', 'allowed')

    if status not in ['allowed', 'blocked']:
        return jsonify({'success': False, 'message': 'Invalid status'}), 400

    if db.set_device_status(device_id, status):
        log_info(f"Device {device_id} status set to {status}")
        broadcast_ws('device_status_changed', {'device_id': device_id, 'status': status})
        return jsonify({'success': True, 'message': f'Device {status}'})
    else:
        return jsonify({'success': False, 'message': 'Failed to update device'}), 500


@app.route('/api/devices/<device_id>', methods=['PUT'])
def api_update_device(device_id: str):
    """Update device information"""
    data = request.get_json() or {}
    device_name = data.get('device_name')
    status = data.get('status', 'allowed')

    if db.upsert_device(device_id, device_name, status):
        log_info(f"Device {device_id} updated")
        broadcast_ws('device_updated', {'device_id': device_id})
        return jsonify({'success': True, 'message': 'Device updated'})
    else:
        return jsonify({'success': False, 'message': 'Failed to update device'}), 500


@app.route('/api/devices/<device_id>', methods=['DELETE'])
def api_delete_device(device_id: str):
    """Delete device"""
    if db.delete_device(device_id):
        log_info(f"Device {device_id} deleted")
        broadcast_ws('device_deleted', {'device_id': device_id})
        return jsonify({'success': True, 'message': 'Device deleted'})
    else:
        return jsonify({'success': False, 'message': 'Failed to delete device'}), 500


# ==============================================================================
# WebSocket Route
# ==============================================================================

@sock.route('/ws')
def websocket(ws):
    """WebSocket endpoint for real-time updates"""
    log_info("WebSocket client connected")

    with ws_lock:
        ws_clients.add(ws)

    try:
        # Send initial status
        total_logs = db.get_logs_count()
        devices = db.get_all_devices()

        ws.send(json.dumps({
            'type': 'status',
            'data': {
                'total_logs': total_logs,
                'total_devices': len(devices),
                'devices': devices
            }
        }))

        # Keep connection alive
        while True:
            message = ws.receive()
            if message is None:
                break

            # Handle ping/pong
            try:
                data = json.loads(message)
                if data.get('type') == 'ping':
                    ws.send(json.dumps({'type': 'pong'}))
            except:
                pass

    except Exception as e:
        log_info(f"WebSocket error: {e}")
    finally:
        with ws_lock:
            ws_clients.discard(ws)
        log_info("WebSocket client disconnected")


# ==============================================================================
# Server Startup
# ==============================================================================

def run_device_server():
    """Run the device communication HTTP server"""
    server_address = (SERVER_HOST, SERVER_PORT)
    httpd = HTTPServer(server_address, BiometricRequestHandler)
    log_success(f"Device server listening on {SERVER_HOST}:{SERVER_PORT}")
    httpd.serve_forever()


def run_web_server():
    """Run the Flask web server"""
    log_success(f"Web server starting on http://0.0.0.0:{WEB_PORT}")
    app.run(host='0.0.0.0', port=WEB_PORT, debug=False, use_reloader=False)


def main():
    """Main entry point"""
    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Biometric Multi-Device Management System{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")

    # Initialize database
    log_info("Initializing database...")
    db.init_database()
    log_success("Database initialized")

    log_info(f"Device communication: {SERVER_HOST}:{SERVER_PORT}")
    log_info(f"Web interface: http://localhost:{WEB_PORT}")

    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")

    # Start device server in background thread
    device_thread = Thread(target=run_device_server, daemon=True)
    device_thread.start()

    # Start web server in main thread
    try:
        run_web_server()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Shutting down...{Style.RESET_ALL}")


if __name__ == '__main__':
    main()
