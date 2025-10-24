#!/usr/bin/env python3
"""
Biometric Device Web Server
Multi-device management system for attendance tracking
"""

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed, rely on system environment

import os
import json
import struct
import logging
import secrets
import hashlib
import hmac
import time
from functools import wraps
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from threading import Thread, Lock
from http.server import HTTPServer, BaseHTTPRequestHandler

from flask import Flask, render_template, jsonify, request
from flask_sock import Sock
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Import database module
import database as db

# Import HRIS configuration
import hris_config

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Configuration - Environment-based
SERVER_HOST = os.getenv('SERVER_HOST', '0.0.0.0')
SERVER_PORT = int(os.getenv('SERVER_PORT', '7005'))
WEB_PORT = int(os.getenv('WEB_PORT', '5050'))

# Secure API Configuration
API_SECRET_KEY = secrets.token_hex(32)  # Generate a secure random key for tokens
API_RATE_LIMIT_WINDOW = hris_config.hris_config.API_RATE_LIMIT_WINDOW
API_RATE_LIMIT_MAX_REQUESTS = hris_config.hris_config.API_RATE_LIMIT_MAX_REQUESTS
API_TOKEN_EXPIRY_HOURS = hris_config.hris_config.API_TOKEN_EXPIRY_HOURS

# Rate limiting storage
rate_limit_store = {}
rate_limit_lock = Lock()

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


# ==============================================================================
# Secure API Functions
# ==============================================================================

def generate_api_token(client_id: str) -> str:
    """Generate a secure API token for a client"""
    timestamp = str(int(datetime.now().timestamp()))
    message = f"{client_id}:{timestamp}"
    signature = hmac.new(API_SECRET_KEY.encode(), message.encode(), hashlib.sha256).hexdigest()
    return f"{client_id}.{timestamp}.{signature}"


def verify_api_token(token: str) -> bool:
    """Verify an API token"""
    try:
        client_id, timestamp, signature = token.split('.')
        # Check token expiry
        token_time = datetime.fromtimestamp(int(timestamp))
        if datetime.now() - token_time > timedelta(hours=API_TOKEN_EXPIRY_HOURS):
            return False

        # Verify signature
        message = f"{client_id}:{timestamp}"
        expected_signature = hmac.new(API_SECRET_KEY.encode(), message.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(signature, expected_signature)
    except (ValueError, OSError):
        return False


def check_rate_limit(client_id: str) -> bool:
    """Check if client has exceeded rate limit"""
    current_time = datetime.now().timestamp()

    with rate_limit_lock:
        if client_id not in rate_limit_store:
            rate_limit_store[client_id] = []

        # Clean old requests
        rate_limit_store[client_id] = [
            req_time for req_time in rate_limit_store[client_id]
            if current_time - req_time < API_RATE_LIMIT_WINDOW
        ]

        # Check if under limit
        if len(rate_limit_store[client_id]) >= API_RATE_LIMIT_MAX_REQUESTS:
            return False

        # Add current request
        rate_limit_store[client_id].append(current_time)
        return True


def require_api_auth(f):
    """Decorator for API authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            log_warning("API request missing Bearer token")
            return jsonify({'error': 'Unauthorized', 'message': 'Missing or invalid token'}), 401

        token = auth_header[7:]  # Remove 'Bearer ' prefix
        if not verify_api_token(token):
            log_warning("API request with invalid token")
            return jsonify({'error': 'Unauthorized', 'message': 'Invalid token'}), 401

        # Extract client_id from token for rate limiting
        try:
            client_id = token.split('.')[0]
            if not check_rate_limit(client_id):
                log_warning(f"Rate limit exceeded for client: {client_id}")
                return jsonify({'error': 'Rate limit exceeded', 'message': 'Too many requests'}), 429
        except Exception as e:
            log_warning(f"Token parsing error: {e}")
            return jsonify({'error': 'Unauthorized', 'message': 'Invalid token format'}), 401

        return f(*args, **kwargs)
    return decorated_function


def validate_date_range(start_date: str, end_date: str) -> tuple:
    """Validate and parse date range parameters"""
    try:
        start = datetime.strptime(start_date, '%Y-%m-%d') if start_date else None
        end = datetime.strptime(end_date, '%Y-%m-%d') if end_date else None

        if end and start and end < start:
            raise ValueError("End date must be after start date")

        return start, end
    except ValueError as e:
        raise ValueError(f"Invalid date format. Use YYYY-MM-DD format. Error: {str(e)}")


def get_verify_mode_str(verify_mode: int) -> str:
    """Get verification mode string"""
    return VERIFY_MODES.get(verify_mode, f"Unknown ({verify_mode})")


def get_io_mode_str(io_mode: int) -> str:
    """Get IO mode string"""
    return IO_MODES.get(io_mode, f"Unknown ({io_mode})")


# Timezone configuration
UTC = timezone.utc
ASIA_MANILA = timezone(timedelta(hours=8))  # UTC+8

def format_timestamp(timestamp: str) -> str:
    """Format YYYYMMDDhhmmss to YYYY-MM-DD HH:MM:SS (assumes UTC input)"""
    try:
        if len(timestamp) == 14:
            return f"{timestamp[0:4]}-{timestamp[4:6]}-{timestamp[6:8]} {timestamp[8:10]}:{timestamp[10:12]}:{timestamp[12:14]}"
    except Exception:
        pass
    return timestamp


def parse_timestamp_to_utc(timestamp_str: str) -> datetime:
    """Parse YYYYMMDDhhmmss to UTC datetime object

    IMPORTANT: Device timestamps are assumed to be in Philippine Manila time (UTC+8).
    This prevents timezone boundary issues where attendance events
    could be recorded on different dates in UTC vs local time.
    """
    try:
        if len(timestamp_str) == 14:
            year = int(timestamp_str[0:4])
            month = int(timestamp_str[4:6])
            day = int(timestamp_str[6:8])
            hour = int(timestamp_str[8:10])
            minute = int(timestamp_str[10:12])
            second = int(timestamp_str[12:14])

            # Create datetime object in Manila time first (devices send Manila timestamps)
            manila_dt = datetime(year, month, day, hour, minute, second, tzinfo=ASIA_MANILA)

            # Convert Manila time to UTC for storage
            utc_dt = manila_dt.astimezone(UTC)
            return utc_dt
    except Exception as e:
        print(f"Error parsing timestamp {timestamp_str}: {e}")
        pass

    # Fallback: assume current UTC time
    return datetime.now(UTC)


def format_timestamp_utc(timestamp_str: str) -> str:
    """Format YYYYMMDDhhmmss to UTC datetime string"""
    utc_dt = parse_timestamp_to_utc(timestamp_str)
    return utc_dt.strftime('%Y-%m-%d %H:%M:%S')


def format_timestamp_local(timestamp_str: str) -> str:
    """Format YYYYMMDDhhmmss to Asia/Manila datetime string"""
    utc_dt = parse_timestamp_to_utc(timestamp_str)
    local_dt = utc_dt.astimezone(ASIA_MANILA)
    formatted = local_dt.strftime('%Y-%m-%d %H:%M:%S')

    # Log timezone conversion for debugging
    if timestamp_str and len(timestamp_str) >= 14:
        log_info(f"Timezone conversion: {timestamp_str} Manila -> {formatted} Manila (stored as UTC)")

    return formatted


def get_current_utc_string() -> str:
    """Get current UTC time as formatted string"""
    return datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S')


def get_current_local_string() -> str:
    """Get current Asia/Manila time as formatted string"""
    return datetime.now(ASIA_MANILA).strftime('%Y-%m-%d %H:%M:%S')


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
        """Handle real-time attendance log with optimized processing"""
        import time
        processing_start = time.time()

        try:
            data = parse_json_body(body)
            if not data:
                self.send_response_with_headers('OK')
                return

            # Extract and validate user_id (convert to int)
            user_id_raw = data.get('user_id')
            if user_id_raw is None:
                log_error(f"Missing user_id in realtime_glog data from device {dev_id}")
                self.send_response_with_headers('ERROR_INVALID_DATA')
                return

            # Convert user_id to integer
            try:
                user_id = int(user_id_raw)
            except (ValueError, TypeError):
                log_error(f"Invalid user_id format: {user_id_raw} (expected integer) from device {dev_id}")
                self.send_response_with_headers('ERROR_INVALID_USER_ID')
                return

            io_time = data.get('io_time', '')

            # Fast integer conversion for other fields
            verify_mode = int(data.get('verify_mode', 0)) if str(data.get('verify_mode', 0)).isdigit() else 0
            io_mode = int(data.get('io_mode', 0)) if str(data.get('io_mode', 0)).isdigit() else 0

            # Pre-compute strings for performance
            verify_mode_str = get_verify_mode_str(verify_mode)
            io_mode_str = get_io_mode_str(io_mode)

            # Store UTC timestamp in database (converted from Manila time), but keep original for reference
            datetime_utc = format_timestamp_utc(io_time)
            datetime_local = format_timestamp_local(io_time)

            # Validate timestamp conversion - ensure no date boundary issues
            try:
                utc_date = datetime_utc.split(' ')[0]  # YYYY-MM-DD
                local_date = datetime_local.split(' ')[0]  # YYYY-MM-DD

                # Log if dates differ (timezone boundary crossing)
                if utc_date != local_date:
                    log_info(f"Timezone boundary: UTC date {utc_date}, Manila date {local_date} for user {user_id}")

            except Exception as e:
                log_error(f"Error validating timestamp conversion: {e}")

            # Validate user ID range for primary device
            if dev_id == hris_config.hris_config.PRIMARY_DEVICE_ID:
                # Primary device (2401058352) should only accept users 1-8
                if not (1 <= user_id <= 8):
                    log_warning(f"Primary device {dev_id} received invalid user {user_id} (should be 1-8)")
                    self.send_response_with_headers('ERROR_INVALID_USER')
                    return

            # Apply alternating IN/OUT logic regardless of device
            from database import get_user_last_direction
            last_direction = get_user_last_direction(user_id)

            # Alternate logic: if last was IN, next is OUT; if last was OUT or None, next is IN
            if last_direction == 'IN':
                corrected_io_mode = 0  # OUT
                corrected_io_mode_str = 'OUT'
            else:  # last_direction is 'OUT' or None (first time)
                corrected_io_mode = 1  # IN
                corrected_io_mode_str = 'IN'

            # Prepare log entry with corrected direction and timezone info
            log_entry = {
                'device_id': dev_id,
                'user_id': user_id,
                'io_mode': corrected_io_mode,
                'io_mode_str': corrected_io_mode_str,
                'verify_mode': verify_mode,
                'verify_mode_str': verify_mode_str,
                'timestamp': io_time,  # Original device timestamp
                'datetime_utc': datetime_utc,  # UTC for database storage
                'datetime_local': datetime_local,  # Asia/Manila for display
                'timezone': 'Asia/Manila'
            }

            # Save to database
            save_success, is_duplicate = db.save_log(log_entry)
            if save_success:
                # Update direction cache for performance (only for new entries, not duplicates)
                if not is_duplicate:
                    db.update_user_direction_cache(user_id, corrected_io_mode_str)

                # Add device type to log entry for HRIS
                device_type = "PRIMARY" if dev_id == hris_config.hris_config.PRIMARY_DEVICE_ID else "SECONDARY"
                log_entry['device_type'] = device_type
                log_entry['is_primary'] = (dev_id == hris_config.hris_config.PRIMARY_DEVICE_ID)
                log_entry['is_duplicate'] = is_duplicate

                # Minimal logging for production - distinguish between new and duplicate
                log_type = "DUP" if is_duplicate else "NEW"
                log_success(f"✓ User {user_id} {corrected_io_mode_str} | Device {dev_id} [{log_type}]")

                # Broadcast to WebSocket clients (async) - send for both new and duplicate for real-time updates
            broadcast_ws('new_log', log_entry)

            # Send real-time webhook to HRIS - AUTOMATICALLY triggered by device usage
            logger.info(f"📤 AUTO WEBHOOK: Sending attendance for user {user_id} to HRIS...")
            try:
                from webhook_manager import webhook_manager
                webhook_success = webhook_manager.send_attendance_webhook(log_entry)
                if webhook_success:
                    logger.info(f"✅ AUTO WEBHOOK: Successfully sent to HRIS for user {user_id}")
                else:
                    logger.warning(f"⚠️ AUTO WEBHOOK: Failed to send to HRIS for user {user_id} (will retry)")
            except Exception as e:
                # Log webhook errors but keep minimal
                logger.error(f"❌ AUTO WEBHOOK ERROR for user {user_id}: {e}")

            # Quick response to device
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

@app.route('/', methods=['GET'])
def index():
    """Main dashboard"""
    return render_template('index.html')


@app.route('/api/status', methods=['GET'])
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
                except Exception:
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


@app.route('/api/logs', methods=['GET'])
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


@app.route('/api/devices', methods=['GET'])
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
                except Exception:
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
# Secure HRIS API Endpoints
# ==============================================================================

@app.route('/api/auth/token', methods=['POST'])
def api_generate_token():
    """Generate API token for HRIS integration"""
    data = request.get_json() or {}
    client_id = data.get('client_id')
    client_secret = data.get('client_secret')

    if not client_id or not client_secret:
        return jsonify({'error': 'Bad Request', 'message': 'client_id and client_secret required'}), 400

    # Check if client is allowed (if whitelist is configured)
    if not hris_config.hris_config.is_client_allowed(client_id):
        log_warning(f"Client not allowed: {client_id}")
        return jsonify({'error': 'Forbidden', 'message': 'Client not authorized'}), 403

    # Validate client secret
    if not hris_config.hris_config.validate_secret(client_secret):
        log_warning(f"Invalid client secret attempt for client: {client_id}")
        return jsonify({'error': 'Unauthorized', 'message': 'Invalid credentials'}), 401

    token = generate_api_token(client_id)
    log_info(f"API token generated for client: {client_id}")

    return jsonify({
        'success': True,
        'token': token,
        'expires_in': f"{API_TOKEN_EXPIRY_HOURS} hours",
        'client_id': client_id
    })


@app.route('/api/hris/status', methods=['GET'])
@require_api_auth
def api_hris_status():
    """Get system status for HRIS"""
    total_logs = db.get_logs_count()
    total_users = db.get_users_count()
    devices = db.get_all_devices()

    # Count connected devices
    connected_devices = 0
    now = datetime.now()

    for device in devices:
        if device['last_seen']:
            try:
                last_seen_str = device['last_seen']
                last_seen = datetime.strptime(last_seen_str, '%Y-%m-%d %H:%M:%S')
                if (now - last_seen).total_seconds() < 120:  # 2 minutes
                    connected_devices += 1
            except Exception:
                pass

    return jsonify({
        'status': 'online',
        'timestamp': datetime.now().isoformat(),
        'stats': {
            'total_logs': total_logs,
            'total_users': total_users,
            'total_devices': len(devices),
            'connected_devices': connected_devices
        }
    })


@app.route('/api/biometric/logs', methods=['GET'])
@require_api_auth
def api_biometric_logs():
    """Get attendance logs (HRIS-compatible format)"""
    try:
        # Parse query parameters
        limit = request.args.get('limit', type=int)
        offset = request.args.get('offset', 0, type=int)
        user_id = request.args.get('user_id', type=int)
        device_id = request.args.get('device_id')
        primary_only = request.args.get('primary_only', type=bool, default=False)
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')

        # Validate date range if provided
        if start_date or end_date:
            start_dt, end_dt = validate_date_range(start_date, end_date)
        else:
            start_dt, end_dt = None, None

        # Get logs from database
        if primary_only:
            # Only get logs from primary device
            logs = db.get_logs(limit=limit, offset=offset, device_id=hris_config.hris_config.PRIMARY_DEVICE_ID)
        else:
            logs = db.get_logs(limit=limit, offset=offset, device_id=device_id)

        # Filter by user_id and date range if specified
        filtered_logs = []
        for log in logs:
            # Filter by user_id
            if user_id and log['user_id'] != user_id:
                continue

            # Filter by date range
            if start_dt or end_dt:
                try:
                    log_datetime = datetime.strptime(log['datetime'], '%Y-%m-%d %H:%M:%S')
                    if start_dt and log_datetime.date() < start_dt.date():
                        continue
                    if end_dt and log_datetime.date() > end_dt.date():
                        continue
                except Exception:
                    continue

            filtered_logs.append(log)

        total = db.get_logs_count()

        return jsonify({
            'success': True,
            'total': total,
            'returned': len(filtered_logs),
            'primary_device': hris_config.hris_config.PRIMARY_DEVICE_ID,
            'logs': [{
                'id': log['id'],
                'user_id': log['user_id'],
                'device_id': log['device_id'],
                'device_type': 'PRIMARY' if log['device_id'] == hris_config.hris_config.PRIMARY_DEVICE_ID else 'SECONDARY',
                'is_primary': log['device_id'] == hris_config.hris_config.PRIMARY_DEVICE_ID,
                'timestamp': log['timestamp'],  # Original device timestamp
                'datetime_utc': log.get('datetime_utc', log.get('datetime', '')),  # UTC time
                'datetime_local': log.get('datetime_local', log.get('datetime', '')),  # Asia/Manila time
                'timezone': log.get('timezone', 'UTC'),
                'direction': 'in' if log['io_mode'] == 1 else 'out',
                'verification_method': log['verify_mode_str'],
                'created_at': log['created_at']
            } for log in filtered_logs]
        })

    except ValueError as e:
        return jsonify({'error': 'Bad Request', 'message': str(e)}), 400
    except Exception as e:
        log_error(f"Error in biometric logs API: {e}")
        return jsonify({'error': 'Internal Server Error', 'message': 'Failed to retrieve logs'}), 500


@app.route('/api/biometric/users', methods=['GET'])
@require_api_auth
def api_biometric_users():
    """Get enrolled users (HRIS-compatible format)"""
    try:
        limit = request.args.get('limit', type=int)
        offset = request.args.get('offset', 0, type=int)
        user_id = request.args.get('user_id', type=int)

        if user_id:
            # Get specific user
            user = db.get_user_by_id(user_id)
            if not user:
                return jsonify({'error': 'Not Found', 'message': f'User {user_id} not found'}), 404
            return jsonify({
                'success': True,
                'total': 1,
                'returned': 1,
                'users': [{
                    'user_id': user['user_id'],
                    'name': f'User {user["user_id"]}',  # Placeholder name
                    'privilege': user['privilege'],
                    'enabled': bool(user['enabled']),
                    'biometric_enabled': True,  # Assuming enrolled if in database
                    'updated_at': user['updated_at']
                }]
            })

        # Get all users
        users = db.get_users(limit=limit, offset=offset)
        total = db.get_users_count()

        return jsonify({
            'success': True,
            'total': total,
            'returned': len(users),
            'users': [{
                'user_id': user['user_id'],
                'name': f'User {user["user_id"]}',  # Placeholder name
                'privilege': user['privilege'],
                'enabled': bool(user['enabled']),
                'biometric_enabled': True,  # Assuming enrolled if in database
                'updated_at': user['updated_at']
            } for user in users]
        })

    except Exception as e:
        log_error(f"Error in biometric users API: {e}")
        return jsonify({'error': 'Internal Server Error', 'message': 'Failed to retrieve users'}), 500


@app.route('/api/biometric/sync', methods=['POST'])
@require_api_auth
def api_biometric_sync():
    """Sync user data from HRIS (HRIS-compatible format)"""
    try:
        data = request.get_json() or {}

        # Process user updates
        users_data = data.get('users', [])
        if users_data:
            # For now, just acknowledge - would need actual sync logic
            log_info(f"Received sync request for {len(users_data)} users")

        return jsonify({
            'success': True,
            'message': 'Sync request acknowledged',
            'received_users': len(users_data),
            'processed_at': datetime.now().isoformat()
        })

    except Exception as e:
        log_error(f"Error in biometric sync API: {e}")
        return jsonify({'error': 'Internal Server Error', 'message': 'Failed to process sync request'}), 500


@app.route('/api/biometric/webhook/status', methods=['GET'])
@require_api_auth
def api_webhook_status():
    """Get webhook status and health"""
    try:
        from webhook_manager import webhook_manager
        health = webhook_manager.health_check()

        return jsonify({
            'success': True,
            'webhook': health,
            'timestamp': datetime.now().isoformat()
        })

    except Exception as e:
        log_error(f"Error getting webhook status: {e}")
        return jsonify({
            'success': False,
            'error': 'Webhook status unavailable',
            'timestamp': datetime.now().isoformat()
        }), 500


@app.route('/api/biometric/manual-log', methods=['POST'])
@require_api_auth
def api_manual_attendance_log():
    """Manual attendance log endpoint that simulates real biometric device processing"""
    try:
        # Parse request data (same as device processing)
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data'}), 400

        # Extract and validate fields exactly like real device processing
        user_id_raw = data.get('user_id')
        device_id = data.get('device_id', 'unknown')

        # Validate required fields (minimal validation like real device)
        if user_id_raw is None or not device_id:
            return jsonify({'success': False, 'error': 'Missing user_id or device_id'}), 400

        # Convert user_id to integer (same validation as real device)
        try:
            user_id = int(user_id_raw)
        except (ValueError, TypeError):
            return jsonify({'success': False, 'error': f'Invalid user_id format: {user_id_raw} (expected integer)'}), 400

        # Validate user_id range for primary device (same as real processing)
        if device_id == hris_config.hris_config.PRIMARY_DEVICE_ID and not (1 <= user_id <= 8):
            return jsonify({'success': False, 'error': f'Invalid user_id {user_id} for primary device (should be 1-8)'}), 400

        # Generate timestamp (same logic as real device)
        io_time = data.get('timestamp', datetime.now().strftime('%Y%m%d%H%M%S'))

        # Process exactly like real device (handle_realtime_glog logic)
        verify_mode = int(data.get('verify_mode', 0)) if str(data.get('verify_mode', 0)).isdigit() else 0
        io_mode = int(data.get('io_mode', 0)) if str(data.get('io_mode', 0)).isdigit() else 0

        verify_mode_str = get_verify_mode_str(verify_mode)
        io_mode_str = get_io_mode_str(io_mode)
        datetime_utc = format_timestamp_utc(io_time)
        datetime_local = format_timestamp_local(io_time)

        # Apply alternating IN/OUT logic (exactly like real device)
        from database import get_user_last_direction
        last_direction = get_user_last_direction(user_id)

        if last_direction == 'IN':
            corrected_io_mode = 0  # OUT
            corrected_io_mode_str = 'OUT'
        else:  # last_direction is 'OUT' or None (first time)
            corrected_io_mode = 1  # IN
            corrected_io_mode_str = 'IN'

        # Create log entry (exactly like real device processing)
        log_entry = {
            'device_id': device_id,
            'user_id': user_id,
            'io_mode': corrected_io_mode,
            'io_mode_str': corrected_io_mode_str,
            'verify_mode': verify_mode,
            'verify_mode_str': verify_mode_str,
            'timestamp': io_time,
            'datetime_utc': datetime_utc,
            'datetime_local': datetime_local,
            'timezone': 'Asia/Manila'
        }

        # Save to database (exactly like real device)
        save_success, is_duplicate = db.save_log(log_entry)
        if save_success:
            # Update cache (exactly like real device) - only for new entries
            if not is_duplicate:
                db.update_user_direction_cache(user_id, corrected_io_mode_str)

            # Add device type info (exactly like real device)
            device_type = "PRIMARY" if device_id == hris_config.hris_config.PRIMARY_DEVICE_ID else "SECONDARY"
            log_entry['device_type'] = device_type
            log_entry['is_primary'] = (device_id == hris_config.hris_config.PRIMARY_DEVICE_ID)
            log_entry['is_duplicate'] = is_duplicate

            # Broadcast to WebSocket (exactly like real device) - send for both new and duplicate
            broadcast_ws('new_log', log_entry)

            # Send webhook (exactly like real device) - AUTOMATICALLY triggered
            logger.info(f"📤 AUTO WEBHOOK: Sending manual attendance for user {user_id} to HRIS...")
            try:
                from webhook_manager import webhook_manager
                webhook_success = webhook_manager.send_attendance_webhook(log_entry)
                if webhook_success:
                    logger.info(f"✅ AUTO WEBHOOK: Manual log successfully sent to HRIS for user {user_id}")
                else:
                    logger.warning(f"⚠️ AUTO WEBHOOK: Manual log failed to send to HRIS for user {user_id} (will retry)")
            except Exception as e:
                logger.error(f"❌ AUTO WEBHOOK ERROR for manual user {user_id}: {e}")

            # Log success (exactly like real device) - distinguish duplicates
            log_type = "DUP" if is_duplicate else "NEW"
            log_success(f"✓ User {user_id} {corrected_io_mode_str} | Device {device_id} [{log_type}]")

            # Return response with duplicate status for testing
            return jsonify({
                'success': True,
                'user_id': user_id,
                'direction': corrected_io_mode_str,
                'device_id': device_id,
                'timestamp': datetime_local,
                'is_duplicate': is_duplicate,
                'log_type': log_type
            })

        else:
            return jsonify({'success': False, 'error': 'Database save failed'}), 500

    except Exception as e:
        log_error(f"Test endpoint error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/biometric/webhook/retry', methods=['POST'])
@require_api_auth
def api_webhook_retry():
    """Manually retry failed webhooks"""
    try:
        data = request.get_json() or {}
        limit = data.get('limit', 10)  # Default to retry 10 failed webhooks

        from webhook_manager import webhook_manager
        retried_count = webhook_manager.retry_failed_webhooks(limit)

        return jsonify({
            'success': True,
            'message': f'Manually retried {retried_count} failed webhooks',
            'retried_count': retried_count,
            'limit': limit
        })

    except Exception as e:
        log_error(f"Error retrying webhooks: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to retry webhooks',
            'message': str(e)
        }), 500


@app.route('/api/biometric/webhook/test', methods=['POST'])
@require_api_auth
def api_webhook_test():
    """Test webhook endpoint connectivity and diagnose issues"""
    try:
        from webhook_manager import webhook_manager

        logger.info("🔍 Testing webhook endpoint connectivity...")

        # Test the webhook endpoint
        test_result = webhook_manager.test_webhook_endpoint()

        if test_result['success']:
            logger.info("✅ Webhook endpoint test successful")
            return jsonify({
                'success': True,
                'message': 'Webhook endpoint is accessible and responding',
                'test_result': test_result,
                'recommendation': 'Webhooks should work automatically now'
            })
        else:
            logger.warning(f"❌ Webhook endpoint test failed: {test_result.get('error', 'Unknown error')}")
            return jsonify({
                'success': False,
                'message': 'Webhook endpoint test failed',
                'test_result': test_result,
                'recommendation': 'Start HRIS server on localhost:8000 or update webhook URL',
                'troubleshooting': {
                    'check_hris_running': 'Ensure HRIS server is running on localhost:8000',
                    'check_endpoint': 'Verify /api/biometric/webhook endpoint exists in HRIS',
                    'check_network': 'Ensure no firewall blocking localhost:8000',
                    'alternative_url': 'Update BIOMETRIC_WEBHOOK_URL if HRIS is on different URL'
                }
            })

    except Exception as e:
        logger.error(f"Error testing webhook endpoint: {e}")
        return jsonify({
            'success': False,
            'error': f'Webhook test failed: {str(e)}',
            'recommendation': 'Check webhook configuration and HRIS server status'
        }), 500



@app.route('/api/server/time', methods=['GET'])
def api_server_time():
    """Get server time information for timezone verification"""
    return jsonify({
        'success': True,
        'server_timezone': 'UTC',
        'display_timezone': 'Asia/Manila',
        'current_time': {
            'utc': get_current_utc_string(),
            'local': get_current_local_string(),
            'utc_iso': datetime.now(UTC).isoformat(),
            'local_iso': datetime.now(ASIA_MANILA).isoformat()
        },
        'timezone_offset': {
            'utc_to_local_hours': 8,
            'description': 'Asia/Manila is UTC+8'
        },
        'timestamp': datetime.now(UTC).isoformat()
    })


@app.route('/api/biometric/performance', methods=['GET'])
@require_api_auth
def api_performance_stats():
    """Get performance statistics"""
    try:
        from webhook_manager import webhook_manager
        import database as db

        # Get cache stats
        cache_size = len(db._user_direction_cache) if hasattr(db, '_user_direction_cache') else 0

        # Get webhook stats
        webhook_stats = webhook_manager.get_stats()

        return jsonify({
            'success': True,
            'performance': {
                'cache': {
                    'user_direction_cache_size': cache_size
                },
                'webhooks': webhook_stats,
                'system': {
                    'uptime_seconds': 0,  # Could be implemented with psutil
                    'memory_usage_mb': 0   # Could be implemented with psutil
                }
            },
            'timestamp': datetime.now().isoformat()
        })

    except Exception as e:
        log_error(f"Error getting performance stats: {e}")
        return jsonify({
            'success': False,
            'error': f'Performance stats unavailable: {str(e)}',
            'timestamp': datetime.now().isoformat()
        }), 500


@app.route('/api/biometric/status', methods=['GET'])
@require_api_auth
def api_biometric_status():
    """Get biometric system status (HRIS-compatible format)"""
    total_logs = db.get_logs_count()
    total_users = db.get_users_count()
    devices = db.get_all_devices()

    # Count connected devices
    connected_devices = 0
    now = datetime.now()

    for device in devices:
        if device['last_seen']:
            try:
                last_seen_str = device['last_seen']
                last_seen = datetime.strptime(last_seen_str, '%Y-%m-%d %H:%M:%S')
                if (now - last_seen).total_seconds() < 120:  # 2 minutes
                    connected_devices += 1
            except Exception:
                pass

    # Calculate employee statistics (placeholder - would need actual HR data)
    total_active_employees = 60  # From HRIS data
    employees_with_biometric_id = 60  # Assuming all have biometric IDs
    connection_rate_percent = (employees_with_biometric_id / total_active_employees * 100) if total_active_employees > 0 else 0

    # Check for duplicate biometric IDs (simplified check)
    all_logs = db.get_logs(limit=1000)  # Get recent logs
    user_ids = [log['user_id'] for log in all_logs]
    duplicates = [uid for uid in set(user_ids) if user_ids.count(uid) > 1]
    duplicate_count = len(set(duplicates))

    # Calculate device-specific statistics
    primary_device_logs = [log for log in all_logs if log['device_id'] == hris_config.hris_config.PRIMARY_DEVICE_ID]
    primary_users = set([log['user_id'] for log in primary_device_logs])
    expected_users = set(range(1, 9))  # Users 1-8
    missing_users = expected_users - primary_users
    extra_users = primary_users - expected_users

    return jsonify({
        'success': True,
        'connection': {
            'status': 'connected' if connected_devices > 0 else 'disconnected',
            'api_url': f'http://{os.getenv("WEB_HOST", "localhost")}:{WEB_PORT}',
            'last_test': datetime.now().isoformat() + 'Z'
        },
        'devices': [{
            'id': device['device_id'],
            'name': device['device_name'] or 'Unnamed',
            'status': device['status'],
            'last_seen': device['last_seen'],
            'connection_status': 'connected' if device['last_seen'] and
                (now - datetime.strptime(device['last_seen'], '%Y-%m-%d %H:%M:%S')).total_seconds() < 120
                else 'disconnected',
            'is_primary': device['device_id'] == hris_config.hris_config.PRIMARY_DEVICE_ID,
            'device_type': 'PRIMARY' if device['device_id'] == hris_config.hris_config.PRIMARY_DEVICE_ID else 'SECONDARY'
        } for device in devices] if devices else None,
        'alignment': {
            'primary_device_id': hris_config.hris_config.PRIMARY_DEVICE_ID,
            'primary_device_name': 'Primary Terminal (Users 1-8)',
            'expected_users': sorted(list(expected_users)),
            'primary_device_users': sorted(list(primary_users)),
            'missing_users': sorted(list(missing_users)),
            'extra_users': sorted(list(extra_users)),
            'alignment_status': 'PERFECT' if not missing_users and not extra_users else 'NEEDS_ATTENTION'
        },
        'connections': {
            'total_active_employees': total_active_employees,
            'employees_with_biometric_id': employees_with_biometric_id,
            'connection_rate_percent': int(connection_rate_percent),
            'duplicate_biometric_ids_count': duplicate_count,
            'duplicate_biometric_ids': list(set(duplicates))[:10]  # Limit to first 10
        },
        'sync': {
            'enabled': True,
            'attendance_interval': 15,
            'user_interval': 60,
            'auto_create_records': True,
            'statistics': {
                'last_sync_attempt': None,
                'last_successful_sync': None,
                'total_synced_today': total_logs,  # Simplified - would need actual sync tracking
                'sync_errors_today': 0,
                'primary_device_logs_today': len(primary_device_logs)
            }
        },
        'config': {
            'client_id': 'hris_system',
            'token_expiry_hours': 24,
            'rate_limit_requests': 100,
            'rate_limit_window': 60,
            'primary_device_id': hris_config.hris_config.PRIMARY_DEVICE_ID
        },
        'webhook': {
            'enabled': hris_config.hris_config.WEBHOOK_ENABLED,
            'url': hris_config.hris_config.WEBHOOK_URL,
            'mode': hris_config.hris_config.WEBHOOK_MODE,
            'rate_limit': hris_config.hris_config.WEBHOOK_RATE_LIMIT,
            'timeout': hris_config.hris_config.WEBHOOK_TIMEOUT,
            'retry_enabled': hris_config.hris_config.WEBHOOK_RETRY_ENABLED
        }
    })


@app.route('/api/hris/logs', methods=['GET'])
@require_api_auth
def api_hris_logs():
    """Get attendance logs for HRIS integration"""
    try:
        # Parse query parameters
        limit = request.args.get('limit', type=int)
        offset = request.args.get('offset', 0, type=int)
        user_id = request.args.get('user_id', type=int)
        device_id = request.args.get('device_id')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')

        # Validate date range if provided
        if start_date or end_date:
            start_dt, end_dt = validate_date_range(start_date, end_date)
        else:
            start_dt, end_dt = None, None

        # Get logs from database
        logs = db.get_logs(limit=limit, offset=offset, device_id=device_id)

        # Filter by user_id and date range if specified
        filtered_logs = []
        for log in logs:
            # Filter by user_id
            if user_id and log['user_id'] != user_id:
                continue

            # Filter by date range
            if start_dt or end_dt:
                try:
                    log_datetime = datetime.strptime(log['datetime'], '%Y-%m-%d %H:%M:%S')
                    if start_dt and log_datetime.date() < start_dt.date():
                        continue
                    if end_dt and log_datetime.date() > end_dt.date():
                        continue
                except Exception:
                    continue

            filtered_logs.append(log)

        total = db.get_logs_count()

        return jsonify({
            'success': True,
            'total': total,
            'returned': len(filtered_logs),
            'logs': filtered_logs
        })

    except ValueError as e:
        return jsonify({'error': 'Bad Request', 'message': str(e)}), 400
    except Exception as e:
        log_error(f"Error in HRIS logs API: {e}")
        return jsonify({'error': 'Internal Server Error', 'message': 'Failed to retrieve logs'}), 500


@app.route('/api/hris/users', methods=['GET'])
@require_api_auth
def api_hris_users():
    """Get enrolled users for HRIS integration"""
    try:
        limit = request.args.get('limit', type=int)
        offset = request.args.get('offset', 0, type=int)
        user_id = request.args.get('user_id', type=int)

        if user_id:
            # Get specific user
            user = db.get_user_by_id(user_id)
            if not user:
                return jsonify({'error': 'Not Found', 'message': f'User {user_id} not found'}), 404
            return jsonify({
                'success': True,
                'total': 1,
                'returned': 1,
                'users': [user]
            })

        # Get all users
        users = db.get_users(limit=limit, offset=offset)
        total = db.get_users_count()

        return jsonify({
            'success': True,
            'total': total,
            'returned': len(users),
            'users': users
        })

    except Exception as e:
        log_error(f"Error in HRIS users API: {e}")
        return jsonify({'error': 'Internal Server Error', 'message': 'Failed to retrieve users'}), 500


@app.route('/api/hris/devices', methods=['GET'])
@require_api_auth
def api_hris_devices():
    """Get device status for HRIS integration"""
    try:
        devices = db.get_all_devices()
        now = datetime.now()

        # Enhance devices with connection status
        for device in devices:
            if device['last_seen']:
                try:
                    last_seen_str = device['last_seen']
                    last_seen = datetime.strptime(last_seen_str, '%Y-%m-%d %H:%M:%S')
                    time_diff = (now - last_seen).total_seconds()

                    if time_diff < 120:
                        device['connection_status'] = 'connected'
                    elif time_diff < 1800:
                        device['connection_status'] = 'recent'
                    else:
                        device['connection_status'] = 'offline'
                except Exception:
                    device['connection_status'] = 'offline'
            else:
                device['connection_status'] = 'never'

        return jsonify({
            'success': True,
            'total': len(devices),
            'devices': devices
        })

    except Exception as e:
        log_error(f"Error in HRIS devices API: {e}")
        return jsonify({'error': 'Internal Server Error', 'message': 'Failed to retrieve devices'}), 500


@app.route('/api/hris/sync', methods=['POST'])
@require_api_auth
def api_hris_sync():
    """Sync user data from HRIS (placeholder for future implementation)"""
    # This endpoint can be used to receive user updates from HRIS
    data = request.get_json() or {}

    # Placeholder response - implement actual sync logic as needed
    log_info("HRIS sync request received")

    return jsonify({
        'success': True,
        'message': 'Sync request acknowledged',
        'received_users': len(data.get('users', []))
    })


@app.route('/swagger', methods=['GET'])
def swagger_ui():
    """Serve Swagger UI for API testing"""
    return render_template('swagger-ui.html')


@app.route('/swagger.yaml', methods=['GET'])
def swagger_spec():
    """Serve Swagger specification file"""
    try:
        with open('swagger.yaml', 'r') as f:
            content = f.read()
        return content, 200, {'Content-Type': 'application/yaml'}
    except FileNotFoundError:
        return jsonify({'error': 'Specification file not found'}), 404


@app.route('/api/docs', methods=['GET'])
def api_documentation():
    """API documentation endpoint"""
    docs = {
        "title": "Biometric Server HRIS API",
        "version": "1.0.0",
        "description": "Secure API endpoints for HRIS integration",
        "authentication": {
            "type": "Bearer Token",
            "token_generation": "POST /api/auth/token",
            "token_format": "Authorization: Bearer <token>",
            "expiry": f"{API_TOKEN_EXPIRY_HOURS} hours"
        },
        "rate_limiting": {
            "requests_per_window": API_RATE_LIMIT_MAX_REQUESTS,
            "window_seconds": API_RATE_LIMIT_WINDOW
        },
        "endpoints": {
            "POST /api/auth/token": {
                "description": "Generate API token",
                "parameters": {
                    "client_id": "string (required)",
                    "client_secret": "string (required)"
                }
            },
            "GET /api/hris/status": {
                "description": "Get system status and statistics",
                "auth_required": True
            },
            "GET /api/hris/logs": {
                "description": "Get attendance logs with filtering",
                "auth_required": True,
                "parameters": {
                    "limit": "integer (optional)",
                    "offset": "integer (optional, default: 0)",
                    "user_id": "integer (optional)",
                    "device_id": "string (optional)",
                    "start_date": "YYYY-MM-DD (optional)",
                    "end_date": "YYYY-MM-DD (optional)"
                }
            },
            "GET /api/hris/users": {
                "description": "Get enrolled users",
                "auth_required": True,
                "parameters": {
                    "limit": "integer (optional)",
                    "offset": "integer (optional, default: 0)",
                    "user_id": "integer (optional, specific user)"
                }
            },
            "GET /api/hris/devices": {
                "description": "Get device status",
                "auth_required": True
            },
            "POST /api/hris/sync": {
                "description": "Sync user data from HRIS",
                "auth_required": True,
                "parameters": {
                    "users": "array of user objects (optional)"
                }
            },
            "GET /api/hris/logs/summary": {
                "description": "Get attendance summary for reporting",
                "auth_required": True,
                "parameters": {
                    "start_date": "YYYY-MM-DD (required)",
                    "end_date": "YYYY-MM-DD (required)"
                }
            }
        }
    }
    return jsonify(docs)


@app.route('/api/hris/logs/summary', methods=['GET'])
@require_api_auth
def api_hris_logs_summary():
    """Get attendance summary for HRIS reporting"""
    try:
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')

        if not start_date or not end_date:
            return jsonify({'error': 'Bad Request', 'message': 'start_date and end_date are required'}), 400

        start_dt, end_dt = validate_date_range(start_date, end_date)

        # Get all logs in date range
        logs = db.get_logs()

        # Filter by date range
        filtered_logs = []
        user_stats = {}

        for log in logs:
            try:
                log_datetime = datetime.strptime(log['datetime'], '%Y-%m-%d %H:%M:%S')
                if start_dt.date() <= log_datetime.date() <= end_dt.date():
                    filtered_logs.append(log)

                    # Aggregate user statistics
                    uid = log['user_id']
                    if uid not in user_stats:
                        user_stats[uid] = {'total_logs': 0, 'in_logs': 0, 'out_logs': 0}

                    user_stats[uid]['total_logs'] += 1
                    if log['io_mode'] == 1:  # IN
                        user_stats[uid]['in_logs'] += 1
                    elif log['io_mode'] == 0:  # OUT
                        user_stats[uid]['out_logs'] += 1

            except Exception:
                continue

        return jsonify({
            'success': True,
            'period': {
                'start_date': start_date,
                'end_date': end_date
            },
            'summary': {
                'total_logs': len(filtered_logs),
                'unique_users': len(user_stats),
                'user_stats': user_stats
            },
            'logs_count': len(filtered_logs)
        })

    except ValueError as e:
        return jsonify({'error': 'Bad Request', 'message': str(e)}), 400
    except Exception as e:
        log_error(f"Error in HRIS logs summary API: {e}")
        return jsonify({'error': 'Internal Server Error', 'message': 'Failed to generate summary'}), 500


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
            except Exception:
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
    log_info(f"HRIS API docs: http://localhost:{WEB_PORT}/api/docs")
    log_info(f"Swagger UI: http://localhost:{WEB_PORT}/swagger")

    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  HRIS API Endpoints:{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  - POST /api/auth/token (Generate API token){Style.RESET_ALL}")
    print(f"{Fore.CYAN}  - GET  /api/hris/status (System status){Style.RESET_ALL}")
    print(f"{Fore.CYAN}  - GET  /api/hris/logs (Attendance logs){Style.RESET_ALL}")
    print(f"{Fore.CYAN}  - GET  /api/hris/users (Enrolled users){Style.RESET_ALL}")
    print(f"{Fore.CYAN}  - GET  /api/hris/devices (Device status){Style.RESET_ALL}")
    print(f"{Fore.CYAN}  - POST /api/hris/sync (User sync){Style.RESET_ALL}")
    print(f"{Fore.CYAN}  - GET  /api/hris/logs/summary (Attendance summary){Style.RESET_ALL}")
    print(f"{Fore.CYAN}  - GET  /swagger (Interactive API testing){Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")

    # Start device server in background thread
    device_thread = Thread(target=run_device_server, daemon=True)
    device_thread.start()

    # Start web server in main thread
    try:
        run_web_server()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Shutting down...{Style.RESET_ALL}")


@app.route('/api/webhook-receiver/biometric', methods=['POST'])
def api_webhook_receiver_biometric():
    """Simple webhook receiver that accepts any POST data automatically (like sync but automated)"""
    try:
        # Import datetime at function level to avoid conflicts
        from datetime import datetime

        # Get any POST data (no strict validation like sync)
        webhook_data = request.get_json() or {}

        logger.info(f"📡 AUTO WEBHOOK RECEIVED: Processing attendance data automatically")

        # Process any attendance data sent via POST
        if webhook_data:
            # Extract attendance info (flexible parsing)
            payload = webhook_data.get('payload', {})
            attendance_data = payload.get('data', webhook_data)  # Fallback to direct data

            user_id = attendance_data.get('user_id', attendance_data.get('id', 'unknown'))
            # Properly extract direction with fallback logic
            direction = attendance_data.get('io_mode_str') or attendance_data.get('direction') or ('IN' if attendance_data.get('io_mode') == 1 else 'OUT' if attendance_data.get('io_mode') == 0 else 'unknown')

            # Format timestamp properly - prioritize readable format from webhook payload
            # Webhook sends: payload.timestamp_local (readable) and payload.timestamp (Unix int)
            timestamp_local = payload.get('timestamp_local')  # From biometric server webhook
            timestamp_unix = payload.get('timestamp')  # Unix timestamp (int)
            timestamp_data = attendance_data.get('timestamp')  # From data field
            
            # Priority: timestamp_local > timestamp_unix (convert) > timestamp_data
            if timestamp_local and isinstance(timestamp_local, str) and ':' in timestamp_local:
                # Already in readable format (YYYY-MM-DD HH:MM:SS)
                timestamp = timestamp_local
            elif timestamp_unix and timestamp_unix != 'unknown':
                # Convert Unix timestamp to readable format
                try:
                    if isinstance(timestamp_unix, int) or (isinstance(timestamp_unix, str) and timestamp_unix.isdigit()):
                        timestamp = datetime.fromtimestamp(int(timestamp_unix)).strftime('%Y-%m-%d %H:%M:%S')
                    else:
                        timestamp = timestamp_unix
                except:
                    timestamp = str(timestamp_unix)
            elif timestamp_data:
                # Fallback to data field timestamp
                timestamp = timestamp_data
            else:
                timestamp = 'unknown'

            log_success(f"🎯 AUTO PROCESSED: Attendance for user {user_id} {direction} at {timestamp}")

            return jsonify({
                'success': True,
                'message': 'Attendance data processed automatically',
                'processed_at': datetime.now().isoformat(),
                'user_id': user_id,
                'direction': direction,
                'timestamp': timestamp
            }), 200
        else:
            # Accept even empty POST requests (like sync)
            log_success("🎯 AUTO PROCESSED: Webhook received and acknowledged")
            return jsonify({
                'success': True,
                'message': 'Webhook processed automatically',
                'processed_at': datetime.now().isoformat()
            }), 200

    except Exception as e:
        logger.error(f"❌ Webhook receiver error: {e}")
        return jsonify({'error': f'Processing failed: {str(e)}'}), 500


@app.route('/api/webhook-receiver/status', methods=['GET'])
def api_webhook_receiver_status():
    """Check status of the local webhook receiver"""
    return jsonify({
        'success': True,
        'webhook_receiver': {
            'status': 'active',
            'endpoint': '/api/webhook-receiver/biometric',
            'supported_events': ['attendance_log'],
            'description': 'Automatically processes biometric attendance data'
        },
        'message': 'Local webhook receiver is running and ready to process automatic attendance data'
    })


if __name__ == '__main__':
    main()
