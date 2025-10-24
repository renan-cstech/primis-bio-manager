# HRIS API Integration Guide

## Overview

The Biometric Server provides secure API endpoints specifically designed for HRIS (Human Resources Information System) integration. This allows your HRIS system to securely retrieve attendance data, user information, device status, and synchronize user data with biometric devices.

## Quick Start for HRIS Teams

### 1. Interactive API Testing
**Visit the Swagger UI:** `http://localhost:5050/swagger`

The Swagger UI provides:
- Interactive API documentation
- "Try it out" functionality for all endpoints
- Automatic token management
- Real-time testing with live data

### 2. Basic API Flow
1. **Get Authentication Token** → `POST /api/auth/token`
2. **Test System Status** → `GET /api/hris/status`
3. **Fetch Attendance Data** → `GET /api/hris/logs`
4. **Sync User Data** → `POST /api/hris/sync`

### 3. Production Setup
- Set environment variable: `export HRIS_API_SECRET_KEY="your_secure_secret"`
- Use HTTPS endpoints in production
- Implement token refresh logic (tokens expire in 24 hours)

## Security Features

- **Bearer Token Authentication**: HMAC-based token system with configurable expiry
- **Rate Limiting**: Configurable request limits to prevent abuse
- **Client Whitelisting**: Optional client ID restrictions
- **Input Validation**: Comprehensive parameter validation
- **HTTPS Ready**: Designed for secure transport (configure your web server for HTTPS)

## Configuration

### Required Setup

**CRITICAL:** Change the default API secret before going to production!

```bash
# Required: Set a secure API secret (MANDATORY)
export HRIS_API_SECRET_KEY="your_actual_secure_secret_here"

# Start the server
./manage_biometric_server.sh start
```

### Optional Configuration

```bash
# Rate limiting (default: 100 requests per 60 seconds)
export HRIS_RATE_LIMIT_REQUESTS="100"
export HRIS_RATE_LIMIT_WINDOW="60"

# Token expiry in hours (default: 24)
export HRIS_TOKEN_EXPIRY_HOURS="24"

# Client whitelist (comma-separated, leave empty to allow all)
export HRIS_ALLOWED_CLIENTS="hris_system,backup_system"
```

### Configuration File

Advanced users can modify `hris_config.py` directly for additional configuration options.

## API Usage

### Option 1: Interactive Testing (Recommended for Development)

1. **Start the Server:**
   ```bash
   ./manage_biometric_server.sh start
   ```

2. **Open Swagger UI:**
   Visit: `http://localhost:5050/swagger`

3. **Test Interactively:**
   - Generate token using the Authentication section
   - Test any endpoint with "Try it out"
   - Token is automatically managed for subsequent requests

### Option 2: Command Line Testing

#### 1. Generate API Token

```bash
curl -X POST http://localhost:5050/api/auth/token \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "your_hris_system",
    "client_secret": "your_actual_secure_secret_here"
  }'
```

**Response:**
```json
{
  "success": true,
  "token": "your_hris_system.1640995200.abc123...",
  "expires_in": "24 hours",
  "client_id": "your_hris_system"
}
```

#### 2. Use API Endpoints

Store the token and use it for authenticated requests:

```bash
# Store token (replace with actual token from response)
TOKEN="your_hris_system.1640995200.abc123..."

# Make authenticated requests
curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:5050/api/hris/status
```

## API Endpoints

All endpoints require Bearer token authentication except `/api/auth/token`.

### 🔐 Authentication
**POST /api/auth/token**
- Generate API token for authentication

Parameters:
- `client_id`: Your HRIS system identifier
- `client_secret`: API secret key

### 📊 System Monitoring

**GET /api/hris/status**
- Returns system health and statistics
- No parameters required

```bash
curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:5050/api/hris/status
```

### 👥 User Management

**GET /api/hris/users**
- Get enrolled user information

Parameters:
- `limit` (optional): Number of users to return (default: all)
- `offset` (optional): Pagination offset (default: 0)
- `user_id` (optional): Get specific user by ID

```bash
# Get all users
curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:5050/api/hris/users

# Get specific user
curl -H "Authorization: Bearer $TOKEN" \
     "http://localhost:5050/api/hris/users?user_id=123"
```

### 📱 Device Management

**GET /api/hris/devices**
- Get status of all biometric devices
- No parameters required

```bash
curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:5050/api/hris/devices
```

### ⏰ Attendance Data

**GET /api/hris/logs**
- Retrieve attendance records with advanced filtering

Parameters:
- `limit` (optional): Records per page (1-1000, default: all)
- `offset` (optional): Pagination offset (default: 0)
- `user_id` (optional): Filter by specific user ID
- `device_id` (optional): Filter by device ID
- `start_date` (optional): Start date (YYYY-MM-DD)
- `end_date` (optional): End date (YYYY-MM-DD)

```bash
# Get recent attendance (last 30 days)
curl -H "Authorization: Bearer $TOKEN" \
     "http://localhost:5050/api/hris/logs?start_date=2024-01-01&end_date=2024-01-31&limit=100"

# Get specific user's attendance
curl -H "Authorization: Bearer $TOKEN" \
     "http://localhost:5050/api/hris/logs?user_id=123&limit=50"

# Get attendance from specific device
curl -H "Authorization: Bearer $TOKEN" \
     "http://localhost:5050/api/hris/logs?device_id=DEVICE001"
```

**GET /api/hris/logs/summary**
- Get aggregated attendance statistics for reporting

Parameters:
- `start_date` (required): Start date (YYYY-MM-DD)
- `end_date` (required): End date (YYYY-MM-DD)

```bash
curl -H "Authorization: Bearer $TOKEN" \
     "http://localhost:5050/api/hris/logs/summary?start_date=2024-01-01&end_date=2024-01-31"
```

### 🔄 Data Synchronization

**POST /api/hris/sync**
- Send user data updates from HRIS to biometric system

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     http://localhost:5050/api/hris/sync \
     -d '{
       "users": [
         {
           "user_id": 123,
           "name": "John Doe",
           "department": "IT",
           "enabled": true
         },
         {
           "user_id": 124,
           "name": "Jane Smith",
           "department": "HR",
           "enabled": false
         }
       ]
     }'
```

### 📖 Documentation

**GET /api/docs**
- Get API documentation (JSON format)
- No authentication required

**GET /swagger**
- Interactive Swagger UI for testing
- No authentication required

---

## 🪝 Real-Time Webhook Integration

### **Webhook Overview**
The biometric server sends real-time attendance notifications to your HRIS system via secure webhooks. This provides instant updates without polling.

### **Webhook Configuration**
```bash
# Environment Variables for HRIS System
BIOMETRIC_WEBHOOK_ENABLED=true
BIOMETRIC_WEBHOOK_URL=http://your-hris-server:8000/api/biometric/webhook
BIOMETRIC_WEBHOOK_MODE=sync                 # 'sync' or 'async'
BIOMETRIC_WEBHOOK_SECRET=your-webhook-secret
BIOMETRIC_WEBHOOK_ALLOWED_IPS=your.biometric.server.ip # Biometric server IP (comma-separated)
BIOMETRIC_WEBHOOK_RATE_LIMIT=60             # Requests per minute
BIOMETRIC_WEBHOOK_TIMEOUT=30                # Processing timeout
BIOMETRIC_WEBHOOK_RETRY_ENABLED=true        # Auto-retry failures
BIOMETRIC_WEBHOOK_MAX_RETRIES=3             # Maximum retry attempts
BIOMETRIC_WEBHOOK_RETRY_DELAY=5             # Delay between retries
BIOMETRIC_WEBHOOK_ALERT_EMAILS=admin@company.com
```

### **Webhook Payload Format**
```json
{
  "event_type": "attendance_log",
  "timestamp": 1640995200,
  "timestamp_utc": "2025-10-22 00:17:22",
  "timestamp_local": "2025-10-22 08:17:22",
  "timezone": "Asia/Manila",
  "attendance_date": "2025-10-22",      // ✅ USE THIS for attendance date
  "attendance_time": "08:17:22",        // ✅ USE THIS for attendance time
  "source": "biometric_server",
  "device_id": "2401058352",
  "user_id": 5,
  "data": {
    "device_id": "2401058352",
    "user_id": 5,
    "io_mode": 1,
    "io_mode_str": "IN",
    "verify_mode": 1,
    "verify_mode_str": "Fingerprint",
    "timestamp": "20251022081722",
    "datetime_utc": "2025-10-22 00:17:22",
    "datetime_local": "2025-10-22 08:17:22",
    "timezone": "Asia/Manila",
    "device_type": "PRIMARY",
    "is_primary": true
  }
}
```

**⚠️ CRITICAL: Use `attendance_date` and `attendance_time` for HRIS records to avoid timezone conflicts!**

### **Webhook Headers**
```
Content-Type: application/json
X-Webhook-Signature: hmac-sha256-signature
X-Webhook-Timestamp: unix-timestamp
X-Webhook-Source: biometric_server
User-Agent: Biometric-Server-Webhook/1.0
```

### **Webhook Verification**
```php
<?php
// Verify webhook signature in your HRIS
function verifyWebhook($payload, $signature, $secret) {
    $expected = hash_hmac('sha256', json_encode($payload, JSON_UNESCAPED_SLASHES), $secret);
    return hash_equals($expected, $signature);
}
```

### **Webhook Monitoring Endpoints**

**GET /api/biometric/webhook/status**
- Check webhook health and statistics
- Returns configuration and delivery stats

**POST /api/biometric/webhook/test**
- Test webhook delivery with sample data
- Useful for troubleshooting connectivity

### **Webhook Event Types**
- `attendance_log`: Real-time attendance events
- Future: `device_status`, `user_sync`, `system_alerts`

### **Error Handling**
- **HTTP 200**: Success
- **HTTP 4xx/5xx**: Delivery failed, will retry
- **Rate Limiting**: Automatic backoff and retry
- **Network Failures**: Exponential backoff retry

### **Webhook Best Practices**
1. **Validate Signatures**: Always verify HMAC signatures
2. **Idempotent Processing**: Handle duplicate events safely
3. **Rate Limiting**: Implement your own rate limiting
4. **Monitoring**: Log all webhook events
5. **Timeouts**: Process within reasonable time limits
6. **Error Responses**: Return appropriate HTTP codes

### **Example HRIS Webhook Handler**
```php
<?php
// routes/api.php
Route::post('/biometric/webhook', 'BiometricController@handleWebhook');

<?php
// BiometricController.php
public function handleWebhook(Request $request)
{
    // Verify signature
    $payload = $request->all();
    $signature = $request->header('X-Webhook-Signature');
    $isValid = $this->verifyWebhookSignature($payload, $signature);

    if (!$isValid) {
        Log::warning('Invalid webhook signature');
        return response()->json(['error' => 'Invalid signature'], 401);
    }

    // Process attendance data
    if ($payload['event_type'] === 'attendance_log') {
        $attendanceData = $payload['data'];

        // Create attendance record
        Attendance::create([
            'user_id' => $attendanceData['user_id'],
            'device_id' => $attendanceData['device_id'],
            'direction' => $attendanceData['io_mode_str'],
            'timestamp' => $attendanceData['datetime'],
            'verification_method' => $attendanceData['verify_mode_str']
        ]);

        Log::info('Attendance webhook processed', $attendanceData);
    }

    return response()->json(['status' => 'processed'], 200);
}
```

---

## 🔗 HRIS-Compatible Endpoints

For seamless integration with HRIS systems, the following endpoints provide data in the exact format expected by HRIS applications:

### System Status (HRIS Format)
**GET /api/biometric/status**
- Returns system status in HRIS-expected format
- Includes connection status, device info, and sync statistics

```json
{
  "success": true,
  "connection": {
    "status": "connected",
    "api_url": "http://localhost:5050",
    "last_test": "2025-10-22T09:04:16.717482Z"
  },
  "devices": [
    {
      "id": "2401058350",
      "name": "Main Entrance",
      "status": "allowed",
      "last_seen": "2025-10-22 09:03:39",
      "connection_status": "connected"
    }
  ],
  "connections": {
    "total_active_employees": 60,
    "employees_with_biometric_id": 60,
    "connection_rate_percent": 100,
    "duplicate_biometric_ids_count": 0,
    "duplicate_biometric_ids": []
  },
  "sync": {
    "enabled": true,
    "attendance_interval": 15,
    "user_interval": 60,
    "auto_create_records": true,
    "statistics": {
      "last_sync_attempt": null,
      "last_successful_sync": null,
      "total_synced_today": 86,
      "sync_errors_today": 0
    }
  },
  "config": {
    "client_id": "hris_system",
    "token_expiry_hours": 24,
    "rate_limit_requests": 100,
    "rate_limit_window": 60
  }
}
```

### Attendance Logs (HRIS Format)
**GET /api/biometric/logs**
- Returns attendance logs in HRIS-compatible format
- Supports all the same filtering as `/api/hris/logs`

```json
{
  "success": true,
  "total": 86,
  "returned": 3,
  "primary_device": "2401058352",
  "logs": [
    {
      "id": 123,
      "user_id": 5,
      "device_id": "2401058352",
      "device_type": "PRIMARY",
      "is_primary": true,
      "timestamp": "20251022081722",
      "datetime_utc": "2025-10-22 00:17:22",
      "datetime_local": "2025-10-22 08:17:22",
      "timezone": "Asia/Manila",
      "direction": "in",
      "verification_method": "Fingerprint",
      "created_at": "2025-10-22 00:17:22"
    }
  ]
}
```

**Primary Device Filtering:**
```bash
# Get only logs from primary device (2401058352)
curl -H "Authorization: Bearer TOKEN" \
     "http://your-biometric-server:5050/api/biometric/logs?primary_only=true&limit=10"
```

---

## 🔄 Device Alignment & User Distribution

### **Device Configuration**
- **Primary Device:** `2401058352` - "Primary Terminal (Users 1-8)"
- **Secondary Device:** `2401058350` - "Secondary Terminal"
- **Expected Users:** IDs 1-8 should log on the primary device

### **System Status Response Includes Alignment Info**
```json
{
  "alignment": {
    "primary_device_id": "2401058352",
    "primary_device_name": "Primary Terminal (Users 1-8)",
    "expected_users": [1, 2, 3, 4, 5, 6, 7, 8],
    "primary_device_users": [1, 2, 3, 4, 5, 7, 8],
    "missing_users": [6],
    "extra_users": [],
    "alignment_status": "NEEDS_ATTENTION"
  }
}
```

### **Log Entries Include Device Type**
```json
{
  "device_id": "2401058352",
  "device_type": "PRIMARY",
  "is_primary": true,
  "user_id": 5
}
```

### **Processing Logic**
- ✅ **Primary Device (2401058352):** Accepts users 1-8 only
- ✅ **Secondary Device (2401058350):** Accepts any users
- ✅ **Validation:** Primary device rejects invalid user IDs
- ✅ **Smart Direction Logic:** Alternates IN/OUT per user automatically
- ✅ **Device Interchangeability:** Both devices handle both directions
- ✅ **Logging:** Clear distinction between PRIMARY/SECONDARY logs

### **Alternating Direction Logic**
The system automatically alternates between IN and OUT for each user:
- **First scan:** IN (check-in)
- **Second scan:** OUT (check-out)
- **Third scan:** IN (check-in)
- **Fourth scan:** OUT (check-out)
- **And so on...**

This works **regardless of which device** the user scans on, allowing both devices to be used interchangeably for the same company.

---

## 🕐 Timezone Handling

### **Server Architecture**
- **Server Storage:** All timestamps stored in UTC
- **Display Timezone:** Asia/Manila (UTC+8)
- **Device Input:** Device timestamps assumed to be in Philippine Manila time (UTC+8)

### **API Response Format**
All attendance log responses include timezone information:

```json
{
  "timestamp": "20251022081722",     // Original device timestamp
  "datetime_utc": "2025-10-22 00:17:22",    // UTC time (server storage)
  "datetime_local": "2025-10-22 08:17:22",  // Asia/Manila time (FOR ATTENDANCE RECORDS)
  "timezone": "Asia/Manila"
}
```

### **⚠️ CRITICAL: Timestamp Field Selection for HRIS**
- **✅ USE:** `datetime_local` for attendance date/time calculations
- **❌ AVOID:** `datetime_utc` for attendance records (causes date boundary issues)
- **Reason:** Prevents "already clocked in/out" errors when shifts cross timezone boundaries
- **Example:** Clocking from 23:00 Manila to 01:00 Manila should be same attendance date

### **Server Time Endpoint**
```
GET /api/server/time
```
Returns current server time in both UTC and local timezone for verification.

**Response:**
```json
{
  "server_timezone": "UTC",
  "display_timezone": "Asia/Manila",
  "current_time": {
    "utc": "2025-10-22 06:17:52",
    "local": "2025-10-22 14:17:52"
  },
  "timezone_offset": {
    "utc_to_local_hours": 8
  }
}
```

### **Webhook Timezone Information**
Webhook payloads include comprehensive timezone data:

```json
{
  "event_type": "attendance_log",
  "timestamp": 1640995200,
  "timestamp_utc": "2025-10-22 00:17:22",
  "timestamp_local": "2025-10-22 08:17:22",
  "timezone": "Asia/Manila",
  "data": { /* attendance data */ }
}
```

### **Best Practices**
1. **For Storage:** Use `datetime_utc` for database operations
2. **For Display:** Use `datetime_local` for user interfaces
3. **For APIs:** Include both timestamps in responses
4. **For Synchronization:** Use UTC for all server-to-server communication
5. **For Logging:** Always log in UTC with timezone information

### User Management (HRIS Format)
**GET /api/biometric/users**
- Returns enrolled users in HRIS-compatible format

**POST /api/biometric/sync**
- Receives user synchronization data from HRIS

### 🔄 Migration Path

If your HRIS is currently configured for different endpoints, you can:

1. **Update HRIS Configuration:**
   - Change API base URL to `http://localhost:5050`
   - Update endpoint paths to use `/api/biometric/` prefix
   - Keep existing authentication method

2. **Use Endpoint Mapping:**
   - `/api/biometric/status` → HRIS status endpoint
   - `/api/biometric/logs` → HRIS attendance endpoint
   - `/api/biometric/users` → HRIS user endpoint
   - `/api/biometric/sync` → HRIS sync endpoint

3. **Test Integration:**
   ```bash
   # Test new endpoints
   curl -H "Authorization: Bearer YOUR_TOKEN" \
        http://localhost:5050/api/biometric/status
   ``` for UI access

## Data Formats

### Attendance Log Entry
```json
{
  "device_id": "DEVICE001",
  "user_id": 123,
  "io_mode": 1,
  "io_mode_str": "IN",
  "verify_mode": 1,
  "verify_mode_str": "Fingerprint",
  "timestamp": "20240101120000",
  "datetime": "2024-01-01 12:00:00",
  "created_at": "2024-01-01 12:00:05"
}
```

### User Entry
```json
{
  "user_id": 123,
  "privilege": 0,
  "enabled": 1,
  "password_flag": 0,
  "card_flag": 0,
  "face_flag": 0,
  "fp_count": 2,
  "vein_count": 0,
  "enrolled_backups": ["template1", "template2"],
  "updated_at": "2024-01-01 10:00:00"
}
```

### Device Entry
```json
{
  "device_id": "DEVICE001",
  "device_name": "Main Entrance",
  "status": "allowed",
  "last_seen": "2024-01-01 12:00:00",
  "connection_status": "connected"
}
```

## Error Handling

All endpoints return standardized error responses:

```json
{
  "error": "ErrorType",
  "message": "Human readable error message"
}
```

Common HTTP status codes:
- `200`: Success
- `400`: Bad Request (invalid parameters)
- `401`: Unauthorized (invalid/missing token)
- `403`: Forbidden (client not allowed)
- `429`: Rate limit exceeded
- `500`: Internal Server Error

## Common Integration Scenarios

### Daily Attendance Sync
```python
import requests
from datetime import datetime, timedelta

class BiometricAPIClient:
    def __init__(self, base_url, client_id, client_secret):
        self.base_url = base_url.rstrip('/')
        self.client_id = client_id
        self.client_secret = client_secret
        self.token = None
        self.token_expiry = None

    def authenticate(self):
        """Get or refresh authentication token"""
        response = requests.post(f"{self.base_url}/api/auth/token", json={
            "client_id": self.client_id,
            "client_secret": self.client_secret
        })
        response.raise_for_status()
        data = response.json()
        self.token = data["token"]
        # Set expiry to 23 hours from now (1 hour buffer)
        self.token_expiry = datetime.now() + timedelta(hours=23)
        return self.token

    def _ensure_authenticated(self):
        """Ensure we have a valid token"""
        if not self.token or datetime.now() >= self.token_expiry:
            self.authenticate()

    def get_headers(self):
        self._ensure_authenticated()
        return {"Authorization": f"Bearer {self.token}"}

    def get_daily_attendance(self, date=None):
        """Get attendance logs for a specific date"""
        if date is None:
            date = datetime.now().date()

        params = {
            "start_date": date.isoformat(),
            "end_date": date.isoformat(),
            "limit": 10000  # Large limit for daily sync
        }

        response = requests.get(
            f"{self.base_url}/api/hris/logs",
            headers=self.get_headers(),
            params=params
        )
        response.raise_for_status()
        return response.json()

    def get_user_list(self):
        """Get all enrolled users"""
        response = requests.get(
            f"{self.base_url}/api/hris/users",
            headers=self.get_headers()
        )
        response.raise_for_status()
        return response.json()

    def sync_users(self, users_data):
        """Sync user data to biometric system"""
        response = requests.post(
            f"{self.base_url}/api/hris/sync",
            headers=self.get_headers(),
            json={"users": users_data}
        )
        response.raise_for_status()
        return response.json()

    def get_system_status(self):
        """Check system health"""
        response = requests.get(
            f"{self.base_url}/api/hris/status",
            headers=self.get_headers()
        )
        response.raise_for_status()
        return response.json()

# Usage Examples:

# Initialize client
api = BiometricAPIClient(
    base_url="http://localhost:5050",
    client_id="hris_system",
    client_secret="your_actual_secure_secret_here"
)

# Check system status
status = api.get_system_status()
print(f"System status: {status}")

# Get today's attendance
today_logs = api.get_daily_attendance()
print(f"Today's attendance records: {today_logs['total']}")

# Get all users
users = api.get_user_list()
print(f"Total enrolled users: {users['total']}")

# Sync user updates
user_updates = [
    {"user_id": 123, "name": "John Doe", "enabled": True},
    {"user_id": 124, "name": "Jane Smith", "enabled": False}
]
result = api.sync_users(user_updates)
print(f"Sync result: {result}")
```

## Real-Time Integration with WebSocket

For **true real-time attendance updates**, connect via WebSocket instead of polling:

### WebSocket Endpoint
**URL:** `ws://localhost:5050/ws`

**Messages you'll receive:**
```json
{
  "type": "new_log",
  "data": {
    "device_id": "2401058350",
    "user_id": 123,
    "io_mode": 1,
    "io_mode_str": "IN",
    "verify_mode": 1,
    "verify_mode_str": "Fingerprint",
    "timestamp": "20251021154752",
    "datetime": "2025-10-21 15:47:52"
  }
}
```

### WebSocket Client Example
```python
import websocket
import json
import threading
import time

class RealTimeAttendanceClient:
    def __init__(self, api_token):
        self.api_token = api_token
        self.ws = None
        self.connected = False

    def on_message(self, ws, message):
        """Handle incoming real-time messages"""
        try:
            data = json.loads(message)
            if data.get('type') == 'new_log':
                attendance_data = data['data']
                print(f"🔔 Real-time attendance: User {attendance_data['user_id']} - {attendance_data['io_mode_str']}")
                # Process the attendance record immediately
                self.process_attendance(attendance_data)
        except Exception as e:
            print(f"Error processing message: {e}")

    def on_open(self, ws):
        """Called when WebSocket connection opens"""
        print("✅ Connected to real-time attendance feed")
        self.connected = True

    def on_close(self, ws, close_status_code, close_msg):
        """Called when WebSocket connection closes"""
        print("❌ Disconnected from real-time attendance feed")
        self.connected = False

    def on_error(self, ws, error):
        """Called on WebSocket errors"""
        print(f"🚨 WebSocket error: {error}")

    def connect(self):
        """Connect to WebSocket"""
        websocket.enableTrace(False)  # Set to True for debug info

        self.ws = websocket.WebSocketApp(
            f"ws://localhost:5050/ws",
            header=[f"Authorization: Bearer {self.api_token}"],
            on_message=self.on_message,
            on_open=self.on_open,
            on_close=self.on_close,
            on_error=self.on_error
        )

        # Start WebSocket in a separate thread
        wst = threading.Thread(target=self.ws.run_forever)
        wst.daemon = True
        wst.start()

    def disconnect(self):
        """Disconnect WebSocket"""
        if self.ws:
            self.ws.close()

    def process_attendance(self, attendance_data):
        """Process real-time attendance data"""
        # Your HRIS processing logic here
        user_id = attendance_data['user_id']
        action = attendance_data['io_mode_str']  # "IN" or "OUT"
        timestamp = attendance_data['datetime']
        device_id = attendance_data['device_id']

        print(f"Processing: User {user_id} {action} at {timestamp} (Device: {device_id})")

        # Send to your HRIS database/API
        # save_to_hris_database(user_id, action, timestamp, device_id)

# Usage:
if __name__ == "__main__":
    # First get your API token
    api_token = get_api_token()  # Your authentication logic

    # Create real-time client
    client = RealTimeAttendanceClient(api_token)

    # Connect to real-time feed
    client.connect()

    # Keep the program running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        client.disconnect()
        print("Shutting down...")
```

### Polling vs Real-Time Comparison

| Method | Polling (Current) | Real-Time (WebSocket) |
|--------|-------------------|------------------------|
| **Updates** | Every 15 minutes | Instant (<1 second) |
| **Server Load** | Higher (frequent requests) | Lower (push only) |
| **Complexity** | Simple | More complex |
| **Reliability** | Good (but delayed) | Excellent (immediate) |
| **Network Usage** | Higher | Lower |

### Hybrid Approach (Recommended)

Use both methods for maximum reliability:

```python
class HybridAttendanceClient:
    def __init__(self, api_token):
        self.api_token = api_token
        self.websocket_client = RealTimeAttendanceClient(api_token)
        self.last_polling_sync = datetime.now()

    def start(self):
        """Start both real-time and polling (backup)"""
        # Start real-time WebSocket connection
        self.websocket_client.connect()

        # Start polling as backup (every 15 minutes)
        self.start_polling_backup()

    def start_polling_backup(self):
        """Fallback polling in case WebSocket fails"""
        def polling_loop():
            while True:
                try:
                    # Only poll if WebSocket isn't connected
                    if not self.websocket_client.connected:
                        self.poll_for_new_attendance()
                except Exception as e:
                    print(f"Polling error: {e}")

                time.sleep(900)  # 15 minutes

        polling_thread = threading.Thread(target=polling_loop)
        polling_thread.daemon = True
        polling_thread.start()

    def poll_for_new_attendance(self):
        """Poll for attendance data as backup"""
        # Your existing polling logic here
        pass
```

## Best Practices

### 🔄 Token Management
- Store tokens securely (environment variables, secure key stores)
- Implement automatic token refresh before expiry
- Handle token expiration gracefully
- Use different client_ids for different integration points

### 📊 Data Synchronization
- Implement incremental syncs using date filtering
- Use pagination for large datasets (limit + offset)
- Handle duplicate records appropriately
- Schedule regular syncs during off-peak hours

### 🛡️ Error Handling
- Implement exponential backoff for retries
- Log all API errors for debugging
- Handle rate limiting (429 errors) with delays
- Validate data before sending to biometric system

### 📈 Performance Optimization
- Cache frequently accessed data (user lists, device status)
- Use specific filters to reduce data transfer
- Implement batch processing for large updates
- Monitor API response times

### 🔒 Security Best Practices
- **Change Default Secret**: Never use default secrets in production
- **Use HTTPS**: Always encrypt data in transit
- **Client Whitelisting**: Restrict access to known systems
- **Token Rotation**: Regularly rotate API tokens
- **Network Security**: Use firewalls and VPNs for access control
- **Audit Logging**: Monitor and log all API access

## Troubleshooting

### Common Issues

**❌ "Not receiving real-time logs"**
- **You're using polling instead of WebSocket!** Connect to `ws://localhost:5050/ws` for real-time updates
- Devices ARE sending data (check `/api/hris/status` for total_logs)
- Use the WebSocket client example above for instant notifications
- Consider hybrid approach: WebSocket + polling backup

**❌ "Invalid token" errors**
- Check token hasn't expired (24 hour limit)
- Verify client_secret matches server configuration (set via HRIS_API_SECRET_KEY environment variable)
- Ensure token format is correct

**❌ "Already clocked in/out for this date" errors**
- **CRITICAL**: Use `timestamp_local` field for attendance date calculations
- **DO NOT** use `timestamp_utc` for attendance records - it can cause date boundary issues
- The system provides both UTC and Manila timestamps - always use Manila time for attendance dates
- Example: If someone clocks in at 23:00 Manila time and out at 01:00 Manila time, both events should be recorded on the same Manila date

**❌ "Rate limit exceeded" (429)**
- Reduce request frequency (current: 100 requests/minute)
- Implement client-side rate limiting
- Use WebSocket for real-time instead of frequent polling
- Use pagination for large data requests

**❌ "Client not authorized" (403)**
- Check HRIS_ALLOWED_CLIENTS environment variable
- Verify client_id is in whitelist (if configured)
- Default allows all clients

**❌ Connection timeouts**
- Check server is running on port 5050 (API) and 7005 (devices)
- Verify network connectivity
- Check firewall settings blocking ports

**❌ Empty responses from `/api/hris/logs`**
- Verify date formats (YYYY-MM-DD)
- Check if biometric devices are connected (see `/api/hris/devices`)
- Confirm there is attendance data for the requested period
- Devices might be sending data but you need WebSocket for real-time alerts

### Debug Commands
```bash
# Check server status
curl http://localhost:5050/api/hris/status

# Test authentication
curl -X POST http://localhost:5050/api/auth/token \
  -d '{"client_id":"test","client_secret":"your_secret"}'

# Check API documentation
curl http://localhost:5050/api/docs
```

## Production Deployment

### Environment Setup
```bash
# Required production settings
export HRIS_API_SECRET_KEY="your-production-secret-here"
export HRIS_ALLOWED_CLIENTS="hris-prod,hris-backup"

# Optional performance tuning
export HRIS_RATE_LIMIT_REQUESTS="500"
export HRIS_RATE_LIMIT_WINDOW="60"
```

### System Requirements
- Python 3.12+
- SQLite database
- Network access to biometric devices
- HTTPS certificate (recommended)

### Monitoring & Maintenance
- Monitor server logs for API usage
- Set up alerts for authentication failures
- Regular backup of biometric_data.db
- Update API secrets periodically

### Load Balancing (Future)
- Multiple biometric servers can share the same database
- Use round-robin DNS or load balancer
- Implement session affinity if needed

## Support & Resources

### 📚 Documentation
- **Interactive API**: `http://localhost:5050/swagger`
- **JSON Documentation**: `http://localhost:5050/api/docs`
- **OpenAPI Spec**: `swagger.yaml`

### 🐛 Getting Help
1. Check server logs: `journalctl -u biometric-server`
2. Test with Swagger UI first
3. Verify configuration in `hris_config.py`
4. Check network connectivity to biometric devices

### 📞 Contact
For technical support with the biometric server API integration, please provide:
- Error messages and logs
- API endpoint and parameters used
- Server configuration details
- Network setup information
- Whether you're using polling or WebSocket for real-time updates

### 🚨 For Real-Time Issues
If you're not receiving real-time attendance logs:

1. **Test WebSocket connection:**
   ```bash
   # Install wscat or use a WebSocket client
   wscat -c ws://localhost:5050/ws -H "Authorization: Bearer YOUR_TOKEN"
   ```

2. **Verify device connectivity:**
   ```bash
   curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:5050/api/hris/devices
   ```

3. **Check attendance data:**
   ```bash
   curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:5050/api/hris/status
   ```

---

## 🎯 Quick Start Checklist

- ✅ **Server Running:** `./manage_biometric_server.sh start`
- ✅ **Environment Config:** Set `HRIS_API_SECRET_KEY` environment variable (see .env.example)
- ✅ **Authentication Working:** Test `/api/auth/token`
- ✅ **API Access Working:** Test `/api/hris/status`
- ✅ **Real-Time Setup:** Implement WebSocket client (see examples above)
- ✅ **Integration Complete:** Start receiving instant attendance notifications!

**🎯 Ready to integrate?** Start with the Swagger UI at `http://localhost:5050/swagger` and implement the WebSocket client for real-time updates!
