#!/bin/bash
# Production Status Check Script
# Run this to verify biometric server is operating correctly

echo "🔍 BIOMETRIC SERVER PRODUCTION STATUS CHECK"
echo "=========================================="

# Check if server is running
echo "1. Server Status:"
if pgrep -f "biometric_web_server.py" > /dev/null; then
    echo "   ✅ Server is running"
else
    echo "   ❌ Server is not running"
    echo "   Run: ./manage_biometric_server.sh start"
    exit 1
fi

# Check network ports
echo "2. Network Ports:"
if netstat -tuln 2>/dev/null | grep -q ":5050"; then
    echo "   ✅ Port 5050 (API) is listening"
else
    echo "   ❌ Port 5050 not accessible"
fi

if netstat -tuln 2>/dev/null | grep -q ":7005"; then
    echo "   ✅ Port 7005 (Devices) is listening"
else
    echo "   ❌ Port 7005 not accessible"
fi

# Check database
echo "3. Database Status:"
if [ -f "biometric_data.db" ]; then
    DB_SIZE=$(stat -c%s biometric_data.db 2>/dev/null || stat -f%z biometric_data.db 2>/dev/null || echo "0")
    DB_SIZE_MB=$((DB_SIZE / 1024 / 1024))
    echo "   ✅ Database file exists (${DB_SIZE_MB}MB)"

    # Quick data check
    LOGS=$(python3 -c "
import sys
sys.path.append('.')
import database as db
print(db.get_logs_count())
" 2>/dev/null || echo "error")

    if [ "$LOGS" != "error" ]; then
        echo "   ✅ Database accessible (${LOGS} logs)"
    else
        echo "   ❌ Database access error"
    fi
else
    echo "   ❌ Database file missing"
fi

# Check API responsiveness
echo "4. API Health Check:"
API_RESPONSE=$(curl -s --max-time 5 http://localhost:5050/api/biometric/status 2>/dev/null || echo "timeout")
if echo "$API_RESPONSE" | grep -q "Unauthorized"; then
    echo "   ✅ API responding (authentication required)"
elif echo "$API_RESPONSE" | grep -q "timeout"; then
    echo "   ❌ API not responding (timeout)"
else
    echo "   ❌ API unexpected response"
fi

# Check devices
echo "5. Device Status:"
TOKEN=$(curl -s -X POST http://localhost:5050/api/auth/token \
    -H "Content-Type: application/json" \
    -d '{"client_id":"hris_system","client_secret":"YOUR_API_SECRET_KEY"}' 2>/dev/null | \
    python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('token', 'error'))" 2>/dev/null || echo "error")

if [ "$TOKEN" != "error" ] && [ "$TOKEN" != "" ]; then
    DEVICE_COUNT=$(curl -s -H "Authorization: Bearer $TOKEN" http://localhost:5050/api/biometric/status 2>/dev/null | \
        python3 -c "import sys, json; data=json.load(sys.stdin); print(len(data.get('devices', [])))" 2>/dev/null || echo "error")

    if [ "$DEVICE_COUNT" != "error" ]; then
        echo "   ✅ ${DEVICE_COUNT} devices registered"
    else
        echo "   ❌ Device check failed"
    fi
else
    echo "   ❌ Authentication failed"
fi

echo ""
echo "📊 SUMMARY:"
echo "Server: your-server-hostname ($WEB_HOST)"
echo "API URL: http://$WEB_HOST:$WEB_PORT"
echo "Documentation: http://$WEB_HOST:$WEB_PORT/swagger"
echo ""
echo "🎯 If all checks pass: System is PRODUCTION READY"
echo "🚨 If any checks fail: Check PRODUCTION_README.md for troubleshooting"
