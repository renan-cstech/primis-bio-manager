#!/bin/bash

echo "🔍 VERIFYING HRIS CONNECTION"
echo "═══════════════════════════════════════════════════════════"

# Check if HRIS is running on port 8000
echo ""
echo "1️⃣ Checking if HRIS is listening on port 8000..."
if nc -z localhost 8000 2>/dev/null; then
    echo "   ✅ HRIS is running on port 8000"
else
    echo "   ❌ HRIS is NOT running on port 8000"
    echo "   → Please start HRIS with: php artisan serve --host=0.0.0.0 --port=8000"
    exit 1
fi

# Check if webhook endpoint exists
echo ""
echo "2️⃣ Testing HRIS webhook endpoint..."
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/api/webhook-receiver/biometric 2>/dev/null)

if [[ "$RESPONSE" == "405" ]] || [[ "$RESPONSE" == "200" ]] || [[ "$RESPONSE" == "422" ]]; then
    echo "   ✅ HRIS webhook endpoint exists (HTTP $RESPONSE)"
elif [[ "$RESPONSE" == "404" ]]; then
    echo "   ❌ HRIS webhook endpoint NOT found (HTTP 404)"
    echo "   → Ensure route exists in routes/api.php"
    exit 1
else
    echo "   ⚠️ HRIS response: HTTP $RESPONSE"
fi

# Check biometric server webhook configuration
echo ""
echo "3️⃣ Verifying biometric server configuration..."
WEBHOOK_URL=$(grep "BIOMETRIC_WEBHOOK_URL" /home/crsadmin/primis/primis-bio-manager/.env | cut -d'=' -f2)
echo "   Webhook URL: $WEBHOOK_URL"

if [[ "$WEBHOOK_URL" == "http://localhost:8000/api/webhook-receiver/biometric" ]]; then
    echo "   ✅ Correctly configured to send to HRIS"
else
    echo "   ❌ Incorrect webhook URL"
    exit 1
fi

# Check pending webhooks
echo ""
echo "4️⃣ Checking webhook queue..."
python3 << 'PYEOF'
import sqlite3

conn = sqlite3.connect('/home/crsadmin/primis/primis-bio-manager/biometric.db')
cursor = conn.cursor()

cursor.execute('SELECT COUNT(*) FROM webhook_queue WHERE status = "failed"')
failed = cursor.fetchone()[0]

if failed > 0:
    print(f"   ⚠️ {failed} failed webhooks waiting to retry")
    print(f"   → These will automatically retry when HRIS is available")
else:
    print(f"   ✅ No failed webhooks")

conn.close()
PYEOF

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "✅ VERIFICATION COMPLETE"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "🎯 STATUS:"
echo "   • Biometric server: Configured to send to port 8000"
echo "   • HRIS server: Running on port 8000"
echo "   • Webhook endpoint: Ready"
echo ""
echo "🚀 NEXT STEPS:"
echo "   1. Trigger a test attendance event"
echo "   2. Check HRIS logs for incoming webhook"
echo "   3. Verify data saved to HRIS database"
echo ""
echo "═══════════════════════════════════════════════════════════"
