# Biometric Management System

A secure biometric device management system with HRIS integration.

## 🚀 Quick Start

### 1. Environment Setup

```bash
# Copy the example environment file
cp .env.example .env

# Edit the .env file with your secure values (REQUIRED)
nano .env
```

**⚠️ CRITICAL**: The following environment variables MUST be set for the system to start:

- `HRIS_API_SECRET_KEY` - API authentication secret
- `BIOMETRIC_WEBHOOK_SECRET` - Webhook signature secret (if webhooks enabled)

### 2. Install Dependencies

```bash
# Install Python dependencies
pip install -r requirements.txt
# or using uv
uv pip install -r requirements.txt
```

### 3. Initialize Database

```bash
python3 biometric_web_server.py
# The database will be initialized automatically on first run
```

### 4. Start the Server

```bash
# Development mode
uv run biometric_web_server.py

# Production mode (using systemd)
sudo systemctl start biometric-server
```

## 🔐 Security Configuration

**CRITICAL**: Before deploying to production:

1. **Change all default secrets** in your `.env` file
2. **Generate strong secret keys**:
   ```bash
   python3 -c "import secrets; print(secrets.token_hex(32))"
   ```
3. **Configure your HRIS webhook URL** and secret
4. **Set appropriate IP restrictions** for webhook delivery

### Required Environment Variables

- `HRIS_API_SECRET_KEY`: API authentication secret (generate a new one)
- `BIOMETRIC_WEBHOOK_SECRET`: Webhook signature secret (must match HRIS)
- `BIOMETRIC_WEBHOOK_URL`: Your HRIS webhook endpoint
- `PRIMARY_DEVICE_ID`: Your primary biometric device ID

## 📚 API Documentation

- **Swagger UI**: http://your-server-host:5050/swagger (configure WEB_HOST in .env)
- **API Docs**: http://your-server-host:5050/api/docs (configure WEB_HOST in .env)

## 🔧 Management

```bash
# Check server status
./manage_biometric_server.sh status

# Restart server
./manage_biometric_server.sh restart

# View logs
tail -f server.log
```

## ⚠️ Security Notes

- Never commit `.env` files to version control
- Use strong, unique secrets for all authentication
- Restrict webhook delivery to trusted IP addresses
- Regularly rotate API keys and secrets
