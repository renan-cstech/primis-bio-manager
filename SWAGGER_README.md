# Swagger UI for HRIS API Testing

## Overview

The Biometric Server now includes an interactive Swagger UI for easy testing and exploration of the HRIS API endpoints.

## Access the Swagger UI

**URL:** `http://localhost:5050/swagger`

## Features

### 🔐 **Automatic Authentication**
- The Swagger UI automatically stores your API token after successful authentication
- No need to manually copy/paste tokens for subsequent requests
- Tokens are stored in your browser's localStorage for the session

### 🧪 **Interactive Testing**
- Click "Try it out" on any endpoint to test it directly
- Fill in parameters and see real responses
- View request/response headers and bodies

### 📚 **Complete Documentation**
- All endpoints documented with parameters, responses, and examples
- Request/response schemas clearly defined
- Error codes and descriptions included

## How to Use

### Step 1: Start the Server
```bash
cd /home/crsadmin/primis/primis-bio-manager
./manage_biometric_server.sh start
```

### Step 2: Open Swagger UI
Navigate to: `http://localhost:5050/swagger`

### Step 3: Authenticate
1. Expand the **Authentication** section
2. Click on `POST /api/auth/token`
3. Click "Try it out"
4. Fill in your credentials:
   ```json
   {
     "client_id": "your_hris_system",
     "client_secret": "your_secure_secret_here"
   }
   ```
5. Click "Execute"
6. The token will be automatically stored for all subsequent requests

### Step 4: Test Endpoints
- Expand any section (System, Attendance, Users, etc.)
- Click "Try it out" on any endpoint
- Fill in any required parameters
- Click "Execute" to see the response

## Available Endpoints

### Authentication
- `POST /api/auth/token` - Generate API token

### System
- `GET /api/hris/status` - Get system status and statistics

### Attendance
- `GET /api/hris/logs` - Get attendance logs with filtering
- `GET /api/hris/logs/summary` - Get attendance summary for reporting

### Users
- `GET /api/hris/users` - Get enrolled users

### Devices
- `GET /api/hris/devices` - Get device status

### Synchronization
- `POST /api/hris/sync` - Sync user data from HRIS

## Tips for Testing

### Rate Limiting
- The API has rate limiting (100 requests per minute by default)
- If you hit the limit, wait a minute or the UI will show a 429 error

### Date Filtering
- Use `YYYY-MM-DD` format for date parameters
- Example: `2024-01-01` for January 1st, 2024

### Pagination
- Use `limit` and `offset` for large result sets
- Example: `limit=100&offset=0` for first 100 records

### Error Handling
- Check the response codes and error messages
- 401 = Authentication required
- 403 = Client not authorized
- 429 = Rate limit exceeded
- 400 = Bad request parameters

## Configuration

The Swagger UI respects the same configuration as the API:

- **Rate Limiting**: Configured in `hris_config.py`
- **Client Whitelisting**: Optional client restrictions
- **Token Expiry**: 24 hours by default

## Standalone Usage

You can also open the `swagger-ui.html` file directly in a browser, but you'll need to:
1. Have the server running for API calls to work
2. Manually copy the token from the authentication response
3. Add `Authorization: Bearer <token>` to each request

## Browser Compatibility

The Swagger UI works in all modern browsers:
- Chrome 70+
- Firefox 65+
- Safari 12+
- Edge 79+

## Troubleshooting

### "Failed to fetch" errors
- Make sure the server is running on port 5050
- Check that CORS is not blocking requests

### Authentication errors
- Verify your `client_secret` matches the one in `hris_config.py`
- Check that your `client_id` is allowed (if whitelisting is enabled)

### 429 Rate Limited
- You've exceeded the rate limit
- Wait a minute before trying again
- The UI will show when the limit resets

## Security Notes

- The Swagger UI is for testing only
- Never expose it publicly in production
- Use HTTPS in production environments
- Keep your API secrets secure
- Monitor API usage for unauthorized access
