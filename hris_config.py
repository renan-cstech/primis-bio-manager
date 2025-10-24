#!/usr/bin/env python3
"""
HRIS API Configuration
Secure configuration for HRIS integration
"""

import os
from typing import Optional

# HRIS API Configuration
class HRISConfig:
    """Configuration class for HRIS API settings"""

    # API Authentication - CRITICAL: Must be set via HRIS_API_SECRET_KEY environment variable
    API_SECRET_KEY = os.getenv('HRIS_API_SECRET_KEY')
    if not API_SECRET_KEY:
        raise ValueError("HRIS_API_SECRET_KEY environment variable must be set for security")

    # Rate Limiting
    API_RATE_LIMIT_MAX_REQUESTS = int(os.getenv('HRIS_RATE_LIMIT_REQUESTS', '100'))
    API_RATE_LIMIT_WINDOW = int(os.getenv('HRIS_RATE_LIMIT_WINDOW', '60'))  # seconds

    # Token Expiry
    API_TOKEN_EXPIRY_HOURS = int(os.getenv('HRIS_TOKEN_EXPIRY_HOURS', '24'))

    # Optional: Client whitelist (leave empty to allow any client)
    ALLOWED_CLIENTS = os.getenv('HRIS_ALLOWED_CLIENTS', '').split(',') if os.getenv('HRIS_ALLOWED_CLIENTS') else []

    # Primary device for HRIS integration (all logs should come from this device)
    PRIMARY_DEVICE_ID = os.getenv('PRIMARY_DEVICE_ID', '2401058352')

    # Webhook Configuration for Real-Time HRIS Integration
    WEBHOOK_ENABLED = os.getenv('BIOMETRIC_WEBHOOK_ENABLED', 'true').lower() == 'true'
    WEBHOOK_URL = os.getenv('BIOMETRIC_WEBHOOK_URL', 'http://your-hris-server.com/api/biometric/webhook')
    WEBHOOK_MODE = os.getenv('BIOMETRIC_WEBHOOK_MODE', 'sync')  # 'sync' or 'async'
    WEBHOOK_SECRET = os.getenv('BIOMETRIC_WEBHOOK_SECRET')
    if WEBHOOK_ENABLED and not WEBHOOK_SECRET:
        raise ValueError("BIOMETRIC_WEBHOOK_SECRET environment variable must be set when webhooks are enabled")
    WEBHOOK_ALLOWED_IPS = os.getenv('BIOMETRIC_WEBHOOK_ALLOWED_IPS', '').split(',') if os.getenv('BIOMETRIC_WEBHOOK_ALLOWED_IPS') else []
    WEBHOOK_RATE_LIMIT = int(os.getenv('BIOMETRIC_WEBHOOK_RATE_LIMIT', '60'))
    WEBHOOK_TIMEOUT = int(os.getenv('BIOMETRIC_WEBHOOK_TIMEOUT', '30'))
    WEBHOOK_RETRY_ENABLED = os.getenv('BIOMETRIC_WEBHOOK_RETRY_ENABLED', 'true').lower() == 'true'
    WEBHOOK_MAX_RETRIES = int(os.getenv('BIOMETRIC_WEBHOOK_MAX_RETRIES', '3'))
    WEBHOOK_RETRY_DELAY = int(os.getenv('BIOMETRIC_WEBHOOK_RETRY_DELAY', '5'))
    WEBHOOK_ALERT_EMAILS = os.getenv('BIOMETRIC_WEBHOOK_ALERT_EMAILS', '').split(',') if os.getenv('BIOMETRIC_WEBHOOK_ALERT_EMAILS') else []

    @classmethod
    def is_client_allowed(cls, client_id: str) -> bool:
        """Check if client is in whitelist (if whitelist is configured)"""
        if not cls.ALLOWED_CLIENTS:
            return True
        return client_id in cls.ALLOWED_CLIENTS

    @classmethod
    def validate_secret(cls, client_secret: str) -> bool:
        """Validate client secret"""
        return client_secret == cls.API_SECRET_KEY

# Export configuration
hris_config = HRISConfig()
