#!/usr/bin/env python3
"""
Webhook Manager for Real-Time HRIS Integration
Handles sending attendance data to HRIS via webhooks with retry logic and monitoring
"""

import json
import hmac
import hashlib
import time
import threading
import queue
import sqlite3
import os
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
import requests
from concurrent.futures import ThreadPoolExecutor

import hris_config
import database as db

class WebhookManager:
    """Manages webhook delivery to HRIS system"""

    def __init__(self):
        self.config = hris_config.hris_config
        self.webhook_queue = queue.Queue()
        self.rate_limiter = {}
        self.stats = {
            'sent': 0,
            'failed': 0,
            'retried': 0,
            'rate_limited': 0,
            'recovered': 0,
            'persistent_queue_size': 0
        }

        # Connection pooling for better performance
        self.session = requests.Session()
        self.session.timeout = self.config.WEBHOOK_TIMEOUT

        # Initialize persistent webhook storage
        self._init_persistent_storage()

        # Recover any unsent webhooks from previous runs
        self._recover_unsent_webhooks()

        # Start webhook processor thread
        if self.config.WEBHOOK_MODE == 'async':
            self.executor = ThreadPoolExecutor(max_workers=3, thread_name_prefix='webhook')
            self.processor_thread = threading.Thread(target=self._process_webhook_queue, daemon=True)
            self.processor_thread.start()

        # Start persistent queue processor
        self.persistent_processor = threading.Thread(target=self._process_persistent_queue, daemon=True)
        self.persistent_processor.start()

        # Start automatic retry processor for failed webhooks
        self.retry_processor = threading.Thread(target=self._auto_retry_processor, daemon=True)
        self.retry_processor.start()

    def _init_persistent_storage(self):
        """Initialize persistent webhook storage table"""
        try:
            with db.get_db() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS webhook_queue (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        webhook_data TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        retry_count INTEGER DEFAULT 0,
                        last_attempt TIMESTAMP,
                        next_attempt TIMESTAMP,
                        error_message TEXT,
                        status TEXT DEFAULT 'pending'
                    )
                ''')
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_webhook_status
                    ON webhook_queue(status, next_attempt)
                ''')
        except Exception as e:
            print(f"❌ Failed to initialize webhook storage: {e}")

    def _recover_unsent_webhooks(self):
        """Recover unsent webhooks from persistent storage"""
        try:
            with db.get_db() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, webhook_data, retry_count
                    FROM webhook_queue
                    WHERE status IN ('pending', 'failed')
                    ORDER BY created_at ASC
                ''')

                recovered_count = 0
                for row in cursor.fetchall():
                    try:
                        webhook_data = json.loads(row['webhook_data'])
                        webhook_data['persistent_id'] = row['id']
                        webhook_data['retry_count'] = row['retry_count']

                        # Re-queue for processing
                        self.webhook_queue.put(webhook_data)
                        recovered_count += 1
                    except Exception as e:
                        print(f"❌ Failed to recover webhook {row['id']}: {e}")

                if recovered_count > 0:
                    self.stats['recovered'] = recovered_count
                    print(f"✅ Recovered {recovered_count} unsent webhooks from persistent storage")

        except Exception as e:
            print(f"❌ Failed to recover webhooks: {e}")

    def _store_webhook_persistently(self, webhook_data: Dict[str, Any]) -> int:
        """Store webhook data persistently for retry capability"""
        try:
            with db.get_db() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO webhook_queue (webhook_data, status)
                    VALUES (?, 'pending')
                ''', (json.dumps(webhook_data),))
                return cursor.lastrowid
        except Exception as e:
            print(f"❌ Failed to store webhook persistently: {e}")
            return None

    def _update_webhook_status(self, persistent_id: int, status: str, error_message: str = None, retry_count: int = 0):
        """Update webhook status in persistent storage"""
        try:
            with db.get_db() as conn:
                cursor = conn.cursor()

                if status == 'completed':
                    cursor.execute('''
                        DELETE FROM webhook_queue WHERE id = ?
                    ''', (persistent_id,))
                else:
                    # Calculate next retry time with exponential backoff
                    next_attempt = None
                    if status == 'failed' and retry_count < self.config.WEBHOOK_MAX_RETRIES:
                        delay_seconds = self.config.WEBHOOK_RETRY_DELAY * (2 ** retry_count)
                        next_attempt = datetime.now() + timedelta(seconds=delay_seconds)

                    cursor.execute('''
                        UPDATE webhook_queue
                        SET status = ?, retry_count = ?, last_attempt = CURRENT_TIMESTAMP,
                            next_attempt = ?, error_message = ?
                        WHERE id = ?
                    ''', (status, retry_count, next_attempt, error_message, persistent_id))

        except Exception as e:
            print(f"❌ Failed to update webhook status: {e}")

    def _process_persistent_queue(self):
        """Process persistent webhook queue with retry logic"""
        while True:
            try:
                # Check for webhooks ready for retry
                now = datetime.now()
                with db.get_db() as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        SELECT id, webhook_data, retry_count
                        FROM webhook_queue
                        WHERE status = 'failed'
                        AND next_attempt <= ?
                        ORDER BY next_attempt ASC
                        LIMIT 5
                    ''', (now,))

                    for row in cursor.fetchall():
                        try:
                            webhook_data = json.loads(row['webhook_data'])
                            webhook_data['persistent_id'] = row['id']
                            webhook_data['retry_count'] = row['retry_count'] + 1

                            # Re-queue for processing
                            self.webhook_queue.put(webhook_data)
                        except Exception as e:
                            print(f"❌ Failed to re-queue webhook {row['id']}: {e}")

            except Exception as e:
                print(f"❌ Persistent queue processor error: {e}")

            time.sleep(30)  # Check every 30 seconds

    def send_attendance_webhook(self, attendance_data: Dict[str, Any]) -> bool:
        """
        Send attendance data to HRIS via webhook with optimized performance
        Returns True if successful (or queued for async)
        """
        if not self.config.WEBHOOK_ENABLED:
            return True

        # Check rate limiting with minimal overhead
        current_time = int(time.time())
        if not self._check_rate_limit_optimized(current_time):
            self.stats['rate_limited'] += 1
            return False  # Skip silently for performance

        webhook_payload = self._prepare_webhook_payload(attendance_data)

        # Store persistently for retry capability (both sync and async)
        persistent_id = self._store_webhook_persistently(webhook_payload)
        if persistent_id:
            webhook_payload['persistent_id'] = persistent_id

        if self.config.WEBHOOK_MODE == 'sync':
            success = self._send_webhook_sync_optimized(webhook_payload)
            if success:
                self.stats['sent'] += 1
                # Remove from persistent storage on success
                if persistent_id:
                    self._update_webhook_status(persistent_id, 'completed')
            else:
                self.stats['failed'] += 1
                # Mark as failed for retry processing
                if persistent_id:
                    self._update_webhook_status(persistent_id, 'failed', 'Initial sync delivery failed', 0)
            return success
        else:  # async
            try:
                self.webhook_queue.put_nowait(webhook_payload)  # Non-blocking
                # Async stats are handled by the queue processor
                return True
            except queue.Full:
                self.stats['failed'] += 1
                # Mark as failed if queue is full
                if persistent_id:
                    self._update_webhook_status(persistent_id, 'failed', 'Queue full', 0)
                return False

    def _prepare_webhook_payload(self, attendance_data: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare webhook payload with signature"""
        timestamp = int(time.time())

        payload = {
            'event_type': 'attendance_log',
            'timestamp': timestamp,
            'timestamp_utc': attendance_data.get('datetime_utc', ''),
            'timestamp_local': attendance_data.get('datetime_local', ''),
            'timezone': attendance_data.get('timezone', 'UTC'),
            # CRITICAL: HRIS should use timestamp_local for attendance date records
            # to avoid timezone boundary issues (e.g., clocking across midnight)
            'attendance_date': attendance_data.get('datetime_local', '').split(' ')[0],  # YYYY-MM-DD format
            'attendance_time': attendance_data.get('datetime_local', '').split(' ')[1] if ' ' in attendance_data.get('datetime_local', '') else '',  # HH:MM:SS format
            'data': attendance_data,
            'source': 'biometric_server',
            'device_id': attendance_data.get('device_id'),
            'user_id': attendance_data.get('user_id')
        }

        # Create HMAC signature
        payload_json = json.dumps(payload, sort_keys=True)
        signature = hmac.new(
            self.config.WEBHOOK_SECRET.encode(),
            payload_json.encode(),
            hashlib.sha256
        ).hexdigest()

        return {
            'payload': payload,
            'signature': signature,
            'timestamp': timestamp
        }

    def _send_webhook_sync(self, webhook_data: Dict[str, Any]) -> bool:
        """Send webhook synchronously with retry logic"""
        max_retries = self.config.WEBHOOK_MAX_RETRIES if self.config.WEBHOOK_RETRY_ENABLED else 1

        for attempt in range(max_retries):
            try:
                success = self._send_single_webhook(webhook_data)
                if success:
                    self.stats['sent'] += 1
                    return True
                elif attempt < max_retries - 1:
                    self.stats['retried'] += 1
                    time.sleep(self.config.WEBHOOK_RETRY_DELAY)

            except Exception as e:
                print(f"🚨 Webhook attempt {attempt + 1} failed: {e}")
                if attempt < max_retries - 1:
                    time.sleep(self.config.WEBHOOK_RETRY_DELAY)

        # All retries failed
        self.stats['failed'] += 1
        self._handle_webhook_failure(webhook_data)
        return False

    def _send_single_webhook(self, webhook_data: Dict[str, Any]) -> bool:
        """Send a single webhook request"""
        headers = {
            'Content-Type': 'application/json',
            'X-Webhook-Signature': webhook_data['signature'],
            'X-Webhook-Timestamp': str(webhook_data['timestamp']),
            'X-Webhook-Source': 'biometric_server',
            'User-Agent': 'Biometric-Server-Webhook/1.0'
        }

        try:
            response = requests.post(
                self.config.WEBHOOK_URL,
                json=webhook_data['payload'],
                headers=headers,
                timeout=self.config.WEBHOOK_TIMEOUT
            )

            if response.status_code == 200:
                print(f"✅ Webhook sent successfully for user {webhook_data['payload']['user_id']}")
                return True
            else:
                print(f"❌ Webhook failed: HTTP {response.status_code} - {response.text}")
                return False

        except requests.exceptions.RequestException as e:
            print(f"❌ Webhook network error: {e}")
            return False

    def _process_webhook_queue(self):
        """Process webhook queue asynchronously with persistent storage updates"""
        while True:
            try:
                webhook_data = self.webhook_queue.get(timeout=1)
                if webhook_data:
                    # Submit with persistent storage callback
                    future = self.executor.submit(self._send_webhook_with_persistence, webhook_data)
                    future.add_done_callback(lambda f: self._handle_webhook_result(f, webhook_data))
                    self.webhook_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"🚨 Webhook queue error: {e}")

    def _send_webhook_with_persistence(self, webhook_data: Dict[str, Any]) -> tuple:
        """Send webhook and return result with retry information"""
        try:
            success = self._send_webhook_sync_optimized(webhook_data)
            return success, None, webhook_data.get('retry_count', 0)
        except Exception as e:
            return False, str(e), webhook_data.get('retry_count', 0)

    def _handle_webhook_result(self, future, webhook_data: Dict[str, Any]):
        """Handle webhook delivery result and update persistent storage"""
        try:
            success, error_message, retry_count = future.result()

            persistent_id = webhook_data.get('persistent_id')

            if success:
                self.stats['sent'] += 1
                if persistent_id:
                    self._update_webhook_status(persistent_id, 'completed')
                print(f"✅ Webhook sent successfully for user {webhook_data['payload']['user_id']}")
            else:
                self.stats['failed'] += 1
                print(f"❌ Webhook failed for user {webhook_data['payload']['user_id']}: {error_message}")

                # Handle retry logic
                if persistent_id and retry_count < self.config.WEBHOOK_MAX_RETRIES:
                    self.stats['retried'] += 1
                    self._update_webhook_status(persistent_id, 'failed', error_message, retry_count)
                    print(f"📤 Webhook queued for retry (attempt {retry_count + 1})")
                elif persistent_id:
                    # Max retries exceeded
                    self._update_webhook_status(persistent_id, 'failed', f'Max retries exceeded: {error_message}', retry_count)
                    print(f"❌ Webhook permanently failed for user {webhook_data['payload']['user_id']} (max retries exceeded)")

        except Exception as e:
            print(f"❌ Error handling webhook result: {e}")

    def _check_rate_limit_optimized(self, current_time: int) -> bool:
        """Optimized rate limiting with reduced overhead"""
        window_start = current_time - 60  # 1 minute window

        # Clean old entries efficiently
        self.rate_limiter = {
            ts: count for ts, count in self.rate_limiter.items()
            if ts > window_start
        }

        # Count requests in current window
        total_requests = sum(self.rate_limiter.values())

        if total_requests >= self.config.WEBHOOK_RATE_LIMIT:
            return False

        # Add current request
        self.rate_limiter[current_time] = self.rate_limiter.get(current_time, 0) + 1
        return True

    def _send_webhook_sync_optimized(self, webhook_data: Dict[str, Any]) -> bool:
        """Optimized synchronous webhook sending with detailed error logging"""
        headers = {
            'Content-Type': 'application/json',
            'X-Webhook-Signature': webhook_data['signature'],
            'X-Webhook-Timestamp': str(webhook_data['timestamp']),
            'X-Webhook-Source': 'biometric_server',
            'User-Agent': 'Biometric-Server-Webhook/1.0'
        }

        try:
            # Use session for connection reuse (better performance)
            response = self.session.post(
                self.config.WEBHOOK_URL,
                json=webhook_data['payload'],
                headers=headers,
                allow_redirects=False,  # Faster, no redirects for webhooks
                timeout=self.config.WEBHOOK_TIMEOUT
            )

            if response.status_code == 200:
                return True
            else:
                # Log detailed error for debugging
                print(f"❌ WEBHOOK FAILED: HTTP {response.status_code} - {response.text[:200]}")
                return False

        except requests.exceptions.ConnectionError as e:
            print(f"❌ WEBHOOK CONNECTION ERROR: Cannot connect to {self.config.WEBHOOK_URL} - {str(e)}")
            return False
        except requests.exceptions.Timeout as e:
            print(f"❌ WEBHOOK TIMEOUT: {self.config.WEBHOOK_URL} timed out after {self.config.WEBHOOK_TIMEOUT}s")
            return False
        except requests.exceptions.RequestException as e:
            print(f"❌ WEBHOOK REQUEST ERROR: {str(e)}")
            return False

    def test_webhook_endpoint(self) -> dict:
        """Test if the webhook endpoint is accessible and working"""
        test_payload = {
            'event_type': 'test_webhook',
            'timestamp': int(time.time()),
            'message': 'Testing webhook connectivity',
            'source': 'biometric_server'
        }

        # Create signature for test
        payload_json = json.dumps(test_payload, sort_keys=True)
        signature = hmac.new(
            self.config.WEBHOOK_SECRET.encode(),
            payload_json.encode(),
            hashlib.sha256
        ).hexdigest()

        test_data = {
            'payload': test_payload,
            'signature': signature,
            'timestamp': int(time.time())
        }

        headers = {
            'Content-Type': 'application/json',
            'X-Webhook-Signature': signature,
            'X-Webhook-Timestamp': str(int(time.time())),
            'X-Webhook-Source': 'biometric_server',
            'User-Agent': 'Biometric-Server-Webhook/1.0'
        }

        try:
            response = self.session.post(
                self.config.WEBHOOK_URL,
                json=test_payload,
                headers=headers,
                timeout=10  # Longer timeout for testing
            )

            return {
                'success': response.status_code == 200,
                'status_code': response.status_code,
                'response': response.text[:500],
                'url': self.config.WEBHOOK_URL
            }

        except requests.exceptions.ConnectionError:
            return {
                'success': False,
                'error': 'Connection refused - HRIS server not running',
                'url': self.config.WEBHOOK_URL
            }
        except requests.exceptions.Timeout:
            return {
                'success': False,
                'error': 'Timeout - HRIS server too slow to respond',
                'url': self.config.WEBHOOK_URL
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Request failed: {str(e)}',
                'url': self.config.WEBHOOK_URL
            }

    def _handle_webhook_failure(self, webhook_data: Dict[str, Any]):
        """Handle webhook delivery failure"""
        print("🚨 WEBHOOK DELIVERY FAILED")
        print(f"   User: {webhook_data['payload']['user_id']}")
        print(f"   Device: {webhook_data['payload']['device_id']}")
        print(f"   URL: {self.config.WEBHOOK_URL}")

        # Log failure for monitoring
        self._log_webhook_failure(webhook_data)

        # Send alert if configured
        if self.config.WEBHOOK_ALERT_EMAILS:
            self._send_failure_alert(webhook_data)

    def _log_webhook_failure(self, webhook_data: Dict[str, Any]):
        """Log webhook failure for monitoring"""
        failure_log = {
            'timestamp': datetime.now().isoformat(),
            'type': 'webhook_failure',
            'user_id': webhook_data['payload']['user_id'],
            'device_id': webhook_data['payload']['device_id'],
            'webhook_url': self.config.WEBHOOK_URL,
            'payload': webhook_data['payload']
        }

        # In production, this would write to a log file or monitoring system
        print(f"📝 Failure logged: {failure_log}")

    def _send_failure_alert(self, webhook_data: Dict[str, Any]):
        """Send failure alert to configured emails"""
        # In production, this would send actual emails
        print("📧 Alert emails configured but email sending not implemented in demo")

    def get_stats(self) -> Dict[str, int]:
        """Get webhook statistics"""
        return self.stats.copy()

    def health_check(self) -> Dict[str, Any]:
        """Perform webhook health check with persistent queue status"""
        # Get persistent queue status
        persistent_stats = self._get_persistent_queue_stats()

        return {
            'enabled': self.config.WEBHOOK_ENABLED,
            'url': self.config.WEBHOOK_URL,
            'mode': self.config.WEBHOOK_MODE,
            'rate_limit': self.config.WEBHOOK_RATE_LIMIT,
            'queue_size': self.webhook_queue.qsize() if hasattr(self, 'webhook_queue') else 0,
            'persistent_queue': persistent_stats,
            'stats': self.get_stats()
        }

    def _get_persistent_queue_stats(self) -> Dict[str, Any]:
        """Get persistent queue statistics"""
        try:
            with db.get_db() as conn:
                cursor = conn.cursor()

                # Get counts by status
                cursor.execute('''
                    SELECT status, COUNT(*) as count
                    FROM webhook_queue
                    GROUP BY status
                ''')

                status_counts = {row['status']: row['count'] for row in cursor.fetchall()}

                # Get total count
                cursor.execute('SELECT COUNT(*) as total FROM webhook_queue')
                total = cursor.fetchone()['total']

                # Get failed webhooks ready for retry
                cursor.execute('''
                    SELECT COUNT(*) as retry_ready
                    FROM webhook_queue
                    WHERE status = 'failed' AND next_attempt <= datetime('now')
                ''')
                retry_ready = cursor.fetchone()['retry_ready']

                return {
                    'total': total,
                    'pending': status_counts.get('pending', 0),
                    'failed': status_counts.get('failed', 0),
                    'retry_ready': retry_ready,
                    'by_status': status_counts
                }

        except Exception as e:
            return {
                'error': f'Failed to get persistent stats: {e}',
                'total': 0,
                'pending': 0,
                'failed': 0,
                'retry_ready': 0
            }

    def retry_failed_webhooks(self, limit: int = 10) -> int:
        """Manually retry failed webhooks up to the specified limit"""
        try:
            with db.get_db() as conn:
                cursor = conn.cursor()

                # Get failed webhooks ready for retry
                cursor.execute('''
                    SELECT id, webhook_data, retry_count
                    FROM webhook_queue
                    WHERE status = 'failed'
                    AND next_attempt <= datetime('now')
                    ORDER BY next_attempt ASC
                    LIMIT ?
                ''', (limit,))

                retried_count = 0
                for row in cursor.fetchall():
                    try:
                        webhook_data = json.loads(row['webhook_data'])
                        webhook_data['persistent_id'] = row['id']
                        webhook_data['retry_count'] = row['retry_count'] + 1

                        # Re-queue for processing
                        self.webhook_queue.put(webhook_data)
                        retried_count += 1

                        print(f"📤 Manually retried webhook {row['id']} (attempt {webhook_data['retry_count']})")

                    except Exception as e:
                        print(f"❌ Failed to retry webhook {row['id']}: {e}")

                return retried_count

        except Exception as e:
            print(f"❌ Failed to retry webhooks: {e}")
            return 0

    def _auto_retry_processor(self):
        """Automatically retry failed webhooks when HRIS becomes available"""
        print("🔄 Starting automatic webhook retry processor...")

        while True:
            try:
                # Check if HRIS is available by testing the endpoint
                test_result = self.test_webhook_endpoint()
                hris_available = test_result.get('success', False)

                if hris_available:
                    print("✅ HRIS detected as available - starting automatic retry of failed webhooks")

                    # Retry failed webhooks in batches
                    batch_size = 10
                    total_retried = 0

                    while True:
                        retried = self.retry_failed_webhooks(batch_size)
                        if retried == 0:
                            break  # No more failed webhooks to retry
                        total_retried += retried
                        print(f"📤 Auto-retried {retried} failed webhooks")

                        # Small delay between batches
                        time.sleep(1)

                    if total_retried > 0:
                        print(f"🎉 Successfully auto-retried {total_retried} failed webhooks to HRIS")

                    # Once HRIS is available and we've processed pending webhooks,
                    # check less frequently but still monitor
                    time.sleep(300)  # Check every 5 minutes when HRIS is available

                else:
                    # HRIS not available, check more frequently
                    time.sleep(60)  # Check every minute when HRIS is down

            except Exception as e:
                print(f"❌ Auto-retry processor error: {e}")
                time.sleep(60)  # Wait a minute before retrying on error

# Global webhook manager instance
webhook_manager = WebhookManager()
