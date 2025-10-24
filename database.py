#!/usr/bin/env python3
"""
SQLite Database Module for Biometric Server
Stores attendance logs and user data persistently
"""

import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Optional, Any
from contextlib import contextmanager
import logging

logger = logging.getLogger(__name__)

DATABASE_PATH = 'biometric.db'


@contextmanager
def get_db():
    """Context manager for database connections"""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row  # Return rows as dictionaries
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error(f"Database error: {e}")
        raise
    finally:
        conn.close()


def init_database():
    """Initialize database schema"""
    with get_db() as conn:
        cursor = conn.cursor()

        # Create logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attendance_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                io_mode INTEGER NOT NULL,
                io_mode_str TEXT NOT NULL,
                verify_mode INTEGER NOT NULL,
                verify_mode_str TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                datetime TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(device_id, user_id, timestamp)
            )
        ''')

        # Add new timezone columns if they don't exist (migration)
        try:
            cursor.execute("PRAGMA table_info(attendance_logs)")
            columns = [row[1] for row in cursor.fetchall()]

            if 'datetime_utc' not in columns:
                cursor.execute('ALTER TABLE attendance_logs ADD COLUMN datetime_utc TEXT')
            if 'datetime_local' not in columns:
                cursor.execute('ALTER TABLE attendance_logs ADD COLUMN datetime_local TEXT')
            if 'timezone' not in columns:
                cursor.execute('ALTER TABLE attendance_logs ADD COLUMN timezone TEXT DEFAULT "UTC"')
        except Exception as e:
            logger.warning(f"Column migration may have failed: {e}")

        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS enrolled_users (
                user_id INTEGER PRIMARY KEY,
                privilege INTEGER NOT NULL,
                enabled INTEGER NOT NULL,
                password_flag INTEGER NOT NULL,
                card_flag INTEGER NOT NULL,
                face_flag INTEGER NOT NULL,
                fp_count INTEGER NOT NULL,
                vein_count INTEGER NOT NULL,
                enrolled_backups TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Create devices table for whitelist/blacklist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                device_id TEXT PRIMARY KEY,
                device_name TEXT,
                status TEXT NOT NULL DEFAULT 'allowed',
                last_seen TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                CHECK(status IN ('allowed', 'blocked'))
            )
        ''')

        # Create indexes for better query performance
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_logs_timestamp
            ON attendance_logs(timestamp DESC)
        ''')

        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_logs_user_id
            ON attendance_logs(user_id)
        ''')

        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_logs_device_id
            ON attendance_logs(device_id)
        ''')

        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_users_enabled
            ON enrolled_users(enabled)
        ''')

        conn.commit()
        logger.info("Database initialized successfully")


# Cache for user directions to improve performance
_user_direction_cache = {}

def get_user_last_direction(user_id: int) -> str:
    """Get the last direction (IN/OUT) for a user with caching"""
    # Check cache first for better performance
    if user_id in _user_direction_cache:
        return _user_direction_cache[user_id]

    try:
        with get_db() as conn:
            cursor = conn.cursor()
            # Optimized query with index-friendly ordering
            cursor.execute('''
                SELECT io_mode_str FROM attendance_logs
                WHERE user_id = ?
                ORDER BY id DESC
                LIMIT 1
            ''', (user_id,))
            result = cursor.fetchone()

            direction = result[0] if result else None
            # Cache the result for faster subsequent lookups
            _user_direction_cache[user_id] = direction
            return direction
    except Exception as e:
        logger.error(f"Error getting user last direction for user {user_id}: {e}")
        return None


def update_user_direction_cache(user_id: int, direction: str):
    """Update the cache when a new log is saved"""
    _user_direction_cache[user_id] = direction


def clear_user_direction_cache():
    """Clear cache (useful for maintenance)"""
    global _user_direction_cache
    _user_direction_cache.clear()
    logger.info("User direction cache cleared")


def save_log(log_data: Dict[str, Any]) -> tuple:
    """
    Save attendance log to database
    Returns (success: bool, is_duplicate: bool)
    - success: True if operation completed without error
    - is_duplicate: True if record was duplicate and ignored
    """
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR IGNORE INTO attendance_logs
                (device_id, user_id, io_mode, io_mode_str, verify_mode, verify_mode_str, timestamp, datetime, datetime_utc, datetime_local, timezone)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                log_data.get('device_id', 'unknown'),
                log_data['user_id'],
                log_data.get('io_mode', 0),
                log_data.get('io_mode_str', ''),
                log_data.get('verify_mode', 0),
                log_data.get('verify_mode_str', ''),
                log_data['timestamp'],  # Original device timestamp
                log_data.get('datetime_utc', ''),  # Legacy datetime field (same as UTC)
                log_data.get('datetime_utc', ''),  # UTC datetime (primary)
                log_data.get('datetime_local', ''),  # Local datetime (for display)
                log_data.get('timezone', 'UTC')  # Timezone info
            ))

            # Check if it was inserted or ignored due to duplicate constraint
            rows_affected = cursor.rowcount
            is_duplicate = (rows_affected == 0)

            # For our use case, both insertion and duplicate-ignore are "successful"
            # The duplicate prevention is working as intended
            return True, is_duplicate

    except Exception as e:
        logger.error(f"Error saving log: {e}")
        return False, False


def save_logs_batch(logs: List[Dict[str, Any]]) -> int:
    """
    Save multiple logs in a single transaction
    Returns number of logs saved
    """
    saved_count = 0
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            for log_data in logs:
                cursor.execute('''
                    INSERT OR IGNORE INTO attendance_logs
                    (device_id, user_id, io_mode, io_mode_str, verify_mode, verify_mode_str, timestamp, datetime)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    log_data.get('device_id', 'unknown'),
                    log_data['user_id'],
                    log_data.get('io_mode', 0),
                    log_data.get('io_mode_str', ''),
                    log_data.get('verify_mode', 0),
                    log_data.get('verify_mode_str', ''),
                    log_data['timestamp'],
                    log_data.get('datetime', '')
                ))
                if cursor.rowcount > 0:
                    saved_count += 1

        logger.info(f"Saved {saved_count}/{len(logs)} new logs to database")
        return saved_count
    except Exception as e:
        logger.error(f"Error saving logs batch: {e}")
        return saved_count


def get_logs(limit: Optional[int] = None, offset: int = 0, device_id: Optional[str] = None) -> List[Dict]:
    """Get attendance logs from database"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()

            if device_id:
                if limit:
                    cursor.execute('''
                        SELECT id, device_id, user_id, io_mode, io_mode_str, verify_mode, verify_mode_str,
                               timestamp, datetime, created_at
                        FROM attendance_logs
                        WHERE device_id = ?
                        ORDER BY timestamp DESC
                        LIMIT ? OFFSET ?
                    ''', (device_id, limit, offset))
                else:
                    cursor.execute('''
                        SELECT id, device_id, user_id, io_mode, io_mode_str, verify_mode, verify_mode_str,
                               timestamp, datetime, datetime_utc, datetime_local, timezone, created_at
                        FROM attendance_logs
                        WHERE device_id = ?
                        ORDER BY timestamp DESC
                    ''', (device_id,))
            else:
                if limit:
                    cursor.execute('''
                        SELECT id, device_id, user_id, io_mode, io_mode_str, verify_mode, verify_mode_str,
                               timestamp, datetime, datetime_utc, datetime_local, timezone, created_at
                        FROM attendance_logs
                        ORDER BY timestamp DESC
                        LIMIT ? OFFSET ?
                    ''', (limit, offset))
                else:
                    cursor.execute('''
                        SELECT id, device_id, user_id, io_mode, io_mode_str, verify_mode, verify_mode_str,
                               timestamp, datetime, datetime_utc, datetime_local, timezone, created_at
                        FROM attendance_logs
                        ORDER BY timestamp DESC
                    ''')

            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    except Exception as e:
        logger.error(f"Error getting logs: {e}")
        return []


def get_logs_count() -> int:
    """Get total count of logs"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM attendance_logs')
            return cursor.fetchone()[0]
    except Exception as e:
        logger.error(f"Error getting logs count: {e}")
        return 0


def save_user(user_data: Dict[str, Any]) -> bool:
    """Save or update user to database"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()

            # Convert enrolled_backups list to JSON string
            enrolled_backups_json = json.dumps(user_data.get('enrolled_backups', []))

            cursor.execute('''
                INSERT OR REPLACE INTO enrolled_users
                (user_id, privilege, enabled, password_flag, card_flag, face_flag,
                 fp_count, vein_count, enrolled_backups, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                user_data['user_id'],
                user_data.get('privilege', 0),
                user_data.get('enabled', 0),
                user_data.get('password_flag', 0),
                user_data.get('card_flag', 0),
                user_data.get('face_flag', 0),
                user_data.get('fp_count', 0),
                user_data.get('vein_count', 0),
                enrolled_backups_json
            ))
            return True
    except Exception as e:
        logger.error(f"Error saving user: {e}")
        return False


def save_users_batch(users: List[Dict[str, Any]]) -> int:
    """Save multiple users in a single transaction"""
    saved_count = 0
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            for user_data in users:
                enrolled_backups_json = json.dumps(user_data.get('enrolled_backups', []))

                cursor.execute('''
                    INSERT OR REPLACE INTO enrolled_users
                    (user_id, privilege, enabled, password_flag, card_flag, face_flag,
                     fp_count, vein_count, enrolled_backups, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ''', (
                    user_data['user_id'],
                    user_data.get('privilege', 0),
                    user_data.get('enabled', 0),
                    user_data.get('password_flag', 0),
                    user_data.get('card_flag', 0),
                    user_data.get('face_flag', 0),
                    user_data.get('fp_count', 0),
                    user_data.get('vein_count', 0),
                    enrolled_backups_json
                ))
                saved_count += 1

        logger.info(f"Saved {saved_count} users to database")
        return saved_count
    except Exception as e:
        logger.error(f"Error saving users batch: {e}")
        return saved_count


def get_users(limit: Optional[int] = None, offset: int = 0) -> List[Dict]:
    """Get enrolled users from database"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()

            if limit:
                cursor.execute('''
                    SELECT user_id, privilege, enabled, password_flag, card_flag, face_flag,
                           fp_count, vein_count, enrolled_backups, updated_at
                    FROM enrolled_users
                    ORDER BY user_id
                    LIMIT ? OFFSET ?
                ''', (limit, offset))
            else:
                cursor.execute('''
                    SELECT user_id, privilege, enabled, password_flag, card_flag, face_flag,
                           fp_count, vein_count, enrolled_backups, updated_at
                    FROM enrolled_users
                    ORDER BY user_id
                ''')

            rows = cursor.fetchall()
            users = []
            for row in rows:
                user = dict(row)
                # Parse enrolled_backups JSON back to list
                if user['enrolled_backups']:
                    user['enrolled_backups'] = json.loads(user['enrolled_backups'])
                users.append(user)
            return users
    except Exception as e:
        logger.error(f"Error getting users: {e}")
        return []


def get_users_count() -> int:
    """Get total count of enrolled users"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM enrolled_users')
            return cursor.fetchone()[0]
    except Exception as e:
        logger.error(f"Error getting users count: {e}")
        return 0


def get_user_by_id(user_id: int) -> Optional[Dict]:
    """Get a specific user by ID"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT user_id, privilege, enabled, password_flag, card_flag, face_flag,
                       fp_count, vein_count, enrolled_backups, updated_at
                FROM enrolled_users
                WHERE user_id = ?
            ''', (user_id,))

            row = cursor.fetchone()
            if row:
                user = dict(row)
                if user['enrolled_backups']:
                    user['enrolled_backups'] = json.loads(user['enrolled_backups'])
                return user
            return None
    except Exception as e:
        logger.error(f"Error getting user {user_id}: {e}")
        return None


def clear_all_logs() -> bool:
    """Clear all attendance logs (use with caution!)"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM attendance_logs')
            logger.warning(f"Cleared {cursor.rowcount} logs from database")
            return True
    except Exception as e:
        logger.error(f"Error clearing logs: {e}")
        return False


def clear_all_users() -> bool:
    """Clear all users (use with caution!)"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM enrolled_users')
            logger.warning(f"Cleared {cursor.rowcount} users from database")
            return True
    except Exception as e:
        logger.error(f"Error clearing users: {e}")
        return False


# ==============================================================================
# Device Management Functions
# ==============================================================================

def upsert_device(device_id: str, device_name: Optional[str] = None, status: str = 'allowed') -> bool:
    """Add or update device in database"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO devices (device_id, device_name, status, last_seen)
                VALUES (?, ?, ?, datetime('now', 'localtime'))
                ON CONFLICT(device_id) DO UPDATE SET
                    device_name = COALESCE(?, device_name),
                    status = ?,
                    last_seen = datetime('now', 'localtime')
            ''', (device_id, device_name, status, device_name, status))
            return True
    except Exception as e:
        logger.error(f"Error upserting device {device_id}: {e}")
        return False


def update_device_last_seen(device_id: str) -> bool:
    """Update device last seen timestamp"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO devices (device_id, last_seen)
                VALUES (?, datetime('now', 'localtime'))
                ON CONFLICT(device_id) DO UPDATE SET
                    last_seen = datetime('now', 'localtime')
            ''', (device_id,))
            return True
    except Exception as e:
        logger.error(f"Error updating device last seen {device_id}: {e}")
        return False


def get_device_status(device_id: str) -> Optional[str]:
    """Get device status (allowed/blocked)"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT status FROM devices WHERE device_id = ?', (device_id,))
            row = cursor.fetchone()
            return row['status'] if row else 'allowed'  # Default to allowed if not in DB
    except Exception as e:
        logger.error(f"Error getting device status {device_id}: {e}")
        return 'allowed'


def set_device_status(device_id: str, status: str) -> bool:
    """Set device status (allowed/blocked)"""
    if status not in ['allowed', 'blocked']:
        logger.error(f"Invalid status: {status}")
        return False

    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO devices (device_id, status)
                VALUES (?, ?)
                ON CONFLICT(device_id) DO UPDATE SET status = ?
            ''', (device_id, status, status))
            return True
    except Exception as e:
        logger.error(f"Error setting device status {device_id}: {e}")
        return False


def get_all_devices() -> List[Dict]:
    """Get all devices"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT device_id, device_name, status, last_seen, created_at
                FROM devices
                ORDER BY last_seen DESC
            ''')
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    except Exception as e:
        logger.error(f"Error getting devices: {e}")
        return []


def delete_device(device_id: str) -> bool:
    """Delete device from database"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM devices WHERE device_id = ?', (device_id,))
            return cursor.rowcount > 0
    except Exception as e:
        logger.error(f"Error deleting device {device_id}: {e}")
        return False
