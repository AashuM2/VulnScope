"""MySQL connection settings for VulnScope.

Configure credentials through environment variables instead of committing secrets.
"""
import os
import mysql.connector

DB_CONFIG = {
    "host": os.environ.get("VULNSCOPE_DB_HOST", "127.0.0.1"),
    "port": int(os.environ.get("VULNSCOPE_DB_PORT", "3306")),
    "user": os.environ.get("VULNSCOPE_DB_USER", "root"),
    "password": os.environ.get("VULNSCOPE_DB_PASSWORD", ""),
    "database": os.environ.get("VULNSCOPE_DB_NAME", "vulnscope"),
    "connection_timeout": 8,
    "charset": "utf8mb4",
    "use_unicode": True,
}


def get_db():
    """Open a new connection; callers are responsible for closing it."""
    return mysql.connector.connect(**DB_CONFIG)
