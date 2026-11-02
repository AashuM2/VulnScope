-- Upgrade an older VulnScope schema without deleting application data.
-- Back up first. This script is intended for MySQL 8.x.
USE vulnscope;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

DROP PROCEDURE IF EXISTS migrate_vulnscope_schema;
DELIMITER //
CREATE PROCEDURE migrate_vulnscope_schema()
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'targets' AND COLUMN_NAME = 'user_id'
    ) THEN
        ALTER TABLE targets ADD COLUMN user_id INT NULL;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'scans' AND COLUMN_NAME = 'user_id'
    ) THEN
        ALTER TABLE scans ADD COLUMN user_id INT NULL;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'scheduled_scans' AND COLUMN_NAME = 'user_id'
    ) THEN
        ALTER TABLE scheduled_scans ADD COLUMN user_id INT NULL;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'targets' AND COLUMN_NAME = 'url'
          AND CHARACTER_MAXIMUM_LENGTH >= 2048
    ) THEN
        ALTER TABLE targets MODIFY COLUMN url VARCHAR(2048) NOT NULL;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'scheduled_scans' AND COLUMN_NAME = 'url'
          AND CHARACTER_MAXIMUM_LENGTH >= 2048
    ) THEN
        ALTER TABLE scheduled_scans MODIFY COLUMN url VARCHAR(2048) NOT NULL;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'scans' AND INDEX_NAME = 'idx_scans_user_date'
    ) THEN
        CREATE INDEX idx_scans_user_date ON scans (user_id, scanned_at);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'scheduled_scans' AND INDEX_NAME = 'idx_scheduled_user_active'
    ) THEN
        CREATE INDEX idx_scheduled_user_active ON scheduled_scans (user_id, is_active);
    END IF;
END//
DELIMITER ;

CALL migrate_vulnscope_schema();
DROP PROCEDURE migrate_vulnscope_schema;
