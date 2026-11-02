-- VulnScope database schema.
-- Safe to run repeatedly: CREATE TABLE IF NOT EXISTS does not delete existing data.
CREATE DATABASE IF NOT EXISTS vulnscope
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE vulnscope;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS targets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    url VARCHAR(2048) NOT NULL,
    user_id INT NULL,
    added_on DATETIME DEFAULT CURRENT_TIMESTAMP,
    scheduled BOOLEAN DEFAULT FALSE,
    INDEX idx_targets_user_url (user_id, url(191)),
    CONSTRAINT fk_targets_user FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS scans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    target_id INT NULL,
    user_id INT NULL,
    scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    risk_score INT DEFAULT 0,
    total_vulnerabilities INT DEFAULT 0,
    INDEX idx_scans_user_date (user_id, scanned_at),
    CONSTRAINT fk_scans_target FOREIGN KEY (target_id) REFERENCES targets(id)
        ON DELETE SET NULL,
    CONSTRAINT fk_scans_user FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT NULL,
    vuln_type VARCHAR(100),
    severity VARCHAR(20),
    detected_by VARCHAR(50),
    description TEXT,
    fix_suggestion TEXT,
    INDEX idx_vulnerabilities_scan (scan_id),
    CONSTRAINT fk_vulnerabilities_scan FOREIGN KEY (scan_id) REFERENCES scans(id)
        ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS scheduled_scans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    url VARCHAR(2048) NOT NULL,
    user_id INT NULL,
    frequency_days INT DEFAULT 7,
    alert_email VARCHAR(255),
    last_scanned DATETIME NULL,
    next_scan DATETIME NULL,
    added_on DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    INDEX idx_scheduled_user_active (user_id, is_active),
    CONSTRAINT fk_scheduled_user FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE
) ENGINE=InnoDB;
