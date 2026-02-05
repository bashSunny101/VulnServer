-- ========================================
-- PostgreSQL Database Initialization
-- ========================================
-- LEARNING: This creates the schema for structured attack data

-- Create extension for UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ========================================
-- Attack Sessions Table
-- ========================================
-- LEARNING: Stores high-level attack session information

CREATE TABLE IF NOT EXISTS attack_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id VARCHAR(255) UNIQUE NOT NULL,
    source_ip INET NOT NULL,
    source_port INTEGER,
    destination_ip INET,
    destination_port INTEGER,
    honeypot_type VARCHAR(50) NOT NULL,  -- 'cowrie', 'dionaea', etc.
    protocol VARCHAR(20),                 -- 'ssh', 'telnet', 'smb', etc.
    start_time TIMESTAMP NOT NULL,
    end_time TIMESTAMP,
    duration_seconds INTEGER,
    
    -- Authentication
    username VARCHAR(255),
    password VARCHAR(255),
    auth_success BOOLEAN DEFAULT FALSE,
    
    -- Geo-location
    country_code VARCHAR(2),
    country_name VARCHAR(100),
    city VARCHAR(100),
    latitude DECIMAL(10, 8),
    longitude DECIMAL(11, 8),
    asn VARCHAR(50),
    asn_org VARCHAR(255),
    
    -- Threat scoring
    threat_score INTEGER DEFAULT 0,
    severity VARCHAR(20),  -- 'low', 'medium', 'high', 'critical'
    
    -- MITRE ATT&CK
    mitre_tactics TEXT[],
    mitre_techniques TEXT[],
    
    -- Metadata
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for fast queries
CREATE INDEX IF NOT EXISTS idx_sessions_source_ip ON attack_sessions(source_ip);
CREATE INDEX IF NOT EXISTS idx_sessions_start_time ON attack_sessions(start_time DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_honeypot ON attack_sessions(honeypot_type);
CREATE INDEX IF NOT EXISTS idx_sessions_threat_score ON attack_sessions(threat_score DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_country ON attack_sessions(country_code);

-- ========================================
-- Attack Commands Table
-- ========================================
-- LEARNING: Stores individual commands executed by attackers

CREATE TABLE IF NOT EXISTS attack_commands (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id UUID REFERENCES attack_sessions(id) ON DELETE CASCADE,
    command TEXT NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    
    -- Command classification
    command_type VARCHAR(50),  -- 'reconnaissance', 'download', 'persistence', etc.
    is_malicious BOOLEAN DEFAULT TRUE,
    
    -- MITRE ATT&CK mapping
    mitre_tactic VARCHAR(20),
    mitre_technique VARCHAR(20),
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_commands_session ON attack_commands(session_id);
CREATE INDEX IF NOT EXISTS idx_commands_timestamp ON attack_commands(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_commands_type ON attack_commands(command_type);

-- ========================================
-- Malware Samples Table
-- ========================================
-- LEARNING: Tracks malware captured by honeypots

CREATE TABLE IF NOT EXISTS malware_samples (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id UUID REFERENCES attack_sessions(id),
    
    -- File identification
    sha256 VARCHAR(64) UNIQUE NOT NULL,
    md5 VARCHAR(32),
    sha1 VARCHAR(40),
    file_size INTEGER,
    file_type VARCHAR(100),
    
    -- Download info
    download_url TEXT,
    download_method VARCHAR(50),  -- 'wget', 'curl', 'ftp', etc.
    
    -- Storage
    storage_path TEXT,
    
    -- Analysis
    virustotal_detections INTEGER,
    malware_family VARCHAR(100),
    is_analyzed BOOLEAN DEFAULT FALSE,
    
    -- Timestamps
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_malware_sha256 ON malware_samples(sha256);
CREATE INDEX IF NOT EXISTS idx_malware_first_seen ON malware_samples(first_seen DESC);
CREATE INDEX IF NOT EXISTS idx_malware_family ON malware_samples(malware_family);

-- ========================================
-- Attacker Profiles Table
-- ========================================
-- LEARNING: Aggregated view of attacker behavior

CREATE TABLE IF NOT EXISTS attacker_profiles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ip_address INET UNIQUE NOT NULL,
    
    -- Activity stats
    total_sessions INTEGER DEFAULT 0,
    total_commands INTEGER DEFAULT 0,
    total_malware_downloads INTEGER DEFAULT 0,
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    
    -- Behavior patterns
    targeted_services TEXT[],  -- ['ssh', 'telnet', 'smb']
    common_usernames TEXT[],
    common_passwords TEXT[],
    
    -- Threat assessment
    avg_threat_score DECIMAL(5, 2),
    max_threat_score INTEGER,
    is_persistent BOOLEAN DEFAULT FALSE,  -- Multiple attacks over time
    is_automated BOOLEAN DEFAULT FALSE,   -- Bot-like behavior
    
    -- Geo-location (most recent)
    country_code VARCHAR(2),
    country_name VARCHAR(100),
    city VARCHAR(100),
    asn VARCHAR(50),
    asn_org VARCHAR(255),
    
    -- Intelligence
    in_blocklist BOOLEAN DEFAULT FALSE,
    abuse_confidence_score INTEGER,  -- From AbuseIPDB
    
    -- Metadata
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_profiles_ip ON attacker_profiles(ip_address);
CREATE INDEX IF NOT EXISTS idx_profiles_last_seen ON attacker_profiles(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_profiles_threat_score ON attacker_profiles(avg_threat_score DESC);
CREATE INDEX IF NOT EXISTS idx_profiles_country ON attacker_profiles(country_code);

-- ========================================
-- IDS Alerts Table
-- ========================================
-- LEARNING: Stores Snort IDS alerts

CREATE TABLE IF NOT EXISTS ids_alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Alert info
    alert_msg TEXT NOT NULL,
    signature_id INTEGER,
    priority INTEGER,
    classification VARCHAR(100),
    
    -- Network details
    source_ip INET NOT NULL,
    source_port INTEGER,
    dest_ip INET NOT NULL,
    dest_port INTEGER,
    protocol VARCHAR(20),
    
    -- Timestamp
    timestamp TIMESTAMP NOT NULL,
    
    -- Correlation
    related_session_id UUID REFERENCES attack_sessions(id),
    
    -- Threat info
    threat_score INTEGER,
    severity VARCHAR(20),
    
    -- MITRE ATT&CK
    mitre_tactic VARCHAR(20),
    mitre_technique VARCHAR(20),
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON ids_alerts(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON ids_alerts(source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_signature ON ids_alerts(signature_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON ids_alerts(severity);

-- ========================================
-- LEARNING: Database Design Principles
-- ========================================
-- 1. Normalize data to reduce redundancy
-- 2. Use appropriate data types (INET for IPs, TIMESTAMP for times)
-- 3. Index frequently queried fields
-- 4. Use foreign keys for referential integrity
-- 5. Plan for analytics queries (aggregations, time-series)
--
-- Why PostgreSQL for this project?
-- - Excellent JSON support (JSONB)
-- - Strong ACID compliance (critical for security data)
-- - Powerful aggregation and window functions
-- - Full-text search capabilities
-- - Mature replication and backup tools
-- ========================================
