-- C-Sentinel Dashboard Database Migration
-- Consolidated schema for fresh installations
-- 
-- Usage: sudo -u postgres psql -d sentinel -f migrate.sql
--
-- This creates all required tables for C-Sentinel v0.6.0+

BEGIN;

-- ============================================
-- CORE TABLES (hosts and fingerprints)
-- ============================================

-- Hosts table (created by initial setup, but ensure it exists)
CREATE TABLE IF NOT EXISTS hosts (
    id SERIAL PRIMARY KEY,
    hostname VARCHAR(255) UNIQUE NOT NULL,
    first_seen TIMESTAMP DEFAULT NOW(),
    last_seen TIMESTAMP DEFAULT NOW(),
    -- Cumulative audit totals
    audit_auth_failures_total INTEGER DEFAULT 0,
    audit_sudo_count_total INTEGER DEFAULT 0,
    audit_sensitive_access_total INTEGER DEFAULT 0,
    audit_brute_force_count INTEGER DEFAULT 0,
    audit_totals_since TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_hosts_hostname ON hosts(hostname);
CREATE INDEX IF NOT EXISTS idx_hosts_audit_totals_since ON hosts(audit_totals_since);

-- Fingerprints table (system snapshots)
CREATE TABLE IF NOT EXISTS fingerprints (
    id SERIAL PRIMARY KEY,
    host_id INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
    captured_at TIMESTAMP DEFAULT NOW(),
    data JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_fingerprints_host_time ON fingerprints(host_id, captured_at DESC);

-- ============================================
-- AUDIT EVENTS (security event history)
-- ============================================

CREATE TABLE IF NOT EXISTS audit_events (
    id SERIAL PRIMARY KEY,
    host_id INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
    fingerprint_id INTEGER REFERENCES fingerprints(id) ON DELETE CASCADE,
    captured_at TIMESTAMP DEFAULT NOW(),
    event_type VARCHAR(32) NOT NULL,  -- 'auth_failure', 'sudo', 'file_access', 'brute_force', etc.
    count INTEGER DEFAULT 1,
    details JSONB,
    acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_events_host_time ON audit_events(host_id, captured_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_type ON audit_events(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_events_acknowledged ON audit_events(acknowledged) WHERE NOT acknowledged;

-- ============================================
-- USER AUTHENTICATION
-- ============================================

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(64) UNIQUE NOT NULL,
    email VARCHAR(255),
    password_hash VARCHAR(64) NOT NULL,
    role VARCHAR(20) DEFAULT 'viewer' CHECK (role IN ('admin', 'operator', 'viewer')),
    created_at TIMESTAMP DEFAULT NOW(),
    last_login TIMESTAMP,
    active BOOLEAN DEFAULT TRUE,
    -- Two-factor authentication
    totp_secret VARCHAR(32),
    totp_enabled BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_active ON users(active);

-- User sessions (database-backed sessions)
CREATE TABLE IF NOT EXISTS user_sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(64) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    last_active TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL,
    ip_address VARCHAR(45),
    user_agent VARCHAR(512)
);

CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_user_sessions_expires ON user_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_user_sessions_user ON user_sessions(user_id);

-- User API keys (for automation/CI)
CREATE TABLE IF NOT EXISTS user_api_keys (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    key_hash VARCHAR(64) NOT NULL,
    key_prefix VARCHAR(12) NOT NULL,
    name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    last_used TIMESTAMP,
    expires_at TIMESTAMP,
    active BOOLEAN DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON user_api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON user_api_keys(user_id);

-- User audit log (tracks user actions)
CREATE TABLE IF NOT EXISTS user_audit_log (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(50) NOT NULL,
    details JSONB,
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_user_audit_created ON user_audit_log(created_at);

-- ============================================
-- HELPER FUNCTIONS
-- ============================================

-- Clean up expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS void AS $$
BEGIN
    DELETE FROM user_sessions WHERE expires_at < NOW();
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- PERMISSIONS
-- ============================================

GRANT ALL ON hosts TO sentinel;
GRANT ALL ON fingerprints TO sentinel;
GRANT ALL ON audit_events TO sentinel;
GRANT ALL ON users TO sentinel;
GRANT ALL ON user_sessions TO sentinel;
GRANT ALL ON user_api_keys TO sentinel;
GRANT ALL ON user_audit_log TO sentinel;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO sentinel;

COMMIT;

-- ============================================
-- VERIFICATION
-- ============================================

SELECT 'C-Sentinel database migration complete!' AS status;
SELECT table_name FROM information_schema.tables 
WHERE table_schema = 'public' 
AND table_name IN ('hosts', 'fingerprints', 'audit_events', 'users', 'user_sessions', 'user_api_keys', 'user_audit_log')
ORDER BY table_name;
