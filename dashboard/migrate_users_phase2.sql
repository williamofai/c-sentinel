-- C-Sentinel Multi-User Migration
-- Run with: sudo -u postgres psql -d sentinel -f migrate_users.sql

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(64) UNIQUE NOT NULL,
    email VARCHAR(255),
    password_hash VARCHAR(64) NOT NULL,
    role VARCHAR(20) DEFAULT 'viewer' CHECK (role IN ('admin', 'operator', 'viewer')),
    created_at TIMESTAMP DEFAULT NOW(),
    last_login TIMESTAMP,
    active BOOLEAN DEFAULT TRUE
);

-- Create index for login lookups
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_active ON users(active);

-- User sessions table (for tracking active sessions)
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

-- Add columns if they don't exist (for existing installations)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='user_sessions' AND column_name='last_active') THEN
        ALTER TABLE user_sessions ADD COLUMN last_active TIMESTAMP DEFAULT NOW();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='user_sessions' AND column_name='user_agent') THEN
        ALTER TABLE user_sessions ADD COLUMN user_agent VARCHAR(512);
    END IF;
END $$;

-- Audit log for user actions (optional but recommended)
CREATE TABLE IF NOT EXISTS user_audit_log (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(50) NOT NULL,
    details JSONB,
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_user_audit_created ON user_audit_log(created_at);

-- Function to clean up expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS void AS $$
BEGIN
    DELETE FROM user_sessions WHERE expires_at < NOW();
END;
$$ LANGUAGE plpgsql;

-- Grant permissions
GRANT ALL ON users TO sentinel;
GRANT ALL ON user_sessions TO sentinel;
GRANT ALL ON user_audit_log TO sentinel;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO sentinel;

SELECT 'Migration complete. Users table created.' AS status;
