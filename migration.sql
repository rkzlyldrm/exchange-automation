-- Exchange Web Credentials table for browser automation
-- Run against the cryptohub database

CREATE TABLE IF NOT EXISTS exchange_web_credentials (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    exchange_name VARCHAR(50) NOT NULL,
    label VARCHAR(100),
    email TEXT NOT NULL,
    password TEXT NOT NULL,
    totp_secret TEXT,
    extra_data TEXT,
    session_status VARCHAR(20) DEFAULT 'disconnected',
    last_login_at TIMESTAMPTZ,
    last_error VARCHAR(500),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_web_cred_exchange
    ON exchange_web_credentials(user_id, exchange_name);
