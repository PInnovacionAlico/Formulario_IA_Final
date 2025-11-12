-- Migration: Add user ban functionality
-- Date: 2025-11-12
-- Description: Adds banned column and ban-related fields to users table

-- Add ban columns
ALTER TABLE users 
ADD COLUMN IF NOT EXISTS banned BOOLEAN DEFAULT false,
ADD COLUMN IF NOT EXISTS banned_at TIMESTAMP WITH TIME ZONE,
ADD COLUMN IF NOT EXISTS banned_reason TEXT,
ADD COLUMN IF NOT EXISTS banned_by UUID REFERENCES users(id);

-- Create index on banned column for faster lookups
CREATE INDEX IF NOT EXISTS idx_users_banned ON users(banned);

-- Optional: Add comments to columns
COMMENT ON COLUMN users.banned IS 'Whether the user is permanently banned from the platform';
COMMENT ON COLUMN users.banned_at IS 'Timestamp when the user was banned';
COMMENT ON COLUMN users.banned_reason IS 'Reason for banning the user';
COMMENT ON COLUMN users.banned_by IS 'ID of the admin who banned the user';
