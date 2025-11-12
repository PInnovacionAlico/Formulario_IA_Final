-- Add is_super_admin column to users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_super_admin BOOLEAN DEFAULT false;

-- Create index for faster queries
CREATE INDEX IF NOT EXISTS idx_users_is_super_admin ON users(is_super_admin);

-- Example: Set the first admin as super admin (replace with your actual admin email)
-- UPDATE users SET is_super_admin = true WHERE email = 'tu-email@ejemplo.com';

-- Note: Only ONE user should be super admin. The super admin:
-- 1. Cannot be deleted by anyone
-- 2. Cannot have their admin status removed
-- 3. Can delete any admin or user
-- 4. Has full control over the system
