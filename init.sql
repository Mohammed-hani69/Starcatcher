CREATE DATABASE IF NOT EXISTS starcatcher;
USE starcatcher;

-- Create any initial database schema here if needed
-- This will run when the MySQL container first starts

-- Grant privileges to application user
GRANT ALL PRIVILEGES ON starcatcher.* TO 'starcatcher'@'%';
FLUSH PRIVILEGES;
