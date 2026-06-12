-- Initialize DVWA database and user
CREATE DATABASE IF NOT EXISTS dvwa;

-- Create dvwa user with full privileges
CREATE USER IF NOT EXISTS 'dvwa'@'%' IDENTIFIED BY 'dvwa';
CREATE USER IF NOT EXISTS 'dvwa'@'localhost' IDENTIFIED BY 'dvwa';

-- Grant all privileges on dvwa database
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'%';
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';

FLUSH PRIVILEGES;
