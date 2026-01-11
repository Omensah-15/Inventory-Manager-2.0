-- PostgreSQL initialization script for InvyPro
-- This script runs when PostgreSQL container starts

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create additional database objects if needed
-- This file can be extended with custom initialization logic

-- Note: Main database schema is created by the application
-- This file is for PostgreSQL-level initialization only
