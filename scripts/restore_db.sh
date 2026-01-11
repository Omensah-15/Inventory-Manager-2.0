#!/bin/bash

# InvyPro Database Restore Script
# Usage: ./restore_db.sh <backup_file>

set -e

# Configuration
BACKUP_DIR="./backups"
LOG_DIR="./logs"
RESTORE_LOG="$LOG_DIR/restore_$(date +%Y%m%d_%H%M%S).log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Log function
log() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$RESTORE_LOG"
}

# Error handler
error_exit() {
    log "${RED}ERROR: $1${NC}"
    exit 1
}

# Check if backup file is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <backup_file>"
    echo "Available backups:"
    ls -lh "$BACKUP_DIR"/*.sql.gz 2>/dev/null || echo "No backups found"
    exit 1
fi

BACKUP_FILE="$1"

# Check if backup file exists
if [ ! -f "$BACKUP_FILE" ]; then
    # Check in backup directory
    if [ -f "$BACKUP_DIR/$BACKUP_FILE" ]; then
        BACKUP_FILE="$BACKUP_DIR/$BACKUP_FILE"
    elif [ -f "$BACKUP_DIR/$BACKUP_FILE.sql.gz" ]; then
        BACKUP_FILE="$BACKUP_DIR/$BACKUP_FILE.sql.gz"
    else
        error_exit "Backup file not found: $BACKUP_FILE"
    fi
fi

# Ensure log directory exists
mkdir -p "$LOG_DIR"

log "${YELLOW}Starting database restore...${NC}"
log "Backup file: $BACKUP_FILE"

# Load environment variables
if [ -f .env ]; then
    log "Loading environment variables from .env"
    export $(grep -v '^#' .env | xargs)
else
    log "${YELLOW}Warning: .env file not found, using defaults${NC}"
fi

# Set database connection parameters
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-invypro}"
DB_USER="${DB_USER:-invypro_user}"
DB_PASSWORD="${DB_PASSWORD:-invypro_pass}"

log "Database: $DB_NAME@$DB_HOST:$DB_PORT"

# Check if file is compressed
if [[ "$BACKUP_FILE" == *.gz ]]; then
    log "Backup file is compressed, extracting..."
    TEMP_FILE=$(mktemp)
    gunzip -c "$BACKUP_FILE" > "$TEMP_FILE"
    BACKUP_FILE="$TEMP_FILE"
    COMPRESSED=true
else
    COMPRESSED=false
fi

# Validate backup file
if [ ! -s "$BACKUP_FILE" ]; then
    error_exit "Backup file is empty or invalid"
fi

log "Backup file size: $(du -h "$BACKUP_FILE" | cut -f1)"

# Create restore directory for temporary files
RESTORE_TEMP_DIR=$(mktemp -d)
log "Temporary directory: $RESTORE_TEMP_DIR"

# Pre-process backup file to remove problematic commands
log "Pre-processing backup file..."
PROCESSED_BACKUP="$RESTORE_TEMP_DIR/processed_backup.sql"

# Remove commands that might cause issues during restore
cat "$BACKUP_FILE" | \
    grep -v "^REVOKE" | \
    grep -v "^GRANT" | \
    grep -v "^REASSIGN" | \
    grep -v "^DROP OWNED BY" | \
    grep -v "^DROP DATABASE" | \
    grep -v "^CREATE DATABASE" | \
    grep -v "^\\connect" > "$PROCESSED_BACKUP"

# Check if processed backup has content
if [ ! -s "$PROCESSED_BACKUP" ]; then
    error_exit "Processed backup file is empty"
fi

# Interactive confirmation
echo -e "${YELLOW}WARNING: This will overwrite the database $DB_NAME${NC}"
echo -e "${YELLOW}All current data will be lost!${NC}"
read -p "Are you sure you want to continue? (yes/no): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    log "Restore cancelled by user"
    exit 0
fi

# Check if database exists and drop it
log "Checking current database..."
if PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -lqt | cut -d \| -f 1 | grep -qw "$DB_NAME"; then
    log "Dropping existing database: $DB_NAME"
    PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres \
        -c "DROP DATABASE IF EXISTS $DB_NAME;" || error_exit "Failed to drop database"
fi

# Create new database
log "Creating new database: $DB_NAME"
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres \
    -c "CREATE DATABASE $DB_NAME;" || error_exit "Failed to create database"

# Restore the database
log "Restoring database from backup..."
START_TIME=$(date +%s)

if PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
    -f "$PROCESSED_BACKUP" >> "$RESTORE_LOG" 2>&1; then
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    log "${GREEN}Database restore completed successfully in ${DURATION} seconds${NC}"
    
    # Verify restore
    log "Verifying restore..."
    TABLE_COUNT=$(PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
        -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public';" | tr -d ' ')
    log "Tables restored: $TABLE_COUNT"
    
    # Check for critical tables
    CRITICAL_TABLES=("users" "products" "transactions")
    for table in "${CRITICAL_TABLES[@]}"; do
        if PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
            -t -c "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = '$table');" | grep -q t; then
            log "${GREEN}✓ Table '$table' exists${NC}"
        else
            log "${YELLOW}Warning: Table '$table' not found${NC}"
        fi
    done
    
else
    error_exit "Database restore failed. Check log: $RESTORE_LOG"
fi

# Cleanup
log "Cleaning up temporary files..."
rm -rf "$RESTORE_TEMP_DIR"
if [ "$COMPRESSED" = true ]; then
    rm -f "$TEMP_FILE"
fi

log "${GREEN}Restore process completed${NC}"
log "Restore log: $RESTORE_LOG"

# Display next steps
echo -e "\n${GREEN}Next steps:${NC}"
echo "1. Start the application: docker-compose up -d"
echo "2. Access the application: http://localhost:8501"
echo "3. Verify data in the application"
echo "4. Check restore log for details: $RESTORE_LOG"
