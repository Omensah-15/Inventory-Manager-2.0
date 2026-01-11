#!/bin/bash

# InvyPro Database Backup Script
# Run manually or schedule with cron

set -e

# Configuration
BACKUP_DIR="./backups"
LOG_DIR="./logs"
RETENTION_DAYS=30
COMPRESS=true
BACKUP_PREFIX="invypro_backup"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Timestamp
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/${BACKUP_PREFIX}_${TIMESTAMP}.sql"
LOG_FILE="$LOG_DIR/backup_${TIMESTAMP}.log"

# Log function
log() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Error handler
error_exit() {
    log "${RED}ERROR: $1${NC}"
    exit 1
}

# Ensure directories exist
mkdir -p "$BACKUP_DIR" "$LOG_DIR"

log "${GREEN}Starting database backup...${NC}"

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
log "Backup file: $BACKUP_FILE"

# Test database connection
log "Testing database connection..."
if ! PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "\q" >/dev/null 2>&1; then
    error_exit "Cannot connect to database"
fi

# Get database size
log "Checking database size..."
DB_SIZE=$(PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
    -t -c "SELECT pg_size_pretty(pg_database_size('$DB_NAME'));" | tr -d ' ')
log "Database size: $DB_SIZE"

# Create backup
log "Creating backup..."
START_TIME=$(date +%s)

if PGPASSWORD="$DB_PASSWORD" pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
    --clean --if-exists --no-owner --no-privileges \
    --format=plain --file="$BACKUP_FILE" 2>> "$LOG_FILE"; then
    
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    
    BACKUP_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
    log "${GREEN}Backup created successfully${NC}"
    log "Backup size: $BACKUP_SIZE"
    log "Duration: ${DURATION} seconds"
    
else
    error_exit "Backup failed. Check log: $LOG_FILE"
fi

# Verify backup
log "Verifying backup..."
if [ -s "$BACKUP_FILE" ]; then
    # Check if backup contains data
    if grep -q "CREATE TABLE" "$BACKUP_FILE"; then
        TABLE_COUNT=$(grep -c "CREATE TABLE" "$BACKUP_FILE")
        log "Backup contains $TABLE_COUNT tables"
    else
        log "${YELLOW}Warning: Backup file does not contain CREATE TABLE statements${NC}"
    fi
    
    # Check for critical tables
    CRITICAL_TABLES=("users" "products" "transactions")
    for table in "${CRITICAL_TABLES[@]}"; do
        if grep -q "CREATE TABLE $table" "$BACKUP_FILE"; then
            log "${GREEN}✓ Table '$table' backed up${NC}"
        else
            log "${YELLOW}Warning: Table '$table' not found in backup${NC}"
        fi
    done
else
    error_exit "Backup file is empty"
fi

# Compress backup if enabled
if [ "$COMPRESS" = true ]; then
    log "Compressing backup..."
    gzip "$BACKUP_FILE"
    BACKUP_FILE="$BACKUP_FILE.gz"
    BACKUP_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
    log "Compressed backup size: $BACKUP_SIZE"
fi

# Cleanup old backups
log "Cleaning up old backups (retention: $RETENTION_DAYS days)..."
find "$BACKUP_DIR" -name "${BACKUP_PREFIX}_*.sql*" -type f -mtime +$RETENTION_DAYS -delete
OLD_BACKUPS_COUNT=$(find "$BACKUP_DIR" -name "${BACKUP_PREFIX}_*.sql*" -type f -mtime +$RETENTION_DAYS | wc -l)
if [ "$OLD_BACKUPS_COUNT" -gt 0 ]; then
    log "Removed $OLD_BACKUPS_COUNT old backup(s)"
fi

# Show backup summary
log "${GREEN}Backup completed successfully${NC}"
log "Backup file: $BACKUP_FILE"
log "Backup size: $BACKUP_SIZE"
log "Log file: $LOG_FILE"

# List all backups
log "Current backups:"
ls -lh "$BACKUP_DIR"/${BACKUP_PREFIX}_*.sql* 2>/dev/null || log "No backups found"

# Calculate next backup time (if scheduled)
log "${YELLOW}To schedule automatic backups, add to crontab:${NC}"
echo "0 2 * * * /path/to/invypro-postgres/scripts/backup_db.sh"

exit 0
