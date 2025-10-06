#!/bin/bash
# Backup Rotation Script
# Author: Suresh Chand
# Description: Archives logs, rotates daily, keeps 7 days of history.

LOG_DIR="/var/log/myapp"
BACKUP_DIR="/var/backups/myapp"
DATE=$(date +%F)

# Ensure backup directory exists
mkdir -p "$BACKUP_DIR"

# Create archive
tar -czf "$BACKUP_DIR/logs_$DATE.tar.gz" "$LOG_DIR"

# Delete backups older than 7 days
find "$BACKUP_DIR" -type f -name "logs_*.tar.gz" -mtime +7 -exec rm {} \;

echo "✅ Backup created: $BACKUP_DIR/logs_$DATE.tar.gz"
