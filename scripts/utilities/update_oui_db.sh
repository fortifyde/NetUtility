#!/bin/sh

# OUI Database Update Script
# Downloads and updates the IEEE OUI database for MAC address vendor identification

. "$(dirname "$0")/../common/utils.sh"
. "$(dirname "$0")/../common/colors.sh" 2>/dev/null || true
. "$(dirname "$0")/../common/logging.sh"
SCRIPT_NAME="$(basename "$0")"

echo "=== OUI Database Update ==="
log_info "=== Script started ===" "$SCRIPT_NAME"
echo >&2

# Configuration
OUI_URL="https://standards-oui.ieee.org/oui/oui.txt"
DATA_DIR="$(dirname "$0")/../../data"
OUI_FILE="oui.txt"
TEMP_FILE="$(mktemp)"
BACKUP_FILE="oui_backup_$(date +%Y%m%d_%H%M%S).txt"

# Ensure directories exist
mkdir -p "$DATA_DIR"

# Cleanup on exit
trap 'rm -f "$TEMP_FILE"' EXIT

echo "Current OUI database status:"
if [ -f "$DATA_DIR/$OUI_FILE" ]; then
    file_size=$(stat -c%s "$DATA_DIR/$OUI_FILE" 2>/dev/null || stat -f%z "$DATA_DIR/$OUI_FILE" 2>/dev/null || echo "unknown")
    file_date=$(stat -c%y "$DATA_DIR/$OUI_FILE" 2>/dev/null | cut -d' ' -f1 || stat -f%Sm -t%Y-%m-%d "$DATA_DIR/$OUI_FILE" 2>/dev/null || echo "unknown")
    line_count=$(wc -l < "$DATA_DIR/$OUI_FILE" 2>/dev/null || echo "unknown")
    echo "  File: $DATA_DIR/$OUI_FILE"
    echo "  Size: $file_size bytes"
    echo "  Date: $file_date"
    echo "  Lines: $line_count"
else
    echo "  No existing database found"
fi
echo >&2

# Confirm update
echo "This will download the latest OUI database from IEEE Standards Association." >&2
echo "The database is typically 3-6 MB and contains ~30,000+ vendor entries." >&2
echo >&2
echo >&2
if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
    printf "%sDo you want to proceed with the update? [y/N]: %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
else
    printf "Do you want to proceed with the update? [y/N]: \n" >&2
fi
read -r response

case "$response" in
    [yY]|[yY][eE][sS])
        echo "Proceeding with OUI database update..." >&2
        ;;
    *)
        echo "Update cancelled." >&2
        exit 0
        ;;
esac

echo >&2

# Download the new database
echo "Downloading OUI database from IEEE..."
echo "Source: $OUI_URL"

if command -v wget >/dev/null 2>&1; then
    echo "Using wget for download..."
    log_debug "Running: wget -q --show-progress -O $TEMP_FILE $OUI_URL" "$SCRIPT_NAME"
    if ! wget -q --show-progress -O "$TEMP_FILE" "$OUI_URL"; then
        log_error "Failed to download OUI database with wget" "$SCRIPT_NAME"
        echo "ERROR: Failed to download OUI database with wget"
        exit 1
    fi
elif command -v curl >/dev/null 2>&1; then
    echo "Using curl for download..."
    log_debug "Running: curl -# -o $TEMP_FILE $OUI_URL" "$SCRIPT_NAME"
    if ! curl -# -o "$TEMP_FILE" "$OUI_URL"; then
        log_error "Failed to download OUI database with curl" "$SCRIPT_NAME"
        echo "ERROR: Failed to download OUI database with curl"
        exit 1
    fi
else
    log_error "Neither wget nor curl available for download" "$SCRIPT_NAME"
    echo "ERROR: Neither wget nor curl available for download"
    echo "Please install wget or curl to update the OUI database"
    exit 1
fi

# Validate downloaded file
echo >&2
echo "Validating downloaded file..."

if [ ! -s "$TEMP_FILE" ]; then
    log_error "Downloaded file is empty" "$SCRIPT_NAME"
    echo "ERROR: Downloaded file is empty"
    exit 1
fi

# Check file size (should be at least 1MB for a valid OUI database)
file_size=$(stat -c%s "$TEMP_FILE" 2>/dev/null || stat -f%z "$TEMP_FILE" 2>/dev/null || echo "0")
if [ "$file_size" -lt 1048576 ]; then
    log_error "Downloaded file is too small: $file_size bytes" "$SCRIPT_NAME"
    echo "ERROR: Downloaded file is too small ($file_size bytes) - may be corrupted"
    exit 1
fi

# Check for expected header content
if ! head -10 "$TEMP_FILE" | grep -q "OUI/MA-L"; then
    log_error "Downloaded file is not a valid OUI database" "$SCRIPT_NAME"
    echo "ERROR: Downloaded file doesn't appear to be a valid OUI database"
    echo "First 10 lines:"
    head -10 "$TEMP_FILE"
    exit 1
fi

# Count entries
new_line_count=$(wc -l < "$TEMP_FILE")
echo "Downloaded file validation:"
echo "  Size: $file_size bytes"
echo "  Lines: $new_line_count"

if [ "$new_line_count" -lt 10000 ]; then
    log_warn "Downloaded file has fewer lines than expected: $new_line_count" "$SCRIPT_NAME"
    echo "WARNING: Downloaded file has fewer lines than expected" >&2
    echo >&2
    if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
        printf "%sDo you want to continue anyway? [y/N]: %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
    else
        printf "Do you want to continue anyway? [y/N]: \n" >&2
    fi
    read -r response
    case "$response" in
        [yY]|[yY][eE][sS])
            echo "Continuing with installation..." >&2
            ;;
        *)
            echo "Update cancelled." >&2
            exit 1
            ;;
    esac
fi

# Backup existing database if it exists
if [ -f "$DATA_DIR/$OUI_FILE" ]; then
    echo >&2
    echo "Creating backup of existing database..."
    if cp "$DATA_DIR/$OUI_FILE" "$DATA_DIR/$BACKUP_FILE"; then
        echo "Backup saved as: $DATA_DIR/$BACKUP_FILE"
        log_info "OUI database backup created: $DATA_DIR/$BACKUP_FILE" "$SCRIPT_NAME"
    else
        echo "WARNING: Failed to create backup"
    fi
fi

# Install new database
echo >&2
echo "Installing new OUI database..."

# Update the main database file
if cp "$TEMP_FILE" "$DATA_DIR/$OUI_FILE"; then
    echo "Updated: $DATA_DIR/$OUI_FILE"
else
    log_error "Failed to install OUI database to $DATA_DIR/$OUI_FILE" "$SCRIPT_NAME"
    echo "ERROR: Failed to update $DATA_DIR/$OUI_FILE"
    exit 1
fi

echo "Note: The Go binary ouihelper will use the embedded database until rebuilt."
echo "To use the updated database immediately, rebuild the project with 'go build -o ouihelper cmd/ouihelper/main.go'."

# Show summary
echo >&2
echo "=== Update Complete ==="
echo "New database statistics:"
echo "  Location: $DATA_DIR/$OUI_FILE"
echo "  Size: $file_size bytes"
echo "  Lines: $new_line_count"
echo "  Updated: $(date)"

if [ -f "$DATA_DIR/$BACKUP_FILE" ]; then
    echo "  Backup: $DATA_DIR/$BACKUP_FILE"
fi

echo >&2
echo "The OUI database has been successfully updated."
log_info "OUI database updated successfully: $DATA_DIR/$OUI_FILE ($new_line_count lines)" "$SCRIPT_NAME"

# Clean up old backups (keep only last 5)
echo >&2
echo "Cleaning up old backups..."
backup_count=$(find "$DATA_DIR" -name "oui_backup_*.txt" | wc -l)
if [ "$backup_count" -gt 5 ]; then
    find "$DATA_DIR" -name "oui_backup_*.txt" | sort | head -n $((backup_count - 5)) | while read -r old_backup; do
        echo "Removing old backup: $(basename "$old_backup")"
        rm -f "$old_backup"
    done
fi

echo >&2
echo "Update completed successfully!"
