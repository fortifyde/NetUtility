#!/bin/sh

# OUI Database Update Script
# Downloads and updates the IEEE OUI database for MAC address vendor identification

. "$(dirname "$0")/../common/utils.sh"

echo "=== OUI Database Update ==="
echo

# Configuration
OUI_URL="http://standards-oui.ieee.org/oui/oui.txt"
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
echo

# Confirm update
echo "This will download the latest OUI database from IEEE Standards Association." >&2
echo "The database is typically 3-6 MB and contains ~30,000+ vendor entries." >&2
echo >&2
echo "Do you want to proceed with the update? [y/N]: " >&2
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

echo

# Download the new database
echo "Downloading OUI database from IEEE..."
echo "Source: $OUI_URL"

if command -v wget >/dev/null 2>&1; then
    echo "Using wget for download..."
    if ! wget -q --show-progress -O "$TEMP_FILE" "$OUI_URL"; then
        echo "ERROR: Failed to download OUI database with wget"
        exit 1
    fi
elif command -v curl >/dev/null 2>&1; then
    echo "Using curl for download..."
    if ! curl -# -o "$TEMP_FILE" "$OUI_URL"; then
        echo "ERROR: Failed to download OUI database with curl"
        exit 1
    fi
else
    echo "ERROR: Neither wget nor curl available for download"
    echo "Please install wget or curl to update the OUI database"
    exit 1
fi

# Validate downloaded file
echo
echo "Validating downloaded file..."

if [ ! -s "$TEMP_FILE" ]; then
    echo "ERROR: Downloaded file is empty"
    exit 1
fi

# Check file size (should be at least 1MB for a valid OUI database)
file_size=$(stat -c%s "$TEMP_FILE" 2>/dev/null || stat -f%z "$TEMP_FILE" 2>/dev/null || echo "0")
if [ "$file_size" -lt 1048576 ]; then
    echo "ERROR: Downloaded file is too small ($file_size bytes) - may be corrupted"
    exit 1
fi

# Check for expected header content
if ! head -10 "$TEMP_FILE" | grep -q "OUI/MA-L"; then
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
    echo "WARNING: Downloaded file has fewer lines than expected" >&2
    echo "Do you want to continue anyway? [y/N]: " >&2
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
    echo
    echo "Creating backup of existing database..."
    if cp "$DATA_DIR/$OUI_FILE" "$DATA_DIR/$BACKUP_FILE"; then
        echo "Backup saved as: $DATA_DIR/$BACKUP_FILE"
    else
        echo "WARNING: Failed to create backup"
    fi
fi

# Install new database
echo
echo "Installing new OUI database..."

# Update the main database file
if cp "$TEMP_FILE" "$DATA_DIR/$OUI_FILE"; then
    echo "Updated: $DATA_DIR/$OUI_FILE"
else
    echo "ERROR: Failed to update $DATA_DIR/$OUI_FILE"
    exit 1
fi

echo "Note: The Go binary ouihelper will use the embedded database until rebuilt."
echo "To use the updated database immediately, rebuild the project with 'go build -o ouihelper cmd/ouihelper/main.go'."

# Show summary
echo
echo "=== Update Complete ==="
echo "New database statistics:"
echo "  Location: $DATA_DIR/$OUI_FILE"
echo "  Size: $file_size bytes"
echo "  Lines: $new_line_count"
echo "  Updated: $(date)"

if [ -f "$DATA_DIR/$BACKUP_FILE" ]; then
    echo "  Backup: $DATA_DIR/$BACKUP_FILE"
fi

echo
echo "The OUI database has been successfully updated."

# Clean up old backups (keep only last 5)
echo
echo "Cleaning up old backups..."
backup_count=$(find "$DATA_DIR" -name "oui_backup_*.txt" | wc -l)
if [ "$backup_count" -gt 5 ]; then
    find "$DATA_DIR" -name "oui_backup_*.txt" | sort | head -n $((backup_count - 5)) | while read -r old_backup; do
        echo "Removing old backup: $(basename "$old_backup")"
        rm -f "$old_backup"
    done
fi

echo
echo "Update completed successfully!"
