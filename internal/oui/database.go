package oui

import (
	"bufio"
	"embed"
	"fmt"
	"strings"
	"sync"
	"time"
)

//go:embed data/oui.txt
var embeddedDB embed.FS

// Database represents the OUI database with fast lookup capabilities
type Database struct {
	vendors    map[string]string
	lastUpdate time.Time
	mu         sync.RWMutex
}

// DatabaseInfo provides metadata about the OUI database
type DatabaseInfo struct {
	TotalEntries int       `json:"total_entries"`
	LastUpdate   time.Time `json:"last_update"`
	Source       string    `json:"source"`
	Version      string    `json:"version"`
}

var (
	globalDB *Database
	once     sync.Once
)

// GetDatabase returns the global OUI database instance
func GetDatabase() (*Database, error) {
	var err error
	once.Do(func() {
		globalDB, err = loadEmbeddedDatabase()
	})
	return globalDB, err
}

// loadEmbeddedDatabase loads the embedded OUI database into memory
func loadEmbeddedDatabase() (*Database, error) {
	file, err := embeddedDB.Open("data/oui.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to open embedded OUI database: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			// Log error but don't fail the function since we're in defer
		}
	}()

	db := &Database{
		vendors:    make(map[string]string),
		lastUpdate: time.Now(),
	}

	scanner := bufio.NewScanner(file)
	var currentOUI string
	var currentVendor string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip header lines and empty lines
		if line == "" || strings.Contains(line, "company_id") || strings.Contains(line, "OUI/MA-L") {
			continue
		}

		// Check if this is an OUI line (contains "(hex)")
		if strings.Contains(line, "(hex)") {
			// Parse OUI and vendor name
			parts := strings.SplitN(line, "(hex)", 2)
			if len(parts) == 2 {
				currentOUI = strings.TrimSpace(parts[0])
				currentVendor = strings.TrimSpace(parts[1])

				// Clean up OUI format (remove hyphens, convert to uppercase)
				currentOUI = strings.ReplaceAll(currentOUI, "-", "")
				currentOUI = strings.ToUpper(currentOUI)

				// Store in database (use first 6 characters for MAC prefix)
				if len(currentOUI) >= 6 {
					ouiPrefix := currentOUI[:6]
					db.vendors[ouiPrefix] = currentVendor
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading embedded OUI database: %w", err)
	}

	return db, nil
}

// LookupVendor returns the vendor name for a given MAC address prefix
func (db *Database) LookupVendor(macAddress string) string {
	db.mu.RLock()
	defer db.mu.RUnlock()

	// Clean MAC address - remove common separators and convert to uppercase
	cleanMAC := strings.ReplaceAll(macAddress, ":", "")
	cleanMAC = strings.ReplaceAll(cleanMAC, "-", "")
	cleanMAC = strings.ReplaceAll(cleanMAC, ".", "")
	cleanMAC = strings.ToUpper(cleanMAC)

	// Extract OUI (first 6 characters)
	if len(cleanMAC) < 6 {
		return "Unknown"
	}

	ouiPrefix := cleanMAC[:6]
	if vendor, exists := db.vendors[ouiPrefix]; exists {
		return vendor
	}

	return "Unknown"
}

// GetInfo returns metadata about the database
func (db *Database) GetInfo() DatabaseInfo {
	db.mu.RLock()
	defer db.mu.RUnlock()

	return DatabaseInfo{
		TotalEntries: len(db.vendors),
		LastUpdate:   db.lastUpdate,
		Source:       "IEEE Standards Association",
		Version:      "embedded",
	}
}

// GetVendorCount returns the total number of vendors in the database
func (db *Database) GetVendorCount() int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return len(db.vendors)
}

// SearchVendors returns vendors matching the search query
func (db *Database) SearchVendors(query string) map[string]string {
	db.mu.RLock()
	defer db.mu.RUnlock()

	results := make(map[string]string)

	// Return empty results for empty query
	if strings.TrimSpace(query) == "" {
		return results
	}

	queryLower := strings.ToLower(query)

	for oui, vendor := range db.vendors {
		if strings.Contains(strings.ToLower(vendor), queryLower) {
			results[oui] = vendor
		}
		// Limit results to prevent memory issues
		if len(results) >= 100 {
			break
		}
	}

	return results
}

// ReloadFromFile reloads the database from an external file (for updates)
func (db *Database) ReloadFromFile(filepath string) error {
	// This will be implemented for the update functionality
	// For now, return an error indicating this is not yet implemented
	return fmt.Errorf("database reload from file not yet implemented")
}
