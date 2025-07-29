package oui

import (
	"fmt"
	"strings"
)

// LookupMAC is a convenience function for looking up a single MAC address vendor
func LookupMAC(macAddress string) (string, error) {
	db, err := GetDatabase()
	if err != nil {
		return "Unknown", fmt.Errorf("failed to get OUI database: %w", err)
	}

	vendor := db.LookupVendor(macAddress)
	return vendor, nil
}

// GetDatabaseInfo returns information about the current OUI database
func GetDatabaseInfo() (DatabaseInfo, error) {
	db, err := GetDatabase()
	if err != nil {
		return DatabaseInfo{}, fmt.Errorf("failed to get OUI database: %w", err)
	}

	return db.GetInfo(), nil
}

// FormatMACAddress standardizes MAC address format for display
func FormatMACAddress(macAddress string) string {
	// Remove all separators and convert to uppercase
	clean := strings.ReplaceAll(macAddress, ":", "")
	clean = strings.ReplaceAll(clean, "-", "")
	clean = strings.ReplaceAll(clean, ".", "")
	clean = strings.ToUpper(clean)

	// If we have at least 12 characters, format as XX:XX:XX:XX:XX:XX
	if len(clean) >= 12 {
		return fmt.Sprintf("%s:%s:%s:%s:%s:%s",
			clean[0:2], clean[2:4], clean[4:6],
			clean[6:8], clean[8:10], clean[10:12])
	}

	// If we have at least 6 characters, format the OUI part as XX:XX:XX
	if len(clean) >= 6 {
		return fmt.Sprintf("%s:%s:%s", clean[0:2], clean[2:4], clean[4:6])
	}

	// Return original if too short
	return macAddress
}

// ExtractOUI extracts just the OUI (first 3 octets) from a MAC address
func ExtractOUI(macAddress string) string {
	// Clean MAC address
	clean := strings.ReplaceAll(macAddress, ":", "")
	clean = strings.ReplaceAll(clean, "-", "")
	clean = strings.ReplaceAll(clean, ".", "")
	clean = strings.ToUpper(clean)

	// Return first 6 characters (3 octets)
	if len(clean) >= 6 {
		return clean[:6]
	}

	return clean
}

// IsLocallyAdministered checks if a MAC address is locally administered
func IsLocallyAdministered(macAddress string) bool {
	oui := ExtractOUI(macAddress)
	if len(oui) < 2 {
		return false
	}

	// Check the second character of the first octet
	// Locally administered addresses have the second bit set (2, 6, A, E)
	secondChar := oui[1]
	return secondChar == '2' || secondChar == '6' || secondChar == 'A' || secondChar == 'E'
}

// IsMulticast checks if a MAC address is a multicast address
func IsMulticast(macAddress string) bool {
	oui := ExtractOUI(macAddress)
	if len(oui) < 2 {
		return false
	}

	// Check the first character of the first octet
	// Multicast addresses have the first bit set (1, 3, 5, 7, 9, B, D, F)
	firstChar := oui[0]
	return firstChar == '1' || firstChar == '3' || firstChar == '5' || firstChar == '7' ||
		firstChar == '9' || firstChar == 'B' || firstChar == 'D' || firstChar == 'F'
}

// IsBroadcast checks if a MAC address is the broadcast address
func IsBroadcast(macAddress string) bool {
	clean := strings.ReplaceAll(macAddress, ":", "")
	clean = strings.ReplaceAll(clean, "-", "")
	clean = strings.ReplaceAll(clean, ".", "")
	clean = strings.ToUpper(clean)

	return clean == "FFFFFFFFFFFF"
}
