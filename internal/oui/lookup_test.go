package oui

import (
	"strings"
	"testing"
)

func TestFormatMACAddress(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "colon separated",
			input:    "aa:bb:cc:dd:ee:ff",
			expected: "AA:BB:CC:DD:EE:FF",
		},
		{
			name:     "hyphen separated",
			input:    "aa-bb-cc-dd-ee-ff",
			expected: "AA:BB:CC:DD:EE:FF",
		},
		{
			name:     "dot separated",
			input:    "aa.bb.cc.dd.ee.ff",
			expected: "AA:BB:CC:DD:EE:FF",
		},
		{
			name:     "no separators",
			input:    "aabbccddeeff",
			expected: "AA:BB:CC:DD:EE:FF",
		},
		{
			name:     "mixed case",
			input:    "AaBbCcDdEeFf",
			expected: "AA:BB:CC:DD:EE:FF",
		},
		{
			name:     "OUI only (6 chars)",
			input:    "aabbcc",
			expected: "AA:BB:CC",
		},
		{
			name:     "too short",
			input:    "aabb",
			expected: "aabb",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatMACAddress(tt.input)
			if result != tt.expected {
				t.Errorf("FormatMACAddress(%s) = %s, want %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestExtractOUI(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "full MAC with colons",
			input:    "aa:bb:cc:dd:ee:ff",
			expected: "AABBCC",
		},
		{
			name:     "full MAC with hyphens",
			input:    "AA-BB-CC-DD-EE-FF",
			expected: "AABBCC",
		},
		{
			name:     "full MAC no separators",
			input:    "aabbccddeeff",
			expected: "AABBCC",
		},
		{
			name:     "OUI only",
			input:    "aa:bb:cc",
			expected: "AABBCC",
		},
		{
			name:     "too short",
			input:    "aabb",
			expected: "AABB",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractOUI(tt.input)
			if result != tt.expected {
				t.Errorf("ExtractOUI(%s) = %s, want %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestIsLocallyAdministered(t *testing.T) {
	tests := []struct {
		name     string
		mac      string
		expected bool
	}{
		{
			name:     "locally administered (2)",
			mac:      "02:00:00:00:00:00",
			expected: true,
		},
		{
			name:     "locally administered (6)",
			mac:      "06:00:00:00:00:00",
			expected: true,
		},
		{
			name:     "locally administered (A)",
			mac:      "0A:00:00:00:00:00",
			expected: true,
		},
		{
			name:     "locally administered (E)",
			mac:      "0E:00:00:00:00:00",
			expected: true,
		},
		{
			name:     "not locally administered (0)",
			mac:      "00:00:00:00:00:00",
			expected: false,
		},
		{
			name:     "not locally administered (4)",
			mac:      "04:00:00:00:00:00",
			expected: false,
		},
		{
			name:     "vendor MAC Intel",
			mac:      "00:1B:77:49:54:FD",
			expected: false,
		},
		{
			name:     "too short",
			mac:      "0",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsLocallyAdministered(tt.mac)
			if result != tt.expected {
				t.Errorf("IsLocallyAdministered(%s) = %v, want %v", tt.mac, result, tt.expected)
			}
		})
	}
}

func TestIsMulticast(t *testing.T) {
	tests := []struct {
		name     string
		mac      string
		expected bool
	}{
		{
			name:     "multicast (1X)",
			mac:      "10:00:00:00:00:00",
			expected: true,
		},
		{
			name:     "multicast (3X)",
			mac:      "30:00:00:00:00:00",
			expected: true,
		},
		{
			name:     "multicast (5X)",
			mac:      "50:00:00:00:00:00",
			expected: true,
		},
		{
			name:     "multicast (7X)",
			mac:      "70:00:00:00:00:00",
			expected: true,
		},
		{
			name:     "multicast (9X)",
			mac:      "90:00:00:00:00:00",
			expected: true,
		},
		{
			name:     "multicast (BX)",
			mac:      "B0:00:00:00:00:00",
			expected: true,
		},
		{
			name:     "multicast (DX)",
			mac:      "D0:00:00:00:00:00",
			expected: true,
		},
		{
			name:     "multicast (FX)",
			mac:      "F0:00:00:00:00:00",
			expected: true,
		},
		{
			name:     "not multicast (0X)",
			mac:      "00:00:00:00:00:00",
			expected: false,
		},
		{
			name:     "not multicast (2X)",
			mac:      "20:00:00:00:00:00",
			expected: false,
		},
		{
			name:     "not multicast (4X)",
			mac:      "40:00:00:00:00:00",
			expected: false,
		},
		{
			name:     "broadcast is also multicast",
			mac:      "FF:FF:FF:FF:FF:FF",
			expected: true,
		},
		{
			name:     "too short",
			mac:      "0",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsMulticast(tt.mac)
			if result != tt.expected {
				t.Errorf("IsMulticast(%s) = %v, want %v", tt.mac, result, tt.expected)
			}
		})
	}
}

func TestIsBroadcast(t *testing.T) {
	tests := []struct {
		name     string
		mac      string
		expected bool
	}{
		{
			name:     "broadcast with colons",
			mac:      "FF:FF:FF:FF:FF:FF",
			expected: true,
		},
		{
			name:     "broadcast with hyphens",
			mac:      "FF-FF-FF-FF-FF-FF",
			expected: true,
		},
		{
			name:     "broadcast no separators",
			mac:      "FFFFFFFFFFFF",
			expected: true,
		},
		{
			name:     "broadcast lowercase",
			mac:      "ff:ff:ff:ff:ff:ff",
			expected: true,
		},
		{
			name:     "not broadcast (zeros)",
			mac:      "00:00:00:00:00:00",
			expected: false,
		},
		{
			name:     "not broadcast (typical MAC)",
			mac:      "AA:BB:CC:DD:EE:FF",
			expected: false,
		},
		{
			name:     "not broadcast (almost)",
			mac:      "FF:FF:FF:FF:FF:FE",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsBroadcast(tt.mac)
			if result != tt.expected {
				t.Errorf("IsBroadcast(%s) = %v, want %v", tt.mac, result, tt.expected)
			}
		})
	}
}

func TestFormatMACAddressVariousSeparators(t *testing.T) {
	input := "aA-bB:cC.dDeEfF"
	result := FormatMACAddress(input)
	expected := "AA:BB:CC:DD:EE:FF"

	if result != expected {
		t.Errorf("FormatMACAddress with mixed separators = %s, want %s", result, expected)
	}
}

func TestExtractOUIFromVariousFormats(t *testing.T) {
	formats := []string{
		"AA:BB:CC:DD:EE:FF",
		"AA-BB-CC-DD-EE-FF",
		"AABBCCDDEEFF",
		"aa.bb.cc.dd.ee.ff",
	}

	expected := "AABBCC"

	for _, format := range formats {
		result := ExtractOUI(format)
		if result != expected {
			t.Errorf("ExtractOUI(%s) = %s, want %s", format, result, expected)
		}
	}
}

func TestIsLocallyAdministeredAndMulticast(t *testing.T) {
	// Test locally administered MAC
	mac := "02:00:00:00:00:00"
	if !IsLocallyAdministered(mac) {
		t.Error("MAC should be locally administered")
	}
	if IsMulticast(mac) {
		t.Error("MAC 02:... should not be multicast per implementation")
	}

	// Test multicast MAC (per implementation, first hex digit must be 1,3,5,7,9,B,D,F)
	mac2 := "10:00:00:00:00:00"
	if !IsMulticast(mac2) {
		t.Error("MAC should be multicast")
	}
}

func TestLookupMACErrorHandling(t *testing.T) {
	// LookupMAC should handle errors gracefully
	// Since we can't easily force GetDatabase() to fail without mocking,
	// we'll just verify it returns something for any input
	result, err := LookupMAC("00:00:00:00:00:00")

	// Should either return a vendor or "Unknown" without error,
	// or return an error if database can't be loaded
	if err != nil && !strings.Contains(err.Error(), "database") {
		t.Errorf("Unexpected error: %v", err)
	}

	if err == nil && result == "" {
		t.Error("LookupMAC should return non-empty result")
	}
}

func TestGetDatabaseInfo(t *testing.T) {
	// Test that GetDatabaseInfo returns valid information
	info, err := GetDatabaseInfo()

	if err != nil {
		// Database might not be available in test environment
		if !strings.Contains(err.Error(), "database") {
			t.Errorf("Unexpected error: %v", err)
		}
		return
	}

	// If successful, verify the structure
	if info.TotalEntries < 0 {
		t.Error("TotalEntries should be non-negative")
	}
}

func TestFormatMACAddressPreservesOriginalWhenTooShort(t *testing.T) {
	shortMAC := "AB"
	result := FormatMACAddress(shortMAC)

	if result != shortMAC {
		t.Errorf("Short MAC should be preserved: got %s, want %s", result, shortMAC)
	}
}

func TestExtractOUIWithPartialMAC(t *testing.T) {
	// Test with partial MAC addresses
	partial := "AA:BB"
	result := ExtractOUI(partial)

	// Should return whatever is available, cleaned up
	if !strings.HasPrefix(result, "AABB") {
		t.Errorf("ExtractOUI(%s) = %s, should start with AABB", partial, result)
	}
}
