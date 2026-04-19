package ui

import (
	"testing"

	"netutil/internal/correlation"
)

func TestHostCategory(t *testing.T) {
	tests := []struct {
		name   string
		result *correlation.CorrelationResult
		want   string
	}{
		{
			name:   "nil HostInfo returns unknown",
			result: &correlation.CorrelationResult{},
			want:   "unknown",
		},
		{
			name: "category attribute returned",
			result: &correlation.CorrelationResult{
				HostInfo: &correlation.Host{
					Attributes: map[string]string{"category": "windows"},
				},
			},
			want: "windows",
		},
		{
			name: "empty category returns unknown",
			result: &correlation.CorrelationResult{
				HostInfo: &correlation.Host{
					Attributes: map[string]string{"category": ""},
				},
			},
			want: "unknown",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hostCategory(tt.result); got != tt.want {
				t.Errorf("hostCategory() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHostVendor(t *testing.T) {
	if got := hostVendor(&correlation.CorrelationResult{}); got != "-" {
		t.Errorf("hostVendor(nil HostInfo) = %q, want -", got)
	}
	r := &correlation.CorrelationResult{
		HostInfo: &correlation.Host{Attributes: map[string]string{"vendor": "Cisco"}},
	}
	if got := hostVendor(r); got != "Cisco" {
		t.Errorf("hostVendor() = %q, want Cisco", got)
	}
}

func TestHostHostname(t *testing.T) {
	r := &correlation.CorrelationResult{
		HostInfo: &correlation.Host{
			Hostname:   "router.local",
			Attributes: map[string]string{"netbios_name": "ROUTER"},
		},
	}
	if got := hostHostname(r); got != "router.local" {
		t.Errorf("hostHostname() = %q, want router.local", got)
	}
	r.HostInfo.Hostname = ""
	if got := hostHostname(r); got != "ROUTER" {
		t.Errorf("hostHostname() fallback = %q, want ROUTER", got)
	}
	r.HostInfo.Attributes = nil
	if got := hostHostname(r); got != "-" {
		t.Errorf("hostHostname() empty = %q, want -", got)
	}
}

func TestHostOpenPorts(t *testing.T) {
	if got := hostOpenPorts(&correlation.CorrelationResult{}); got != "-" {
		t.Errorf("hostOpenPorts(nil HostInfo) = %q, want -", got)
	}
	r := &correlation.CorrelationResult{
		HostInfo: &correlation.Host{
			Ports: []correlation.Port{
				{Number: 22, State: "open"},
				{Number: 80, State: "open"},
				{Number: 443, State: "filtered"},
			},
		},
	}
	if got := hostOpenPorts(r); got != "22,80" {
		t.Errorf("hostOpenPorts() = %q, want 22,80", got)
	}
}

func TestCategoryOrder(t *testing.T) {
	if categoryOrder("windows") >= categoryOrder("linux") {
		t.Error("windows should sort before linux")
	}
	if categoryOrder("linux") >= categoryOrder("network_device") {
		t.Error("linux should sort before network_device")
	}
	if categoryOrder("network_device") >= categoryOrder("unknown") {
		t.Error("network_device should sort before unknown")
	}
}

func TestCompareIPs(t *testing.T) {
	tests := []struct {
		ip1, ip2 string
		want     bool
	}{
		{"192.168.1.1", "192.168.1.2", true},
		{"192.168.1.2", "192.168.1.1", false},
		{"10.0.0.1", "192.168.1.1", true},
		{"192.168.1.1", "192.168.1.1", false},
	}
	for _, tt := range tests {
		if got := compareIPs(tt.ip1, tt.ip2); got != tt.want {
			t.Errorf("compareIPs(%q, %q) = %v, want %v", tt.ip1, tt.ip2, got, tt.want)
		}
	}
}

func TestHostOpenPortsTruncation(t *testing.T) {
	// Build a host with many open ports so the joined string exceeds 22 runes
	var ports []correlation.Port
	for i := 1; i <= 20; i++ {
		ports = append(ports, correlation.Port{Number: i * 1000, State: "open"})
	}
	r := &correlation.CorrelationResult{
		HostInfo: &correlation.Host{Ports: ports},
	}
	got := hostOpenPorts(r)
	runes := []rune(got)
	if len(runes) > 22 {
		t.Errorf("hostOpenPorts() length = %d, want ≤22 runes; got %q", len(runes), got)
	}
	if len(runes) > 0 && runes[len(runes)-1] != '…' {
		t.Errorf("hostOpenPorts() should end with …, got %q", got)
	}
}

func TestHostMatchesText(t *testing.T) {
	result := &correlation.CorrelationResult{
		Host: "192.168.1.50",
		HostInfo: &correlation.Host{
			Hostname: "webserver.local",
			Attributes: map[string]string{
				"netbios_name": "WEBSERVER",
			},
			Ports: []correlation.Port{
				{Number: 80, State: "open", Service: "http"},
				{Number: 443, State: "open", Service: "https"},
				{Number: 22, State: "closed", Service: "ssh"},
			},
		},
	}

	tests := []struct {
		query string
		want  bool
	}{
		// IP match
		{"192.168", true},
		{"192.168.1.50", true},
		// Hostname match
		{"webserver", true},
		{"WEBSERVER.LOCAL", true}, // case-insensitive
		// NetBIOS match
		{"webserv", true},
		// Port number match (open ports only)
		{"80", true},
		{"443", true},
		{"22", false}, // port 22 is closed — should not match
		// Service name match (open ports only)
		{"http", true},
		{"https", true},
		{"ssh", false}, // ssh is on a closed port — should not match
		// No match
		{"10.0.0.1", false},
		{"ftp", false},
		// Empty query always matches
		{"", true},
	}

	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			got := hostMatchesText(result.Host, result, tt.query)
			if got != tt.want {
				t.Errorf("hostMatchesText(%q) = %v, want %v", tt.query, got, tt.want)
			}
		})
	}
}

func TestHostMatchesTextNilHostInfo(t *testing.T) {
	result := &correlation.CorrelationResult{Host: "10.0.0.1"}
	if !hostMatchesText(result.Host, result, "") {
		t.Error("empty query with nil HostInfo should return true")
	}
	if !hostMatchesText(result.Host, result, "10.0") {
		t.Error("IP match with nil HostInfo should return true")
	}
	if hostMatchesText(result.Host, result, "webserver") {
		t.Error("non-IP query with nil HostInfo should return false")
	}
}
