package ui

import "testing"

func TestFormatCategoryName(t *testing.T) {
	tui := &TUI{}
	tests := []struct {
		key  string
		want string
	}{
		{"advanced", "Advanced Tools"},
		{"scanning", "Port Scanning"},
		{"host-config", "Host Configuration"},
		{"utilities", "System Utilities"},
		{"discovery", "Network Discovery"},
		{"unknown-key", "Unknown-key"},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			if got := tui.formatCategoryName(tt.key); got != tt.want {
				t.Errorf("formatCategoryName(%q) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}
