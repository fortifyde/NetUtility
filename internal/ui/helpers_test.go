package ui

import (
	"testing"
)

func TestWrapTextEmpty(t *testing.T) {
	result := wrapText("", 80)
	if len(result) != 1 || result[0] != "" {
		t.Errorf("wrapText empty = %v, want [\"\"]", result)
	}
}

func TestWrapTextZeroWidth(t *testing.T) {
	result := wrapText("hello", 0)
	if len(result) != 1 || result[0] != "hello" {
		t.Errorf("wrapText zero width = %v, want [\"hello\"]", result)
	}
}

func TestWrapTextNegativeWidth(t *testing.T) {
	result := wrapText("hello", -5)
	if len(result) != 1 || result[0] != "hello" {
		t.Errorf("wrapText negative width = %v, want [\"hello\"]", result)
	}
}

func TestWrapTextShortString(t *testing.T) {
	result := wrapText("hello world", 80)
	if len(result) != 1 || result[0] != "hello world" {
		t.Errorf("wrapText short = %v, want [\"hello world\"]", result)
	}
}

func TestWrapTextExactWidth(t *testing.T) {
	text := "hello"
	result := wrapText(text, 5)
	if len(result) != 1 || result[0] != "hello" {
		t.Errorf("wrapText exact = %v, want [\"hello\"]", result)
	}
}

func TestWrapTextBreakAtSpace(t *testing.T) {
	text := "hello world"
	result := wrapText(text, 7)
	if len(result) != 2 {
		t.Fatalf("wrapText = %v, want 2 lines", result)
	}
	if result[0] != "hello" {
		t.Errorf("line[0] = %q, want %q", result[0], "hello")
	}
	if result[1] != "world" {
		t.Errorf("line[1] = %q, want %q", result[1], "world")
	}
}

func TestWrapTextLongWord(t *testing.T) {
	text := "abcdefghij"
	result := wrapText(text, 5)
	if len(result) != 2 {
		t.Fatalf("wrapText long word = %v, want 2 lines", result)
	}
	if result[0] != "abcde" {
		t.Errorf("line[0] = %q, want %q", result[0], "abcde")
	}
	if result[1] != "fghij" {
		t.Errorf("line[1] = %q, want %q", result[1], "fghij")
	}
}

func TestWrapTextUnicode(t *testing.T) {
	text := "héllo wörld test"
	result := wrapText(text, 8)
	if len(result) < 2 {
		t.Fatalf("wrapText unicode = %v, expected at least 2 lines", result)
	}
}

func TestWrapTextMultipleSpaces(t *testing.T) {
	text := "hello   world   foo"
	result := wrapText(text, 10)
	// Leading spaces after cut should be trimmed
	for _, line := range result {
		if len(line) > 0 && line[0] == ' ' {
			t.Errorf("line should not start with space: %q", line)
		}
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
		{"192.168.1.1", "10.0.0.1", false},
		{"192.168.1.1", "192.168.1.1", false},
		{"172.16.0.1", "172.16.1.1", true},
	}

	for _, tt := range tests {
		t.Run(tt.ip1+"_vs_"+tt.ip2, func(t *testing.T) {
			if got := compareIPs(tt.ip1, tt.ip2); got != tt.want {
				t.Errorf("compareIPs(%q, %q) = %v, want %v", tt.ip1, tt.ip2, got, tt.want)
			}
		})
	}
}

func TestFormatCategoryNameDefaults(t *testing.T) {
	tui := &TUI{str: stringsEN}

	tests := []struct {
		input string
		want  string
	}{
		{"", ""},
		{"a", "A"},
		{"my-category", "My-category"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := tui.formatCategoryName(tt.input); got != tt.want {
				t.Errorf("formatCategoryName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
