package jobs

import (
	"regexp"
	"strings"
)

// ansiEscape matches terminal color/attribute escape sequences.
var ansiEscape = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// StripANSI removes terminal escape sequences from a string.
func StripANSI(s string) string {
	return ansiEscape.ReplaceAllString(s, "")
}

// ipPattern matches dotted-decimal sequences like "192.168".
var ipPattern = regexp.MustCompile(`\d+\.\d+`)

// keyValuePair matches "Label: value" patterns (structured output, not prompts).
var keyValuePair = regexp.MustCompile(`^[A-Za-z_ ]+:\s*\S`)

// DetectScriptPrompt checks whether a line of script output looks like
// an interactive prompt waiting for user input. This is the shared
// detection logic used by both the Job manager's progress scanner and
// the UI OutputViewer so that prompt state is tracked at the Job level.
func DetectScriptPrompt(content string) bool {
	lower := strings.ToLower(content)

	// Common interactive prompt phrases.
	phrases := []string{
		"enter selection",
		"choose option",
		"select option",
		"enter choice",
		"enter number",
		"enter option",
		"please select",
		"your choice",
		"enter your",
		"type your",
		"(default:",
		", default:",
	}
	for _, p := range phrases {
		if strings.Contains(lower, p) {
			return true
		}
	}

	// y/n confirmation patterns.
	confirmPatterns := []string{
		"[y/n]", "[y/N]", "[Y/n]", "[n/y]", "[n/Y]", "[N/y]",
		"(y/n)", "(y/N)", "(Y/n)", "(n/y)",
	}
	for _, p := range confirmPatterns {
		if strings.Contains(content, p) {
			return true
		}
	}

	// Short lines ending with ": " are often prompts, but exclude
	// common false positives (headers, IP addresses).
	trimmed := strings.TrimSpace(content)
	if len(trimmed) <= 40 &&
		(strings.HasSuffix(trimmed, ":") || strings.HasSuffix(trimmed, ": ")) &&
		!strings.Contains(trimmed, "===") &&
		!strings.Contains(trimmed, "---") &&
		!ipPattern.MatchString(trimmed) &&
		!strings.HasPrefix(trimmed, "+") &&
		!strings.HasPrefix(trimmed, "|") &&
		!strings.Contains(strings.ToUpper(trimmed), "VULNERABLE") &&
		!keyValuePair.MatchString(trimmed) {
		return true
	}

	return false
}

// DetectPasswordPrompt checks whether a line of script output is asking
// for a password or passphrase.
func DetectPasswordPrompt(content string) bool {
	lower := strings.ToLower(content)
	patterns := []string{
		"password:",
		"password ",
		"confirm password",
		"enter password",
		"passphrase:",
	}
	for _, p := range patterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}
