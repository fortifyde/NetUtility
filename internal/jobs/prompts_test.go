package jobs

import (
	"strings"
	"testing"
)

func TestDetectScriptPrompt(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    bool
		comment string
	}{
		// --- True positives: actual interactive prompts ---
		{name: "enter selection", input: "Enter selection: ", want: true},
		{name: "choose option", input: "Please choose option [1-5]:", want: true},
		{name: "select option", input: "Select option: ", want: true},
		{name: "enter choice", input: "Enter your choice: ", want: true},
		{name: "enter number", input: "Enter number: ", want: true},
		{name: "please select", input: "Please select an interface:", want: true},
		{name: "your choice", input: "Your choice: ", want: true},
		{name: "enter your", input: "Enter your name: ", want: true},
		{name: "type your", input: "Type your response:", want: true},
		{name: "default in parens", input: "Interface (default: eth0):", want: true},
		{name: "default with comma", input: "Port, default: 80:", want: true},
		{name: "yn bracket lower", input: "Continue? [y/n]", want: true},
		{name: "yn bracket mixed", input: "Continue? [Y/n]", want: true},
		{name: "yn parens", input: "Continue? (y/n)", want: true},
		{name: "colon prompt short", input: "Enter IP address:", want: true},
		{name: "colon prompt with space", input: "Hostname: ", want: true},
		{name: "simple colon prompt", input: "Selection:", want: true},

		// --- True negatives: tool output lines that don't end with colon ---
		// (Lines ending with ":" are detected as prompts since we only check stderr.
		// Stdout tool output like these never reaches DetectScriptPrompt.)
		{name: "nikto cipher line", input: "+ Preferred Cipher: TLS_AES_256", want: false, comment: "no trailing colon"},
		{name: "nmap nse pipe value", input: "|   State: LIKELY VULNERABLE", want: false, comment: "no trailing colon"},
		{name: "structured key value", input: "Preferred Cipher: TLS_AES_256", want: false, comment: "no trailing colon"},
		{name: "structured key value short", input: "Status: open", want: false, comment: "no trailing colon"},
		{name: "sslscan cipher", input: "Preferred Cipher: ECDHE-RSA-AES256", want: false, comment: "no trailing colon"},
		{name: "ip address line", input: "Target: 192.168.1.1", want: false, comment: "contains IP"},
		{name: "separator equals", input: "================================:", want: false, comment: "contains ==="},
		{name: "separator dashes", input: "--------------------------------:", want: false, comment: "contains ---"},
		{name: "long line over 120", input: strings.Repeat("x", 121) + ":", want: false, comment: "exceeds 120 char limit"},
		{name: "nikto plus prefix", input: "+ Server: Apache/2.4.41", want: false, comment: "no trailing colon"},
		{name: "nmap pipe output", input: "|   Title: Apache Tomcat", want: false, comment: "no trailing colon"},
		{name: "nmap pipe ref", input: "|_  Reference: https://example.com", want: false, comment: "no trailing colon"},
		{name: "vulnerable caps no colon", input: "VULNERABLE", want: false, comment: "no trailing colon"},

		// --- True positives: stderr prompts that were previously missed ---
		{name: "routed network prompt", input: "Add a routed network to scan? (enter CIDR or press Enter to finish):", want: true},
		{name: "scan local network prompt", input: "Scan local network? (Enter=yes / custom CIDR / n=skip):", want: true},
		{name: "press enter phrase", input: "Press Enter to continue:", want: true},
		{name: "vulnerable colon stderr", input: "VULNERABLE:", want: true, comment: "stderr-only gate prevents false positives"},
		{name: "nikto plus vulnerable stderr", input: "+ VULNERABLE:", want: true, comment: "stderr-only gate prevents false positives"},
		{name: "nmap pipe vulnerable stderr", input: "|   VULNERABLE:", want: true, comment: "stderr-only gate prevents false positives"},
		{name: "mixed case vulnerable stderr", input: "Potentially VULNERABLE:", want: true, comment: "stderr-only gate prevents false positives"},

		// --- Edge cases ---
		{name: "empty string", input: "", want: false},
		{name: "just colon", input: ":", want: true, comment: "bare colon is ambiguous but short enough"},
		{name: "whitespace only", input: "   ", want: false},
		{name: "spaces and colon", input: "   :", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectScriptPrompt(tt.input)
			if got != tt.want {
				c := tt.comment
				if c == "" {
					c = "unexpected result"
				}
				t.Errorf("DetectScriptPrompt(%q) = %v, want %v (%s)", tt.input, got, tt.want, c)
			}
		})
	}
}

func TestDetectPasswordPrompt(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		// True positives
		{name: "password colon", input: "Password:", want: true},
		{name: "password space", input: "password required", want: true},
		{name: "confirm password", input: "Confirm password:", want: true},
		{name: "enter password", input: "Enter password:", want: true},
		{name: "passphrase", input: "Passphrase:", want: true},
		{name: "password case", input: "PASSWORD:", want: true},
		{name: "password inline", input: "Enter your password now:", want: true},

		// True negatives
		{name: "no password", input: "Enter IP address:", want: false},
		{name: "password in word", input: "Password Generator v1.0", want: true},
		{name: "empty", input: "", want: false},
		{name: "unrelated", input: "Scanning target...", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectPasswordPrompt(tt.input)
			if got != tt.want {
				t.Errorf("DetectPasswordPrompt(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestStripANSI(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "plain text", input: "hello world", want: "hello world"},
		{name: "color code", input: "\x1b[31mred text\x1b[0m", want: "red text"},
		{name: "bold", input: "\x1b[1mbold\x1b[0m", want: "bold"},
		{name: "multiple codes", input: "\x1b[32;1m\x1b[4mgreen bold underline\x1b[0m", want: "green bold underline"},
		{name: "no codes", input: "plain", want: "plain"},
		{name: "empty", input: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StripANSI(tt.input)
			if got != tt.want {
				t.Errorf("StripANSI(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
