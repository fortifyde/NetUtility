package jobs

import "testing"

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

		// --- True negatives: tool output (nikto, nmap, sslscan) ---
		{name: "nikto cipher line", input: "+ Preferred Cipher: TLS_AES_256", want: false, comment: "nikto output with + prefix"},
		{name: "nikto vulnerable", input: "+ VULNERABLE:", want: false, comment: "nikto + prefix"},
		{name: "nmap nse pipe", input: "|   VULNERABLE:", want: false, comment: "nmap NSE | prefix"},
		{name: "nmap nse pipe value", input: "|   State: LIKELY VULNERABLE", want: false, comment: "nmap NSE with value after colon"},
		{name: "structured key value", input: "Preferred Cipher: TLS_AES_256", want: false, comment: "Key: Value is output not prompt"},
		{name: "structured key value short", input: "Status: open", want: false, comment: "Key: Value is output"},
		{name: "sslscan cipher", input: "Preferred Cipher: ECDHE-RSA-AES256", want: false},
		{name: "ip address line", input: "Target: 192.168.1.1", want: false, comment: "contains IP"},
		{name: "separator equals", input: "================================:", want: false},
		{name: "separator dashes", input: "--------------------------------:", want: false},
		{name: "long line with colon", input: "This is a very long line that exceeds the forty character limit and ends with:", want: false},
		{name: "nikto plus prefix", input: "+ Server: Apache/2.4.41", want: false},
		{name: "nmap pipe output", input: "|   Title: Apache Tomcat", want: false},
		{name: "nmap pipe ref", input: "|_  Reference: https://example.com", want: false},
		{name: "vulnerable caps", input: "VULNERABLE:", want: false, comment: "all caps finding header"},
		{name: "mixed case vulnerable", input: "Potentially VULNERABLE:", want: false},

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
