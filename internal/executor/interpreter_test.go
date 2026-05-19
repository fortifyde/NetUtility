package executor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectInterpreter(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name         string
		content      string
		wantCmd      string
		wantArgs     []string
	}{
		{
			name:    "bash shebang",
			content: "#!/bin/bash\necho hello",
			wantCmd: "/bin/bash",
		},
		{
			name:     "env python3 shebang",
			content:  "#!/usr/bin/env python3\nprint('hi')",
			wantCmd:  "/usr/bin/env",
			wantArgs: []string{"python3"},
		},
		{
			name:    "sh shebang",
			content: "#!/bin/sh\necho hi",
			wantCmd: "/bin/sh",
		},
		{
			name:    "no shebang falls back to bash",
			content: "echo hello\n",
			wantCmd: "bash",
		},
		{
			name:    "empty file falls back to bash",
			content: "",
			wantCmd: "bash",
		},
		{
			name:    "single byte falls back to bash",
			content: "x",
			wantCmd: "bash",
		},
		{
			name:     "shebang with multiple args",
			content:  "#!/usr/bin/env -S python3 -u\nprint('hi')",
			wantCmd:  "/usr/bin/env",
			wantArgs: []string{"-S", "python3", "-u"},
		},
		{
			name:    "shebang with trailing whitespace",
			content: "#!/bin/bash   \necho hi",
			wantCmd: "/bin/bash",
		},
		{
			name:    "python3 direct shebang",
			content: "#!/usr/bin/python3\nprint('hi')",
			wantCmd: "/usr/bin/python3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(tmpDir, tt.name+".sh")
			if err := os.WriteFile(path, []byte(tt.content), 0o600); err != nil {
				t.Fatalf("write file: %v", err)
			}

			cmd, args := DetectInterpreter(path)
			if cmd != tt.wantCmd {
				t.Errorf("cmd = %q, want %q", cmd, tt.wantCmd)
			}
			if len(args) != len(tt.wantArgs) {
				t.Fatalf("args = %v, want %v", args, tt.wantArgs)
			}
			for i := range args {
				if args[i] != tt.wantArgs[i] {
					t.Errorf("args[%d] = %q, want %q", i, args[i], tt.wantArgs[i])
				}
			}
		})
	}
}

func TestDetectInterpreter_missingFile(t *testing.T) {
	cmd, args := DetectInterpreter("/nonexistent/file.sh")
	if cmd != "bash" {
		t.Errorf("cmd = %q, want %q", cmd, "bash")
	}
	if args != nil {
		t.Errorf("args = %v, want nil", args)
	}
}
