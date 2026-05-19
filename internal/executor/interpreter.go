package executor

import (
	"os"
	"strings"
)

// defaultInterpreter is the fallback when no shebang is found.
const defaultInterpreter = "bash"

// DetectInterpreter reads the shebang line from a script file and returns
// the interpreter command and any extra arguments. Falls back to "bash" if
// no valid shebang is found, preserving existing behavior for shell scripts.
func DetectInterpreter(scriptPath string) (cmd string, args []string) {
	f, err := os.Open(scriptPath) //nolint:gosec // path comes from trusted script metadata
	if err != nil {
		return defaultInterpreter, nil
	}
	defer func() { _ = f.Close() }()

	// Read enough for any reasonable shebang line.
	buf := make([]byte, 256)
	n, err := f.Read(buf)
	if err != nil || n < 2 {
		return defaultInterpreter, nil
	}

	content := string(buf[:n])
	if !strings.HasPrefix(content, "#!") {
		return defaultInterpreter, nil
	}

	// Extract the shebang line up to the first newline.
	end := strings.Index(content, "\n")
	if end == -1 {
		end = len(content)
	}
	shebang := strings.TrimSpace(content[2:end])

	parts := strings.Fields(shebang)
	if len(parts) == 0 {
		return defaultInterpreter, nil
	}

	if len(parts) == 1 {
		return parts[0], nil
	}
	return parts[0], parts[1:]
}
