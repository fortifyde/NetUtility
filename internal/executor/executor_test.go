package executor

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNewExecutor(t *testing.T) {
	executor := NewExecutor()
	if executor == nil {
		t.Error("NewExecutor() returned nil")
	}

	if executor.IsRunning() {
		t.Error("New executor should not be running")
	}
}

func TestExecuteScript(t *testing.T) {
	executor := NewExecutor()

	// Create a temporary test script
	testScript := "/tmp/test_script.sh"
	testContent := "#!/bin/bash\necho 'Hello, World!'\necho 'Test output' >&2\n"

	if err := os.WriteFile(testScript, []byte(testContent), 0755); err != nil {
		t.Fatalf("Failed to create test script: %v", err)
	}
	defer os.Remove(testScript)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := executor.ExecuteScript(ctx, testScript)
	if err != nil {
		t.Fatalf("ExecuteScript() failed: %v", err)
	}

	if !result.Success {
		t.Errorf("Script execution should have succeeded")
	}

	if !strings.Contains(result.Output, "Hello, World!") {
		t.Errorf("Expected output not found in result: %s", result.Output)
	}
}

func TestExecuteScriptTimeout(t *testing.T) {
	executor := NewExecutor()

	// Create a script that sleeps longer than the timeout
	testScript := "/tmp/test_timeout_script.sh"
	testContent := "#!/bin/bash\nsleep 5\necho 'Should not reach here'\n"

	if err := os.WriteFile(testScript, []byte(testContent), 0755); err != nil {
		t.Fatalf("Failed to create test script: %v", err)
	}
	defer os.Remove(testScript)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, err := executor.ExecuteScript(ctx, testScript)
	if err == nil {
		t.Error("Expected timeout error but got none")
	}
}

func TestExecuteScriptNonexistent(t *testing.T) {
	executor := NewExecutor()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := executor.ExecuteScript(ctx, "/nonexistent/script.sh")
	if err == nil {
		t.Error("Expected error for nonexistent script but got none")
	}
}
