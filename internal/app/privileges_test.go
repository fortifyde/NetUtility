package app

import (
	"os"
	"testing"
)

// NOTE: CheckRootAccess and escalatePrivileges cannot be safely unit tested
// because escalatePrivileges calls os.Exit(0) on success. These tests verify
// only the non-exiting paths and the function signatures.

func TestCheckRootAccessReturnsNilWhenRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("not running as root — skipping root-only test")
	}

	err := CheckRootAccess()
	if err != nil {
		t.Errorf("expected nil when running as root, got: %v", err)
	}
}

func TestPackageExportsExpectedFunctions(t *testing.T) {
	// Verify the package exports the expected API surface.
	// This is a compile-time check — if the functions don't exist,
	// the test file won't compile.
	_ = CheckRootAccess
}
