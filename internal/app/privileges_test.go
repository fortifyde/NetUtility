package app

import (
	"os"
	"testing"
)

func TestCheckRootAccess(t *testing.T) {
	if os.Geteuid() == 0 {
		err := CheckRootAccess()
		if err != nil {
			t.Errorf("CheckRootAccess() failed when running as root: %v", err)
		}
	} else {
		t.Skip("Skipping root access test - not running as root")
	}
}
