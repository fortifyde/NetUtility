package app

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

func CheckRootAccess() error {
	if os.Geteuid() == 0 {
		return nil
	}

	fmt.Println("This application requires root privileges.")
	fmt.Println("Attempting to escalate privileges...")

	return escalatePrivileges()
}

func escalatePrivileges() error {
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	cmd := exec.Command("sudo", executable)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				os.Exit(status.ExitStatus())
			}
		}
		return fmt.Errorf("failed to escalate privileges: %w", err)
	}

	os.Exit(0)
	return nil
}
