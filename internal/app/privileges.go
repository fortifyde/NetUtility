package app

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

func CheckRootAccess() error {
	if os.Geteuid() == 0 {
		return nil
	}

	fmt.Fprintf(os.Stderr, "This application requires root privileges.\n")
	fmt.Fprintf(os.Stderr, "Attempting to escalate privileges...\n")

	return escalatePrivileges()
}

func escalatePrivileges() error {
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	cmd := exec.Command("sudo", append([]string{executable}, os.Args[1:]...)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				os.Exit(status.ExitStatus())
			}
		}
		return fmt.Errorf("failed to escalate privileges: %w", err)
	}

	os.Exit(0)
	return nil
}
