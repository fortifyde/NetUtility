package executor

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
)

type Executor struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	cancel  chan struct{}
	running bool
	mu      sync.RWMutex
}

type ScriptResult struct {
	Success bool
	Output  string
	Error   error
}

func NewExecutor() *Executor {
	return &Executor{
		cancel: make(chan struct{}),
	}
}

func (e *Executor) ExecuteScript(scriptPath string, outputWriter io.Writer) (*ScriptResult, error) {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return nil, fmt.Errorf("executor is already running")
	}
	e.running = true
	e.mu.Unlock()

	defer func() {
		e.mu.Lock()
		e.running = false
		e.mu.Unlock()
	}()

	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("script file does not exist: %s", scriptPath)
	}

	// Create command
	cmd := exec.Command("bash", scriptPath)
	cmd.Env = os.Environ()
	e.cmd = cmd

	// Set up direct I/O
	cmd.Stdout = outputWriter
	cmd.Stderr = outputWriter

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}
	e.stdin = stdin

	// Start the command
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start command: %w", err)
	}

	// Wait for completion or cancellation
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	var cmdErr error
	select {
	case cmdErr = <-done:
		// Command completed normally
	case <-e.cancel:
		// Command was cancelled
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		cmdErr = <-done // Wait for process to actually exit
	}

	// Close stdin
	if e.stdin != nil {
		e.stdin.Close()
		e.stdin = nil
	}

	result := &ScriptResult{
		Success: cmdErr == nil,
		Output:  "", // Output goes directly to writer
		Error:   cmdErr,
	}

	return result, nil
}

func (e *Executor) SendInput(input string) error {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if !e.running || e.stdin == nil {
		return fmt.Errorf("executor is not running or stdin is not available")
	}

	_, err := e.stdin.Write([]byte(input))
	return err
}

func (e *Executor) IsRunning() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.running
}

func (e *Executor) Stop() error {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if !e.running {
		return nil
	}

	select {
	case e.cancel <- struct{}{}:
	default:
	}

	return nil
}
