package executor

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
)

type Executor struct {
	outputChan chan string
	errorChan  chan error
	doneChan   chan bool
	mu         sync.RWMutex
	running    bool
}

type ScriptResult struct {
	Success bool
	Output  string
	Error   error
}

func NewExecutor() *Executor {
	return &Executor{
		outputChan: make(chan string, 100),
		errorChan:  make(chan error, 10),
		doneChan:   make(chan bool, 1),
	}
}

func (e *Executor) ExecuteScript(ctx context.Context, scriptPath string, args ...string) (*ScriptResult, error) {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return nil, fmt.Errorf("executor is already running a script")
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

	cmd := exec.CommandContext(ctx, "bash", append([]string{scriptPath}, args...)...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start command: %w", err)
	}

	var wg sync.WaitGroup
	var output string
	var mu sync.Mutex

	wg.Add(2)

	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			mu.Lock()
			output += line + "\n"
			mu.Unlock()

			select {
			case e.outputChan <- "[stdout] " + line:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			mu.Lock()
			output += "[ERROR] " + line + "\n"
			mu.Unlock()

			select {
			case e.outputChan <- "[stderr] " + line:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(e.outputChan)
		e.doneChan <- true
	}()

	err = cmd.Wait()

	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("script execution timed out")
	}

	result := &ScriptResult{
		Success: err == nil,
		Output:  output,
		Error:   err,
	}

	return result, nil
}

func (e *Executor) GetOutputChannel() <-chan string {
	return e.outputChan
}

func (e *Executor) GetErrorChannel() <-chan error {
	return e.errorChan
}

func (e *Executor) GetDoneChannel() <-chan bool {
	return e.doneChan
}

func (e *Executor) IsRunning() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.running
}

func (e *Executor) StreamOutput(ctx context.Context, scriptPath string, outputWriter io.Writer, args ...string) error {
	cmd := exec.CommandContext(ctx, "bash", append([]string{scriptPath}, args...)...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start command: %w", err)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			fmt.Fprintf(outputWriter, "[stdout] %s\n", line)
		}
	}()

	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			fmt.Fprintf(outputWriter, "[stderr] %s\n", line)
		}
	}()

	wg.Wait()
	return cmd.Wait()
}
