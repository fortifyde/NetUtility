package executor

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
)

// OutputLine represents a single line of output with metadata
type OutputLine struct {
	Content   string
	Timestamp time.Time
	Source    string // "stdout" or "stderr"
}

// StreamingExecutor provides real-time output streaming capabilities
type StreamingExecutor struct {
	cmd        *exec.Cmd
	stdin      io.WriteCloser
	ctx        context.Context
	cancel     context.CancelFunc
	running    bool
	outputChan chan OutputLine
	errorChan  chan error
	doneChan   chan struct{}
	mu         sync.RWMutex
}

// StreamingResult contains the final result of script execution
type StreamingResult struct {
	Success     bool
	ExitCode    int
	Error       error
	OutputLines []OutputLine
	Duration    time.Duration
	StartTime   time.Time
	EndTime     time.Time
}

// NewStreamingExecutor creates a new streaming executor
func NewStreamingExecutor() *StreamingExecutor {
	ctx, cancel := context.WithCancel(context.Background())
	return &StreamingExecutor{
		ctx:        ctx,
		cancel:     cancel,
		outputChan: make(chan OutputLine, 1000), // Buffer for output lines
		errorChan:  make(chan error, 1),
		doneChan:   make(chan struct{}),
	}
}

// ExecuteScriptStreaming executes a script with real-time output streaming
func (e *StreamingExecutor) ExecuteScriptStreaming(scriptPath string) (*StreamingResult, <-chan OutputLine, <-chan error) {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		errChan := make(chan error, 1)
		errChan <- fmt.Errorf("executor is already running")
		close(errChan)
		return nil, nil, errChan
	}
	e.running = true
	e.mu.Unlock()

	result := &StreamingResult{
		StartTime:   time.Now(),
		OutputLines: make([]OutputLine, 0),
	}

	// Check if script exists
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		e.mu.Lock()
		e.running = false
		e.mu.Unlock()

		errChan := make(chan error, 1)
		errChan <- fmt.Errorf("script file does not exist: %s", scriptPath)
		close(errChan)
		return result, nil, errChan
	}

	// Start the execution in a goroutine
	go e.executeScript(scriptPath, result)

	return result, e.outputChan, e.errorChan
}

// executeScript runs the actual script execution
func (e *StreamingExecutor) executeScript(scriptPath string, result *StreamingResult) {
	defer func() {
		e.mu.Lock()
		e.running = false
		e.mu.Unlock()

		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime)

		close(e.outputChan)
		close(e.errorChan)
		close(e.doneChan)
	}()

	// Create command
	cmd := exec.CommandContext(e.ctx, "bash", scriptPath)
	cmd.Env = os.Environ()
	e.cmd = cmd

	// Set up pipes
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		e.errorChan <- fmt.Errorf("failed to create stdout pipe: %w", err)
		return
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		e.errorChan <- fmt.Errorf("failed to create stderr pipe: %w", err)
		return
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		e.errorChan <- fmt.Errorf("failed to create stdin pipe: %w", err)
		return
	}
	e.stdin = stdin

	// Start the command
	if err := cmd.Start(); err != nil {
		e.errorChan <- fmt.Errorf("failed to start command: %w", err)
		return
	}

	// Set up output readers
	var wg sync.WaitGroup

	// Read stdout
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.readOutput(stdout, "stdout", result)
	}()

	// Read stderr
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.readOutput(stderr, "stderr", result)
	}()

	// Wait for command completion
	cmdDone := make(chan error, 1)
	go func() {
		cmdDone <- cmd.Wait()
	}()

	// Handle completion or cancellation
	select {
	case err := <-cmdDone:
		result.Error = err
		result.Success = err == nil
		if err != nil {
			if exitError, ok := err.(*exec.ExitError); ok {
				result.ExitCode = exitError.ExitCode()
			}
		}
	case <-e.ctx.Done():
		// Context was cancelled
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		result.Error = e.ctx.Err()
		result.Success = false
		result.ExitCode = -1
	}

	// Wait for output readers to finish
	wg.Wait()

	// Close stdin
	if e.stdin != nil {
		e.stdin.Close()
		e.stdin = nil
	}
}

// readOutput reads output from a pipe and sends it to the output channel
func (e *StreamingExecutor) readOutput(pipe io.Reader, source string, result *StreamingResult) {
	scanner := bufio.NewScanner(pipe)

	// Set a reasonable buffer size for long lines
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := OutputLine{
			Content:   scanner.Text(),
			Timestamp: time.Now(),
			Source:    source,
		}

		// Store in result
		result.OutputLines = append(result.OutputLines, line)

		// Send to channel (non-blocking)
		select {
		case e.outputChan <- line:
		case <-e.ctx.Done():
			return
		default:
			// Channel is full, skip this line to avoid blocking
		}
	}

	if err := scanner.Err(); err != nil {
		select {
		case e.errorChan <- fmt.Errorf("error reading %s: %w", source, err):
		case <-e.ctx.Done():
		default:
		}
	}
}

// SendInput sends input to the running script
func (e *StreamingExecutor) SendInput(input string) error {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if !e.running || e.stdin == nil {
		return fmt.Errorf("executor is not running or stdin is not available")
	}

	_, err := e.stdin.Write([]byte(input + "\n"))
	if err != nil {
		return err
	}

	// Flush the input to ensure it's sent immediately
	if flusher, ok := e.stdin.(interface{ Flush() error }); ok {
		return flusher.Flush()
	}

	return nil
}

// IsRunning returns whether the executor is currently running
func (e *StreamingExecutor) IsRunning() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.running
}

// Stop cancels the running script execution
func (e *StreamingExecutor) Stop() error {
	e.cancel()
	return nil
}

// Wait waits for the script execution to complete
func (e *StreamingExecutor) Wait() {
	<-e.doneChan
}

// GetOutputHistory returns all output lines captured so far
func (e *StreamingExecutor) GetOutputHistory(result *StreamingResult) []OutputLine {
	if result == nil {
		return nil
	}
	return result.OutputLines
}

// FilterOutput filters output lines by source (stdout/stderr)
func FilterOutput(lines []OutputLine, source string) []OutputLine {
	filtered := make([]OutputLine, 0, len(lines))
	for _, line := range lines {
		if line.Source == source {
			filtered = append(filtered, line)
		}
	}
	return filtered
}

// FormatOutput formats output lines for display
func FormatOutput(lines []OutputLine, showTimestamp bool, showSource bool) string {
	var result string
	for _, line := range lines {
		if showTimestamp {
			result += line.Timestamp.Format("15:04:05 ")
		}
		if showSource {
			result += fmt.Sprintf("[%s] ", line.Source)
		}
		result += line.Content + "\n"
	}
	return result
}

// TailOutput returns the last N lines of output
func TailOutput(lines []OutputLine, n int) []OutputLine {
	if len(lines) <= n {
		return lines
	}
	return lines[len(lines)-n:]
}

// SearchOutput searches for lines containing the given text
func SearchOutput(lines []OutputLine, searchText string) []OutputLine {
	var matches []OutputLine
	for _, line := range lines {
		if contains(line.Content, searchText) {
			matches = append(matches, line)
		}
	}
	return matches
}

// Helper function for case-insensitive string matching
func contains(text, substr string) bool {
	// Simple case-insensitive contains check
	// In a real implementation, you might want to use strings.ToLower
	// or a more sophisticated search algorithm
	return len(text) >= len(substr) &&
		findSubstring(text, substr) >= 0
}

// Simple substring search (case-insensitive)
func findSubstring(text, substr string) int {
	if len(substr) == 0 {
		return 0
	}
	if len(text) < len(substr) {
		return -1
	}

	// Convert to lowercase for comparison
	textLower := toLowerCase(text)
	substrLower := toLowerCase(substr)

	for i := 0; i <= len(textLower)-len(substrLower); i++ {
		if textLower[i:i+len(substrLower)] == substrLower {
			return i
		}
	}
	return -1
}

// Simple lowercase conversion
func toLowerCase(s string) string {
	result := make([]byte, len(s))
	for i, c := range []byte(s) {
		if c >= 'A' && c <= 'Z' {
			result[i] = c + 32
		} else {
			result[i] = c
		}
	}
	return string(result)
}
