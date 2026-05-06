package executor

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
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
	stopOnce   sync.Once
}

// StreamingResult contains the final result of script execution
type StreamingResult struct {
	Success   bool
	ExitCode  int
	Error     error
	Duration  time.Duration
	StartTime time.Time
	EndTime   time.Time

	mu          sync.Mutex
	OutputLines []OutputLine
}

// AppendLine appends a line to OutputLines under the mutex.
func (r *StreamingResult) AppendLine(line OutputLine) {
	r.mu.Lock()
	r.OutputLines = append(r.OutputLines, line)
	r.mu.Unlock()
}

// GetOutputLines returns a snapshot copy of OutputLines.
func (r *StreamingResult) GetOutputLines() []OutputLine {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]OutputLine, len(r.OutputLines))
	copy(out, r.OutputLines)
	return out
}

// SetFinal records the final result fields atomically. Call this exactly once,
// after the process has exited and all output readers have finished.
func (r *StreamingResult) SetFinal(success bool, exitCode int, err error, endTime time.Time) {
	r.mu.Lock()
	r.Success = success
	r.ExitCode = exitCode
	r.Error = err
	r.EndTime = endTime
	r.Duration = endTime.Sub(r.StartTime)
	r.mu.Unlock()
}

// GetFinal returns the final result fields atomically.
func (r *StreamingResult) GetFinal() (success bool, exitCode int, duration time.Duration, endTime time.Time, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.Success, r.ExitCode, r.Duration, r.EndTime, r.Error
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

		close(e.outputChan)
		close(e.errorChan)
		close(e.doneChan)
	}()

	// Create command
	cmd := exec.CommandContext(e.ctx, "bash", scriptPath)
	cmd.Env = append(os.Environ(), "NETUTIL_FORCE_COLOR=1")
	// Isolate child in its own process group so SIGINT to the TUI
	// does not propagate to the script, and vice versa.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	e.mu.Lock()
	e.cmd = cmd
	e.mu.Unlock()

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

	// Start the command before publishing stdin so the process is ready to receive input.
	if err := cmd.Start(); err != nil {
		e.errorChan <- fmt.Errorf("failed to start command: %w", err)
		return
	}

	// Atomically publish stdin under the same lock that guards e.running,
	// so SendInput cannot observe running=true with stdin=nil.
	e.mu.Lock()
	e.stdin = stdin
	e.mu.Unlock()

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

	// Wait for readers first — they terminate at EOF (write end closed on process exit,
	// or on kill via exec.CommandContext context cancellation).
	wg.Wait()

	// Now safe to call cmd.Wait(): read ends are no longer in use.
	exitErr := cmd.Wait()
	var (
		success  bool
		exitCode int
		finalErr error
	)
	if e.ctx.Err() != nil {
		finalErr = e.ctx.Err()
		success = false
		exitCode = -1
	} else {
		finalErr = exitErr
		success = exitErr == nil
		if exitErr != nil {
			if exitError, ok := exitErr.(*exec.ExitError); ok {
				exitCode = exitError.ExitCode()
			}
		}
	}
	result.SetFinal(success, exitCode, finalErr, time.Now())

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

	var dropped int

	for scanner.Scan() {
		line := OutputLine{
			Content:   scanner.Text(),
			Timestamp: time.Now(),
			Source:    source,
		}

		// Store in result (thread-safe — two goroutines call readOutput concurrently)
		result.AppendLine(line)

		// If we previously dropped lines, emit a notice once the channel has room.
		if dropped > 0 {
			notice := OutputLine{
				Content:   fmt.Sprintf("[%d lines dropped — output buffer was full]", dropped),
				Timestamp: time.Now(),
				Source:    "system",
			}
			select {
			case e.outputChan <- notice:
				dropped = 0
			case <-e.ctx.Done():
				return
			default:
			}
		}

		select {
		case e.outputChan <- line:
		case <-e.ctx.Done():
			return
		default:
			// Channel still full — count the drop; notice will be emitted next iteration.
			dropped++
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

// Stop cancels the running script execution and kills the entire process
// group to ensure grandchildren (nmap, tcpdump, etc.) are cleaned up,
// not just the direct bash child.
func (e *StreamingExecutor) Stop() error {
	e.stopOnce.Do(func() {
		e.cancel() // Signal context cancellation

		// Kill the entire process group. Setpgid: true (set in executeScript)
		// ensures the child leads its own group, so -pid targets the group.
		e.mu.RLock()
		cmd := e.cmd
		e.mu.RUnlock()

		if cmd != nil && cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			// TODO: Consider SIGTERM + graceful timeout before SIGKILL for
			// scripts that produce intermediate output to disk.
		}
	})
	return nil
}

// Wait waits for the script execution to complete
func (e *StreamingExecutor) Wait() {
	<-e.doneChan
}

// GetOutputHistory returns a snapshot of all output lines captured so far.
func (e *StreamingExecutor) GetOutputHistory(result *StreamingResult) []OutputLine {
	if result == nil {
		return nil
	}
	return result.GetOutputLines()
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
	var sb strings.Builder
	for _, line := range lines {
		if showTimestamp {
			sb.WriteString(line.Timestamp.Format("15:04:05 "))
		}
		if showSource {
			fmt.Fprintf(&sb, "[%s] ", line.Source)
		}
		sb.WriteString(line.Content)
		sb.WriteByte('\n')
	}
	return sb.String()
}

// TailOutput returns the last N lines of output
func TailOutput(lines []OutputLine, n int) []OutputLine {
	if len(lines) <= n {
		return lines
	}
	return lines[len(lines)-n:]
}

// SearchOutput searches for lines containing the given text (case-insensitive).
func SearchOutput(lines []OutputLine, searchText string) []OutputLine {
	lower := strings.ToLower(searchText)
	var matches []OutputLine
	for _, line := range lines {
		if strings.Contains(strings.ToLower(line.Content), lower) {
			matches = append(matches, line)
		}
	}
	return matches
}
