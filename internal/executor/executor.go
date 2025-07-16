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
	"time"
)

type Executor struct {
	outputChan    chan string
	errorChan     chan error
	doneChan      chan bool
	mu            sync.RWMutex
	running       bool
	activeWG      sync.WaitGroup // Tracks active goroutines from current execution
	activeSession *InteractiveSession
	sessionMu     sync.RWMutex
}

type ScriptResult struct {
	Success bool
	Output  string
	Error   error
}

// InteractiveSession represents an active interactive script execution
type InteractiveSession struct {
	inputChan      chan string
	doneChan       chan bool
	errorChan      chan error
	outputChan     chan string
	cancel         context.CancelFunc
	cmd            *exec.Cmd
	stdin          io.WriteCloser
	mu             sync.RWMutex
	active         bool
	result         *ScriptResult
	resultReady    chan bool
	goroutineWG    sync.WaitGroup
	cleanupOnce    sync.Once
	channelsClosed bool
	context        context.Context // renamed from ctx to avoid containedctx warning
	terminated     bool            // Track if session was explicitly terminated
	inputClosed    bool            // Track if input channel was closed
}

func NewExecutor() *Executor {
	return &Executor{
		outputChan: make(chan string, 100),
		errorChan:  make(chan error, 10),
		doneChan:   make(chan bool, 1),
	}
}

// NewInteractiveSession creates a new interactive session
func NewInteractiveSession(ctx context.Context) *InteractiveSession {
	sessionCtx, cancel := context.WithCancel(ctx)
	return &InteractiveSession{
		inputChan:   make(chan string, 10),
		doneChan:    make(chan bool, 1),
		errorChan:   make(chan error, 10),
		outputChan:  make(chan string, 100),
		context:     sessionCtx,
		cancel:      cancel,
		active:      false,
		resultReady: make(chan bool, 1),
	}
}

// SendInput sends input to the interactive session
func (s *InteractiveSession) SendInput(input string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.active {
		return fmt.Errorf("session is not active")
	}

	if s.channelsClosed || s.inputClosed {
		return fmt.Errorf("session input is closed")
	}

	if s.terminated {
		return fmt.Errorf("session was terminated")
	}

	select {
	case s.inputChan <- input:
		return nil
	case <-s.context.Done():
		return fmt.Errorf("session context cancelled")
	case <-time.After(1 * time.Second):
		return fmt.Errorf("input send timeout - channel may be blocked")
	}
}

// GetOutputChannel returns the output channel for the session
func (s *InteractiveSession) GetOutputChannel() <-chan string {
	return s.outputChan
}

// GetErrorChannel returns the error channel for the session
func (s *InteractiveSession) GetErrorChannel() <-chan error {
	return s.errorChan
}

// GetDoneChannel returns the done channel for the session
func (s *InteractiveSession) GetDoneChannel() <-chan bool {
	return s.doneChan
}

// IsActive returns whether the session is currently active
func (s *InteractiveSession) IsActive() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active
}

// Wait waits for the session to complete and returns the result
func (s *InteractiveSession) Wait() (*ScriptResult, error) {
	select {
	case <-s.resultReady:
		s.mu.RLock()
		defer s.mu.RUnlock()
		return s.result, nil
	case <-s.context.Done():
		return nil, fmt.Errorf("session context cancelled")
	}
}

// Terminate terminates the interactive session
func (s *InteractiveSession) Terminate() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.active {
		return fmt.Errorf("session is not active")
	}

	// Mark as terminated to prevent further input
	s.terminated = true

	// Cancel the context first to signal all goroutines
	s.cancel()

	// Close input channel to unblock any waiting goroutines
	if !s.inputClosed {
		close(s.inputChan)
		s.inputClosed = true
	}

	// Try to kill the process if it exists
	if s.cmd != nil && s.cmd.Process != nil {
		if err := s.cmd.Process.Kill(); err != nil {
			// If kill fails, try terminate
			if termErr := s.cmd.Process.Signal(os.Interrupt); termErr != nil {
				return fmt.Errorf("failed to terminate process: kill=%w, term=%w", err, termErr)
			}
		}
	}

	return nil
}

// cleanup performs cleanup operations for the session
func (s *InteractiveSession) cleanup() {
	s.cleanupOnce.Do(func() {
		// Cancel the context to signal all goroutines to stop
		s.cancel()

		// Wait for all goroutines to finish with timeout
		done := make(chan struct{})
		go func() {
			s.goroutineWG.Wait()
			close(done)
		}()

		select {
		case <-done:
			// All goroutines finished normally
		case <-time.After(5 * time.Second):
			// Timeout waiting for goroutines - proceed with cleanup anyway
		}

		s.mu.Lock()
		defer s.mu.Unlock()

		s.active = false

		if !s.channelsClosed {
			// Drain channels before closing to prevent deadlocks
			s.drainChannels()

			// Close input channel if not already closed
			if !s.inputClosed {
				close(s.inputChan)
				s.inputClosed = true
			}

			// Close output channels
			close(s.outputChan)
			close(s.errorChan)

			// Signal completion
			select {
			case s.doneChan <- true:
			default:
			}
			close(s.doneChan)

			s.channelsClosed = true
		}

		if s.stdin != nil {
			if err := s.stdin.Close(); err != nil {
				// Log error but continue cleanup
			}
			s.stdin = nil
		}
	})
}

// drainChannels drains all channels to prevent deadlocks
func (s *InteractiveSession) drainChannels() {
	// Drain input channel
	for {
		select {
		case <-s.inputChan:
		default:
			return
		}
	}
}

func (e *Executor) resetChannels() {
	// Drain existing channels before replacing them
	e.drainAllChannels()

	e.outputChan = make(chan string, 100)
	e.errorChan = make(chan error, 10)
	e.doneChan = make(chan bool, 1)
}

// drainAllChannels drains all executor channels to prevent deadlocks
func (e *Executor) drainAllChannels() {
	for {
		select {
		case <-e.outputChan:
		case <-e.errorChan:
		case <-e.doneChan:
		default:
			return
		}
	}
}

func (e *Executor) ExecuteScript(ctx context.Context, scriptPath string, args ...string) (*ScriptResult, error) {
	// Simple implementation that uses the interactive session but waits for completion
	session, err := e.ExecuteInteractiveScript(ctx, scriptPath, args...)
	if err != nil {
		return nil, err
	}

	// Wait for completion and return the result
	return session.Wait()
}

// ExecuteInteractiveScript starts an interactive script and returns an InteractiveSession for management
func (e *Executor) ExecuteInteractiveScript(ctx context.Context, scriptPath string, args ...string) (*InteractiveSession, error) {
	e.sessionMu.Lock()
	if e.activeSession != nil && e.activeSession.IsActive() {
		e.sessionMu.Unlock()
		return nil, fmt.Errorf("an interactive session is already active")
	}
	e.sessionMu.Unlock()

	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("script file does not exist: %s", scriptPath)
	}

	// Create new interactive session
	session := NewInteractiveSession(ctx)

	// Set up the command
	cmd := exec.CommandContext(session.context, "bash", append([]string{scriptPath}, args...)...)
	session.cmd = cmd

	// Set up stdin for interactive mode
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}
	session.stdin = stdin

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

	// Mark session as active
	session.mu.Lock()
	session.active = true
	session.mu.Unlock()

	// Store the active session
	e.sessionMu.Lock()
	e.activeSession = session
	e.sessionMu.Unlock()

	var output string
	var mu sync.Mutex
	var wg sync.WaitGroup

	wg.Add(3)                  // stdout, stderr, and input handler
	session.goroutineWG.Add(3) // Track goroutines for proper cleanup

	// Handle input forwarding
	go func() {
		defer wg.Done()
		defer session.goroutineWG.Done()
		for {
			select {
			case input, ok := <-session.inputChan:
				if !ok {
					// Input channel closed, exit gracefully
					return
				}
				if session.stdin != nil {
					// Add newline and flush immediately
					inputData := []byte(input + "\n")
					if _, err := session.stdin.Write(inputData); err != nil {
						// Check if this is due to broken pipe/closed stdin
						if strings.Contains(err.Error(), "broken pipe") || strings.Contains(err.Error(), "file already closed") {
							// Process likely terminated, exit gracefully
							return
						}
						// Other error, log but continue
						continue
					}
					// Force flush if the stdin supports it
					if flusher, ok := session.stdin.(interface{ Flush() error }); ok {
						flusher.Flush()
					}
				}
			case <-session.context.Done():
				return
			}
		}
	}()

	// Handle stdout with simple line-based reading and prompt detection
	go func() {
		defer wg.Done()
		defer session.goroutineWG.Done()

		reader := bufio.NewReader(stdout)
		scanner := bufio.NewScanner(reader)

		// Read complete lines
		for scanner.Scan() {
			// Check if context is cancelled
			select {
			case <-session.context.Done():
				return
			default:
			}

			line := scanner.Text()

			// Immediately send output to accumulator and channel
			mu.Lock()
			output += line + "\n"
			mu.Unlock()

			// Send line immediately to output channel
			select {
			case session.outputChan <- "[stdout] " + line:
			case <-session.context.Done():
				return
			}
		}

		// Check for scanner error first
		if err := scanner.Err(); err != nil {
			select {
			case session.outputChan <- "[stdout] Scanner error: " + err.Error():
			case <-session.context.Done():
			}
			return
		}

		// After scanner finishes, check for any remaining buffered data (potential prompts)
		for {
			// Set a short read timeout to detect prompts
			select {
			case <-session.context.Done():
				return
			default:
			}

			// Try to read any remaining data with a timeout
			data := make([]byte, 1024)
			// Use a longer timeout to catch prompts reliably
			deadline := time.Now().Add(50 * time.Millisecond)

			// For regular files/pipes, we can't set deadline, so use a goroutine with timeout
			done := make(chan bool, 1)
			var n int
			var err error

			go func() {
				n, err = reader.Read(data)
				done <- true
			}()

			select {
			case <-done:
				if err != nil {
					if err == io.EOF {
						return // Normal end of stream
					}
					// Other error, report and exit
					select {
					case session.outputChan <- "[stdout] Read error: " + err.Error():
					case <-session.context.Done():
					}
					return
				}

				if n > 0 {
					// We got some data - likely a prompt without newline
					promptText := strings.TrimSpace(string(data[:n]))
					if promptText != "" {
						mu.Lock()
						output += promptText + "\n"
						mu.Unlock()

						// Send the prompt text immediately
						select {
						case session.outputChan <- "[stdout] " + promptText:
						case <-session.context.Done():
							return
						}
					}
				}
			case <-time.After(time.Until(deadline)):
				// Timeout - no more data available
				return
			case <-session.context.Done():
				return
			}
		}
	}()

	// Handle stderr
	go func() {
		defer wg.Done()
		defer session.goroutineWG.Done()
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			select {
			case <-session.context.Done():
				return
			default:
			}

			line := scanner.Text()
			mu.Lock()
			output += "[ERROR] " + line + "\n"
			mu.Unlock()

			select {
			case session.outputChan <- "[stderr] " + line:
			case <-session.context.Done():
				return
			}
		}
	}()

	// Handle completion and cleanup
	go func() {
		defer func() {
			// Ensure cleanup happens even if there's a panic
			session.cleanup()

			// Remove from active sessions
			e.sessionMu.Lock()
			if e.activeSession == session {
				e.activeSession = nil
			}
			e.sessionMu.Unlock()
		}()

		// Wait for all output goroutines to finish or timeout
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()

		var err error
		var cmdErr error

		// Wait for either goroutines to finish or context cancellation
		select {
		case <-done:
			// All goroutines finished, now wait for command
			cmdErr = cmd.Wait()
		case <-session.context.Done():
			// Context cancelled, kill the process
			if cmd.Process != nil {
				cmd.Process.Kill()
			}
			// Still wait for the command to finish after killing
			cmdErr = cmd.Wait()
			err = session.context.Err()
		}

		// Capture final output state
		mu.Lock()
		finalOutput := output
		mu.Unlock()

		// Prepare result
		result := &ScriptResult{
			Success: cmdErr == nil && err == nil,
			Output:  finalOutput,
			Error:   cmdErr,
		}

		// If context was cancelled, include that error
		if err != nil {
			if cmdErr != nil {
				result.Error = fmt.Errorf("%w (command error: %v)", err, cmdErr)
			} else {
				result.Error = err
			}
		}

		session.mu.Lock()
		session.result = result
		session.active = false // Mark as inactive before cleanup
		session.mu.Unlock()

		// Signal result is ready
		select {
		case session.resultReady <- true:
		default:
		}
	}()

	return session, nil
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

// isPromptLine checks if a line contains a prompt for user input
func (e *Executor) isPromptLine(line string) bool {
	// Common prompt patterns
	promptPatterns := []string{
		":",        // Common shell prompt ending
		"? ",       // Question prompts
		"(y/n)",    // Yes/no prompts
		"[y/N]",    // Yes/no prompts with default
		"[Y/n]",    // Yes/no prompts with default
		"Enter",    // Enter prompts
		"input",    // Input prompts
		"choice",   // Choice prompts
		"select",   // Selection prompts
		"password", // Password prompts
		"username", // Username prompts
		"continue", // Continue prompts
		"proceed",  // Proceed prompts
	}

	// Convert to lowercase for case-insensitive matching
	lowerLine := strings.ToLower(line)

	// Check for prompt patterns
	for _, pattern := range promptPatterns {
		if strings.Contains(lowerLine, pattern) {
			return true
		}
	}

	// Check if line ends with colon and space (common prompt pattern)
	if strings.HasSuffix(strings.TrimSpace(line), ": ") {
		return true
	}

	return false
}

// isLikelyPrompt determines if content is likely a prompt based on patterns and context
func (e *Executor) isLikelyPrompt(content string, recentLines []string) bool {
	trimmed := strings.TrimSpace(content)
	lowerContent := strings.ToLower(trimmed)

	// Check for immediate prompt indicators
	immediatePatterns := []string{
		":",     // Ends with colon (common prompt pattern)
		"? ",    // Question prompts
		"(y/n)", // Yes/no prompts
		"[y/N]", // Yes/no with default
		"[Y/n]", // Yes/no with default
	}

	for _, pattern := range immediatePatterns {
		if strings.HasSuffix(trimmed, pattern) || strings.Contains(lowerContent, pattern) {
			return true
		}
	}

	// Check for prompt keywords combined with context from recent lines
	promptKeywords := []string{
		"enter", "input", "type", "provide", "specify",
		"select", "choose", "pick", "option",
		"path", "directory", "file", "name",
		"address", "ip", "port", "host",
		"username", "password", "login",
		"continue", "proceed", "confirm",
	}

	for _, keyword := range promptKeywords {
		if strings.Contains(lowerContent, keyword) {
			// Check context from recent lines to confirm it's a prompt
			for _, recentLine := range recentLines {
				recentLower := strings.ToLower(recentLine)
				// Look for context that suggests this is asking for input
				if strings.Contains(recentLower, "enter") ||
					strings.Contains(recentLower, "input") ||
					strings.Contains(recentLower, "provide") ||
					strings.Contains(recentLower, "type") {
					return true
				}
			}

			// If no context from recent lines, check if current content has multiple prompt indicators
			promptIndicators := 0
			for _, indicator := range promptKeywords {
				if strings.Contains(lowerContent, indicator) {
					promptIndicators++
				}
			}
			// If we have multiple indicators, it's likely a prompt
			if promptIndicators >= 2 {
				return true
			}
		}
	}

	// Special case: Detect patterns that typically indicate waiting for input
	// This handles cases like prompts that don't end with standard patterns
	if len(trimmed) > 10 && len(trimmed) < 200 { // Reasonable prompt length
		// Look for sentence-like structure that ends abruptly (suggests waiting for input)
		if (strings.Contains(lowerContent, "directory") || strings.Contains(lowerContent, "path")) &&
			(strings.Contains(lowerContent, "enter") || strings.Contains(lowerContent, "current")) {
			return true
		}
	}

	return false
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
			if _, err := fmt.Fprintf(outputWriter, "[stdout] %s\n", line); err != nil {
				// Log error but continue
			}
		}
	}()

	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			if _, err := fmt.Fprintf(outputWriter, "[stderr] %s\n", line); err != nil {
				// Log error but continue
			}
		}
	}()

	wg.Wait()
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("command execution failed: %w", err)
	}
	return nil
}
