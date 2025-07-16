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
)

type Executor struct {
	outputChan    chan string
	errorChan     chan error
	doneChan      chan bool
	inputChan     chan string
	promptChan    chan string
	mu            sync.RWMutex
	running       bool
	activeWG      sync.WaitGroup // Tracks active goroutines from current execution
	stdin         io.WriteCloser
	interactive   bool
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
	inputChan   chan string
	doneChan    chan bool
	errorChan   chan error
	outputChan  chan string
	ctx         context.Context
	cancel      context.CancelFunc
	cmd         *exec.Cmd
	stdin       io.WriteCloser
	mu          sync.RWMutex
	active      bool
	result      *ScriptResult
	resultReady chan bool
}

func NewExecutor() *Executor {
	return &Executor{
		outputChan: make(chan string, 100),
		errorChan:  make(chan error, 10),
		doneChan:   make(chan bool, 1),
		inputChan:  make(chan string, 10),
		promptChan: make(chan string, 10),
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
		ctx:         sessionCtx,
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

	select {
	case s.inputChan <- input:
		return nil
	case <-s.ctx.Done():
		return fmt.Errorf("session context cancelled")
	default:
		return fmt.Errorf("input channel is full")
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
	case <-s.ctx.Done():
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

	s.cancel()
	if s.cmd != nil && s.cmd.Process != nil {
		return s.cmd.Process.Kill()
	}

	return nil
}

// cleanup performs cleanup operations for the session
func (s *InteractiveSession) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.active = false
	close(s.inputChan)
	close(s.outputChan)
	close(s.errorChan)

	if s.stdin != nil {
		s.stdin.Close()
	}

	select {
	case s.doneChan <- true:
	default:
	}

	close(s.doneChan)
}

func (e *Executor) resetChannels() {
	e.outputChan = make(chan string, 100)
	e.errorChan = make(chan error, 10)
	e.doneChan = make(chan bool, 1)
	e.inputChan = make(chan string, 10)
	e.promptChan = make(chan string, 10)
}

func (e *Executor) ExecuteScript(ctx context.Context, scriptPath string, args ...string) (*ScriptResult, error) {
	return e.ExecuteScriptWithInput(ctx, scriptPath, "", args...)
}

func (e *Executor) ExecuteInteractiveScriptLegacy(ctx context.Context, scriptPath string, args ...string) (*ScriptResult, error) {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return nil, fmt.Errorf("executor is already running a script")
	}
	e.running = true
	e.interactive = true
	e.mu.Unlock()

	// Wait for any previous execution's goroutines to complete
	e.activeWG.Wait()

	// Reset channels after all goroutines have finished
	e.resetChannels()

	defer func() {
		e.mu.Lock()
		e.running = false
		e.interactive = false
		if e.stdin != nil {
			e.stdin.Close()
			e.stdin = nil
		}
		e.mu.Unlock()
	}()

	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("script file does not exist: %s", scriptPath)
	}

	cmd := exec.CommandContext(ctx, "bash", append([]string{scriptPath}, args...)...)

	// Set up stdin for interactive mode
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}
	e.stdin = stdin

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

	wg.Add(3)         // stdout, stderr, and input handler
	e.activeWG.Add(4) // Add all 4 goroutines to the activeWG

	// Handle input forwarding
	go func() {
		defer e.activeWG.Done()
		for {
			select {
			case input := <-e.inputChan:
				if e.stdin != nil {
					if _, err := e.stdin.Write([]byte(input + "\n")); err != nil {
						return
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Handle stdout
	go func() {
		defer wg.Done()
		defer e.activeWG.Done()
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			mu.Lock()
			output += line + "\n"
			mu.Unlock()

			// Check if this line contains a prompt
			if e.isPromptLine(line) {
				select {
				case e.promptChan <- line:
				case <-ctx.Done():
					return
				}
			}

			select {
			case e.outputChan <- "[stdout] " + line:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Handle stderr
	go func() {
		defer wg.Done()
		defer e.activeWG.Done()
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

	// Wait for completion
	go func() {
		defer e.activeWG.Done()
		wg.Wait()
		select {
		case e.doneChan <- true:
		default:
		}
		close(e.outputChan)
		close(e.promptChan)
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
	cmd := exec.CommandContext(session.ctx, "bash", append([]string{scriptPath}, args...)...)
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

	wg.Add(3) // stdout, stderr, and input handler

	// Handle input forwarding
	go func() {
		defer wg.Done()
		for {
			select {
			case input := <-session.inputChan:
				if session.stdin != nil {
					if _, err := session.stdin.Write([]byte(input + "\n")); err != nil {
						return
					}
				}
			case <-session.ctx.Done():
				return
			}
		}
	}()

	// Handle stdout
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			mu.Lock()
			output += line + "\n"
			mu.Unlock()

			select {
			case session.outputChan <- "[stdout] " + line:
			case <-session.ctx.Done():
				return
			}
		}
	}()

	// Handle stderr
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			mu.Lock()
			output += "[ERROR] " + line + "\n"
			mu.Unlock()

			select {
			case session.outputChan <- "[stderr] " + line:
			case <-session.ctx.Done():
				return
			}
		}
	}()

	// Handle completion
	go func() {
		wg.Wait()

		// Wait for command to complete
		err := cmd.Wait()

		// Prepare result
		result := &ScriptResult{
			Success: err == nil,
			Output:  output,
			Error:   err,
		}

		session.mu.Lock()
		session.result = result
		session.mu.Unlock()

		// Signal result is ready
		select {
		case session.resultReady <- true:
		default:
		}

		// Clean up session
		session.cleanup()

		// Remove from active sessions
		e.sessionMu.Lock()
		if e.activeSession == session {
			e.activeSession = nil
		}
		e.sessionMu.Unlock()
	}()

	return session, nil
}

func (e *Executor) ExecuteScriptWithInput(ctx context.Context, scriptPath string, input string, args ...string) (*ScriptResult, error) {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return nil, fmt.Errorf("executor is already running a script")
	}
	e.running = true
	e.mu.Unlock()

	// Wait for any previous execution's goroutines to complete
	e.activeWG.Wait()

	// Reset channels after all goroutines have finished
	e.resetChannels()

	defer func() {
		e.mu.Lock()
		e.running = false
		e.mu.Unlock()
	}()

	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("script file does not exist: %s", scriptPath)
	}

	cmd := exec.CommandContext(ctx, "bash", append([]string{scriptPath}, args...)...)

	// Set up stdin - provide input or EOF for interactive scripts
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	// If input is provided, write it to stdin, otherwise close immediately
	if input != "" {
		go func() {
			defer stdin.Close()
			stdin.Write([]byte(input))
		}()
	} else {
		// Close stdin immediately to provide EOF, preventing scripts from hanging
		stdin.Close()
	}

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
	e.activeWG.Add(3) // Add all 3 goroutines to the activeWG

	go func() {
		defer wg.Done()
		defer e.activeWG.Done()
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
		defer e.activeWG.Done()
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
		defer e.activeWG.Done()
		wg.Wait()
		select {
		case e.doneChan <- true:
		default:
		}
		close(e.outputChan)
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

func (e *Executor) GetInputChannel() chan<- string {
	return e.inputChan
}

func (e *Executor) GetPromptChannel() <-chan string {
	return e.promptChan
}

func (e *Executor) SendInput(input string) {
	select {
	case e.inputChan <- input:
	default:
		// Input channel is full, ignore
	}
}

func (e *Executor) IsRunning() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.running
}

func (e *Executor) IsInteractive() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.interactive
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
