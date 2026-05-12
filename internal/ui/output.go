package ui

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"netutil/internal/executor"
	"netutil/internal/jobs"
)

type OutputViewer struct {
	*tview.Flex
	app        *tview.Application
	pages      *tview.Pages
	jobManager *jobs.JobManager
	str        *Strings

	outputView *tview.TextView
	inputField *tview.InputField
	statusLine *tview.TextView

	executor     *executor.StreamingExecutor
	result       *executor.StreamingResult
	outputLines  []executor.OutputLine
	scriptPath   string
	progressText string

	showTimestamp bool
	showSource    bool
	maxLines      int
	searchQuery   string

	running        bool
	paused         bool
	following      bool
	waitingInput   bool
	completed      bool
	passwordMode   bool
	connectedJobID string
	connectedJob   *jobs.Job
	mu             sync.RWMutex

	outputChan <-chan executor.OutputLine
	errorChan  <-chan error
	stopChan   chan struct{}
	stopOnce   sync.Once

	returnToMainCallback func()
}

func NewOutputViewer(app *tview.Application, pages *tview.Pages, jobManager *jobs.JobManager, returnToMainCallback func(), str *Strings) *OutputViewer {
	outputView := tview.NewTextView().
		SetDynamicColors(true).
		SetRegions(true).
		SetScrollable(true).
		SetWrap(true)

	inputField := tview.NewInputField().
		SetLabel("Input: ").
		SetFieldWidth(0).
		SetPlaceholder("Type your response here...")

	statusLine := tview.NewTextView().
		SetDynamicColors(true).
		SetText(str.StatusReady)

	flex := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(outputView, 0, 1, true).
		AddItem(statusLine, 1, 0, false).
		AddItem(inputField, 1, 0, false)

	ov := &OutputViewer{
		Flex:                 flex,
		app:                  app,
		pages:                pages,
		jobManager:           jobManager,
		outputView:           outputView,
		inputField:           inputField,
		statusLine:           statusLine,
		showTimestamp:        true,
		showSource:           false,
		maxLines:             1000,
		following:            true,
		stopChan:             make(chan struct{}),
		returnToMainCallback: returnToMainCallback,
		str:                  str,
	}

	ov.SetBorder(true).SetTitle(ov.str.PaneTitleScriptOutput)
	ov.setupKeyBindings()
	ov.setupInputField()

	return ov
}

func (ov *OutputViewer) setupKeyBindings() {
	ov.outputView.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEscape:
			ov.cancelJob()
			ov.Stop()
			if ov.returnToMainCallback != nil {
				ov.returnToMainCallback()
			} else {
				ov.pages.RemovePage("output")
			}
			return nil
		case tcell.KeyCtrlC:
			ov.Stop()
			return nil
		case tcell.KeyTab:
			ov.app.SetFocus(ov.inputField)
			ov.statusLine.SetText(ov.str.StatusInputMode)
			return nil
		}

		if event.Key() == tcell.KeyRune {
			switch event.Rune() {
			case 'q':
				ov.Stop()
				if ov.returnToMainCallback != nil {
					ov.returnToMainCallback()
				} else {
					ov.pages.RemovePage("output")
				}
				return nil
			case ' ':
				ov.TogglePause()
				return nil
			case 'f':
				ov.ToggleFollowing()
				return nil
			case 't':
				ov.ToggleTimestamp()
				return nil
			case 's':
				ov.ToggleSource()
				return nil
			case '/':
				ov.StartSearch()
				return nil
			case 'c':
				ov.Clear()
				return nil
			case 'G':
				ov.outputView.ScrollToEnd()
				return nil
			case 'g':
				ov.outputView.ScrollToBeginning()
				return nil
			case 'l':
				ov.app.SetFocus(ov.inputField)
				ov.statusLine.SetText(ov.str.StatusInputMode)
				return nil
			}
		}

		return event
	})
}

func (ov *OutputViewer) setupInputField() {
	ov.inputField.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEscape:
			ov.cancelJob()
			ov.Stop()
			if ov.returnToMainCallback != nil {
				ov.returnToMainCallback()
			} else {
				ov.pages.RemovePage("output")
			}
			return nil
		case tcell.KeyCtrlC:
			ov.Stop()
			return nil
		case tcell.KeyTab:
			ov.app.SetFocus(ov.outputView)
			ov.statusLine.SetText(ov.str.StatusViewMode)
			return nil
		case tcell.KeyEnter:
			ov.mu.RLock()
			isCompleted := ov.completed
			ov.mu.RUnlock()

			if isCompleted {
				ov.Stop()
				if ov.returnToMainCallback != nil {
					ov.returnToMainCallback()
				} else {
					ov.pages.RemovePage("output")
				}
				return nil
			}

			input := ov.inputField.GetText()
			ov.inputField.SetText("")
			go ov.sendInputToScript(input)
			return nil
		}

		return event
	})
}

func (ov *OutputViewer) sendInputToScript(input string) {
	ov.mu.Lock()
	isPassword := ov.passwordMode
	ov.passwordMode = false
	exec := ov.executor
	ov.mu.Unlock()

	if exec == nil {
		return
	}

	err := exec.SendInput(input)
	if err != nil {
		ov.addOutputLine(executor.OutputLine{
			Content:   fmt.Sprintf("Error sending input: %v", err),
			Timestamp: time.Now(),
			Source:    "system",
		})
		return
	}

	ov.mu.Lock()
	ov.waitingInput = false
	ov.mu.Unlock()
	if ov.connectedJob != nil {
		ov.connectedJob.SetNeedsInput(false)
	}

	if !isPassword {
		display := input
		if display == "" {
			display = "(default)"
		}
		ov.addOutputLine(executor.OutputLine{
			Content:   fmt.Sprintf("> %s", display),
			Timestamp: time.Now(),
			Source:    "input",
		})
	}

	ov.app.QueueUpdateDraw(func() {
		if isPassword {
			ov.inputField.SetMaskCharacter(0)
		}
		ov.statusLine.SetText(ov.str.StatusInputSent)
	})
}

func (ov *OutputViewer) StartScript(scriptPath string) error {
	ov.mu.Lock()
	defer ov.mu.Unlock()

	if ov.running {
		return fmt.Errorf("script is already running")
	}

	ov.executor = executor.NewStreamingExecutor()

	result, outputChan, errorChan := ov.executor.ExecuteScriptStreaming(scriptPath)
	ov.result = result
	ov.outputChan = outputChan
	ov.errorChan = errorChan
	ov.running = true
	ov.outputLines = make([]executor.OutputLine, 0)
	ov.scriptPath = scriptPath

	ov.updateTitleLocked(scriptPath, "Running")

	go ov.processOutput()

	return nil
}

func (ov *OutputViewer) ConnectToJob(job *jobs.Job) error {
	ov.mu.Lock()
	if ov.running {
		ov.mu.Unlock()
		return fmt.Errorf("viewer is already connected to a job")
	}

	if !job.IsRunning() {
		ov.mu.Unlock()
		return fmt.Errorf("job is not running")
	}

	ov.executor = job.Executor
	ov.result = job.Result
	ov.scriptPath = job.ScriptPath
	ov.connectedJobID = job.ID
	ov.connectedJob = job
	ov.running = true

	historicalLines := job.GetOutputLines()
	totalLines := len(historicalLines)
	startIdx := 0
	if totalLines > ov.maxLines {
		startIdx = totalLines - ov.maxLines
	}

	ov.outputLines = make([]executor.OutputLine, totalLines-startIdx)
	copy(ov.outputLines, historicalLines[startIdx:])

	if startIdx > 0 {
		truncMsg := executor.OutputLine{
			Content:   fmt.Sprintf(ov.str.FmtReconnected, ov.maxLines, totalLines),
			Timestamp: time.Now(),
			Source:    "system",
		}
		ov.outputLines = append([]executor.OutputLine{truncMsg}, ov.outputLines...)
	}

	ov.updateDisplayLocked()
	ov.updateTitleLocked(job.ScriptPath, "Running")
	ov.mu.Unlock()

	go ov.pollJobOutput(job, totalLines)
	return nil
}

func (ov *OutputViewer) pollJobOutput(job *jobs.Job, startIdx int) {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	lastIdx := startIdx

	for {
		select {
		case <-ticker.C:
			allLines := job.GetOutputLines()
			for i := lastIdx; i < len(allLines); i++ {
				line := allLines[i]
				if strings.HasPrefix(line.Content, "##NETUTIL:PROGRESS## ") {
					text := strings.TrimPrefix(line.Content, "##NETUTIL:PROGRESS## ")
					ov.mu.Lock()
					ov.progressText = text
					ov.mu.Unlock()
					ov.app.QueueUpdateDraw(func() {
						ov.statusLine.SetText(fmt.Sprintf(ov.str.FmtStatusProgress, text))
					})
					continue
				}
				ov.addOutputLine(line)
			}
			lastIdx = len(allLines)

			if !job.IsRunning() {
				allLines = job.GetOutputLines()
				for i := lastIdx; i < len(allLines); i++ {
					line := allLines[i]
					if !strings.HasPrefix(line.Content, "##NETUTIL:PROGRESS## ") {
						ov.addOutputLine(line)
					}
				}

				ov.mu.Lock()
				ov.running = false
				ov.completed = true
				status := "Completed"
			statusColor := colorGreen
				duration := time.Duration(0)
				if job.Result != nil {
					duration = job.Result.Duration
					if !job.Result.Success {
						status = "Failed"
						statusColor = "red"
					}
				}
				if job.GetStatus() == jobs.JobStatusCancelled {
					status = "Cancelled"
					statusColor = "gray"
				}
				ov.mu.Unlock()

				ov.addOutputLine(executor.OutputLine{
					Content:   "────────────────────────────────────────────────────────────────",
					Timestamp: time.Now(),
					Source:    "system",
				})
				ov.addOutputLine(executor.OutputLine{
					Content:   fmt.Sprintf(ov.str.FmtScriptCompleted, strings.ToLower(status), duration.Round(time.Second)),
					Timestamp: time.Now(),
					Source:    "system",
				})

				finalStatus := status
				finalColor := statusColor
				finalDuration := duration
				scriptPath := ov.scriptPath
				ov.app.QueueUpdateDraw(func() {
					ov.mu.Lock()
					ov.updateTitleLocked(scriptPath, fmt.Sprintf(ov.str.FmtScriptCompleted, strings.ToLower(finalStatus), finalDuration.Round(time.Second)))
					ov.mu.Unlock()
					ov.statusLine.SetText(fmt.Sprintf(ov.str.FmtStatusCompletion, finalColor))
				})
				return
			}

		case <-ov.stopChan:
			return
		}
	}
}

func (ov *OutputViewer) processOutput() {
	defer func() {
		ov.mu.Lock()
		ov.running = false
		ov.completed = true
		ov.mu.Unlock()

		if ov.result != nil {
			status := "Completed"
		statusColor := colorGreen
			if !ov.result.Success {
				status = "Failed"
				statusColor = "red"
			}

			ov.addOutputLine(executor.OutputLine{
				Content:   "────────────────────────────────────────────────────────────────",
				Timestamp: time.Now(),
				Source:    "system",
			})

			ov.addOutputLine(executor.OutputLine{
				Content:   fmt.Sprintf(ov.str.FmtScriptCompleted, strings.ToLower(status), ov.result.Duration.Round(time.Second)),
				Timestamp: time.Now(),
				Source:    "system",
			})

			finalStatus := status
			finalColor := statusColor
			scriptPath := ov.scriptPath
			result := ov.result
			ov.app.QueueUpdateDraw(func() {
				ov.mu.Lock()
				ov.updateTitleLocked(scriptPath, fmt.Sprintf(ov.str.FmtScriptCompleted, strings.ToLower(finalStatus), result.Duration.Round(time.Second)))
				ov.mu.Unlock()
				ov.statusLine.SetText(fmt.Sprintf(ov.str.FmtStatusCompletion, finalColor))
			})
		}
	}()

	for {
		select {
		case line, ok := <-ov.outputChan:
			if !ok {
				return
			}
			if strings.HasPrefix(line.Content, "##NETUTIL:PROGRESS## ") {
				text := strings.TrimPrefix(line.Content, "##NETUTIL:PROGRESS## ")
				ov.mu.Lock()
				ov.progressText = text
				ov.mu.Unlock()
				ov.app.QueueUpdateDraw(func() {
					ov.statusLine.SetText(fmt.Sprintf(ov.str.FmtStatusProgress, text))
				})
				continue
			}
			ov.addOutputLine(line)

		case err, ok := <-ov.errorChan:
			if !ok {
				return
			}
			if err != nil {
				errorLine := executor.OutputLine{
					Content:   fmt.Sprintf("ERROR: %v", err),
					Timestamp: time.Now(),
					Source:    "error",
				}
				ov.addOutputLine(errorLine)
			}

		case <-ov.stopChan:
			return
		}
	}
}

func (ov *OutputViewer) addOutputLine(line executor.OutputLine) {
	ov.mu.Lock()
	ov.outputLines = append(ov.outputLines, line)
	if len(ov.outputLines) > ov.maxLines {
		ov.outputLines = ov.outputLines[len(ov.outputLines)-ov.maxLines:]
	}
	isPaused := ov.paused
	ov.mu.Unlock()

	ov.handlePromptDetection(line)

	if !isPaused {
		ov.app.QueueUpdateDraw(func() {
			ov.mu.RLock()
			defer ov.mu.RUnlock()
			ov.updateDisplayLocked()
		})
	}
}

func (ov *OutputViewer) handlePromptDetection(line executor.OutputLine) {
	stripped := jobs.StripANSI(line.Content)
	if line.Source != "stderr" {
		return
	}

	if jobs.DetectScriptPrompt(stripped) {
		ov.mu.Lock()
		ov.waitingInput = true
		ov.mu.Unlock()
		if ov.connectedJob != nil {
			ov.connectedJob.SetNeedsInput(true)
		}
		ov.app.QueueUpdateDraw(func() {
			if ov.HasFocus() {
				ov.app.SetFocus(ov.inputField)
				ov.statusLine.SetText(ov.str.StatusWaitingInput)
			}
		})
	}

	if jobs.DetectPasswordPrompt(stripped) {
		ov.mu.Lock()
		ov.passwordMode = true
		ov.mu.Unlock()
		if ov.connectedJob != nil {
			ov.connectedJob.SetNeedsInput(true)
		}
		ov.app.QueueUpdateDraw(func() {
			if ov.HasFocus() {
				ov.inputField.SetMaskCharacter('*')
				ov.app.SetFocus(ov.inputField)
				ov.statusLine.SetText(ov.str.StatusPasswordInput)
			}
		})
	}

	// Auto-reset: if we were waiting for input but a new non-prompt
	// stderr line arrived, the prompt was a false positive or was
	// answered by background output — clear the waiting state.
	if ov.waitingInput && !jobs.DetectScriptPrompt(stripped) && !jobs.DetectPasswordPrompt(stripped) {
		ov.mu.Lock()
		ov.waitingInput = false
		ov.mu.Unlock()
		if ov.connectedJob != nil {
			ov.connectedJob.SetNeedsInput(false)
		}
	}
}


func (ov *OutputViewer) updateDisplayLocked() {
	lines := ov.outputLines

	if ov.searchQuery != "" {
		lines = executor.SearchOutput(lines, ov.searchQuery)
	}

	content := ov.formatLinesLocked(lines)
	ov.outputView.SetText(content)

	if ov.following {
		ov.outputView.ScrollToEnd()
	}
}

func (ov *OutputViewer) formatLinesLocked(lines []executor.OutputLine) string {
	var content strings.Builder

	for _, line := range lines {
		if ov.showTimestamp {
		fmt.Fprintf(&content, "[gray]%s[white] ",
			line.Timestamp.Format("15:04:05"))
		}

		if ov.showSource {
			color := "white"
			switch line.Source {
			case "stderr":
				color = "red"
			case "error":
				color = "red"
			case "stdout":
			color = colorGreen
			}
		fmt.Fprintf(&content, "[%s]%s[white] ", color, line.Source)
		}

		lineContent := tview.TranslateANSI(line.Content)

		if !strings.Contains(lineContent, "[") {
			if strings.Contains(strings.ToLower(lineContent), "error") {
				lineContent = fmt.Sprintf("[red]%s[white]", lineContent)
			} else if strings.Contains(strings.ToLower(lineContent), "warning") {
				lineContent = fmt.Sprintf("[yellow]%s[white]", lineContent)
			} else if strings.Contains(strings.ToLower(lineContent), "success") {
				lineContent = fmt.Sprintf("[green]%s[white]", lineContent)
			}
		}

		content.WriteString(lineContent)
		content.WriteString("\n")
	}

	return content.String()
}


func (ov *OutputViewer) ShowHistoricalOutput(jobName string, status jobs.JobStatus, lines []executor.OutputLine) {
	ov.mu.Lock()
	ov.outputLines = append(ov.outputLines, lines...)
	if len(ov.outputLines) > ov.maxLines {
		ov.outputLines = ov.outputLines[len(ov.outputLines)-ov.maxLines:]
	}
	ov.completed = true
	ov.updateDisplayLocked()
	ov.mu.Unlock()

	statusColor := colorGreen
	switch status {
	case jobs.JobStatusFailed:
		statusColor = "red"
	case jobs.JobStatusCancelled:
		statusColor = "gray"
	}

	ov.SetTitle(fmt.Sprintf("Output - %s [%s]", jobName, string(status)))
	ov.statusLine.SetText(fmt.Sprintf(ov.str.FmtHistoricalStatus, statusColor, string(status)))
}

// cancelJob attempts to cancel the running job if connected via ConnectToJob.
// If no job is connected (e.g. StartScript path), this is a no-op.
func (ov *OutputViewer) cancelJob() {
	ov.mu.RLock()
	jobID := ov.connectedJobID
	ov.mu.RUnlock()

	if jobID != "" && ov.jobManager != nil {
		if err := ov.jobManager.CancelJob(jobID); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to cancel job %s: %v\n", jobID, err)
		}
	}
}

// CancelAndReturn cancels the running job, stops the viewer, and returns to main.
// This is the Ctrl+C / Esc action: kill the job and go back.
func (ov *OutputViewer) CancelAndReturn() {
	ov.cancelJob()
	ov.Stop()
	if ov.returnToMainCallback != nil {
		ov.returnToMainCallback()
	} else {
		ov.pages.RemovePage("output")
	}
}
func (ov *OutputViewer) Stop() {
	ov.mu.Lock()
	if !ov.running {
		ov.mu.Unlock()
		return
	}
	ov.running = false
	ov.connectedJobID = ""
	ov.connectedJob = nil
	ov.mu.Unlock()

	ov.stopOnce.Do(func() { close(ov.stopChan) })
}

func (ov *OutputViewer) TogglePause() {
	ov.mu.Lock()
	ov.paused = !ov.paused
	resuming := !ov.paused
	status := "Paused"
	if resuming {
		status = "Running"
	}
	ov.updateTitleLocked(ov.scriptPath, status)
	if resuming {
		ov.updateDisplayLocked()
	}
	ov.mu.Unlock()
}

func (ov *OutputViewer) ToggleFollowing() {
	ov.mu.Lock()
	defer ov.mu.Unlock()

	ov.following = !ov.following
}

func (ov *OutputViewer) ToggleTimestamp() {
	ov.mu.Lock()
	ov.showTimestamp = !ov.showTimestamp
	ov.updateDisplayLocked()
	ov.mu.Unlock()
}

func (ov *OutputViewer) ToggleSource() {
	ov.mu.Lock()
	ov.showSource = !ov.showSource
	ov.updateDisplayLocked()
	ov.mu.Unlock()
}

func (ov *OutputViewer) StartSearch() {
	var searchInput *tview.InputField

	closeSearch := func() {
		ov.pages.RemovePage("search")
		ov.app.SetFocus(ov)
	}

	searchInput = tview.NewInputField().
		SetLabel("Search (Esc=clear, Enter=apply): ").
		SetFieldWidth(0).
		SetText(ov.searchQuery).
		SetDoneFunc(func(key tcell.Key) {
			switch key {
			case tcell.KeyEnter:
				ov.SetSearchQuery(searchInput.GetText())
				closeSearch()
			case tcell.KeyEscape:
				ov.SetSearchQuery("")
				closeSearch()
			}
		})

	box := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(nil, 0, 1, false).
		AddItem(
			tview.NewFlex().SetDirection(tview.FlexColumn).
				AddItem(nil, 0, 1, false).
				AddItem(searchInput, 50, 0, true).
				AddItem(nil, 0, 1, false),
			3, 0, true,
		).
		AddItem(nil, 0, 1, false)

	searchInput.SetBorder(true).SetTitle(ov.str.PaneTitleSearchOutput)

	ov.pages.AddPage("search", box, true, true)
	ov.app.SetFocus(searchInput)
}

func (ov *OutputViewer) SetSearchQuery(query string) {
	ov.mu.Lock()
	ov.searchQuery = query
	ov.updateDisplayLocked()
	ov.mu.Unlock()
}

func (ov *OutputViewer) Clear() {
	ov.mu.Lock()
	ov.outputLines = make([]executor.OutputLine, 0)
	ov.outputView.SetText("")
	ov.mu.Unlock()
}

func (ov *OutputViewer) SendInput(input string) error {
	ov.mu.RLock()
	defer ov.mu.RUnlock()

	if !ov.running || ov.executor == nil {
		return fmt.Errorf("no script is running")
	}

	return ov.executor.SendInput(input)
}

func (ov *OutputViewer) IsRunning() bool {
	ov.mu.RLock()
	defer ov.mu.RUnlock()
	return ov.running
}

func (ov *OutputViewer) GetResult() *executor.StreamingResult {
	ov.mu.RLock()
	defer ov.mu.RUnlock()
	return ov.result
}

func (ov *OutputViewer) GetOutputLines() []executor.OutputLine {
	ov.mu.RLock()
	defer ov.mu.RUnlock()
	return append([]executor.OutputLine{}, ov.outputLines...)
}

func (ov *OutputViewer) ShowHelp() {
	helpModal := tview.NewModal().
		SetText(ov.str.OutputViewerHelp).
		AddButtons([]string{ov.str.BtnClose}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			ov.pages.RemovePage("output-help")
		})

	ov.pages.AddPage("output-help", helpModal, true, true)
}

func (ov *OutputViewer) FocusView() {
	ov.app.SetFocus(ov.outputView)
}

func (ov *OutputViewer) updateTitleLocked(scriptPath, status string) {
	var title string
	if ov.jobManager != nil {
		stats := ov.jobManager.GetStats()
		jobCount := fmt.Sprintf("[%d/%d Jobs]", stats.RunningJobs, stats.MaxConcurrent)
		scriptName := scriptPath
		if idx := strings.LastIndex(scriptPath, "/"); idx != -1 {
			scriptName = scriptPath[idx+1:]
		}
		title = fmt.Sprintf(ov.str.FmtTitleWithJobs, jobCount, scriptName, status)
	} else {
		title = fmt.Sprintf(ov.str.FmtTitleNoJobs, scriptPath, status)
	}
	ov.SetTitle(title)
}
