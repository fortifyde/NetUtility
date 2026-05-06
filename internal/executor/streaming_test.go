package executor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeScript writes a small shell script to a temp file and returns its path.
func writeScript(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+content), 0755); err != nil {
		t.Fatalf("writeScript: %v", err)
	}
	return path
}

func TestExecuteScriptStreaming_Success(t *testing.T) {
	script := writeScript(t, `echo hello
echo world
exit 0`)
	e := NewStreamingExecutor()
	result, outCh, errCh := e.ExecuteScriptStreaming(script)
	if result == nil {
		t.Fatal("result is nil")
	}
	var lines []OutputLine
	for line := range outCh {
		lines = append(lines, line)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	e.Wait()
	success, _, _, _, _ := result.GetFinal()
	if !success {
		t.Error("expected success=true")
	}
	var contents []string
	for _, l := range lines {
		contents = append(contents, l.Content)
	}
	joined := strings.Join(contents, "\n")
	if !strings.Contains(joined, "hello") || !strings.Contains(joined, "world") {
		t.Errorf("expected 'hello' and 'world' in output, got: %q", joined)
	}
}

func TestExecuteScriptStreaming_NonZeroExit(t *testing.T) {
	script := writeScript(t, `echo failing; exit 1`)
	e := NewStreamingExecutor()
	result, outCh, _ := e.ExecuteScriptStreaming(script)
	for range outCh {
	}
	e.Wait()
	success, exitCode, _, _, _ := result.GetFinal()
	if success {
		t.Error("expected success=false for non-zero exit")
	}
	if exitCode != 1 {
		t.Errorf("exitCode = %d, want 1", exitCode)
	}
}

func TestExecuteScriptStreaming_MissingScript(t *testing.T) {
	e := NewStreamingExecutor()
	result, outCh, errCh := e.ExecuteScriptStreaming("/nonexistent/path/script.sh")
	if outCh != nil {
		t.Error("expected nil outCh for missing script")
	}
	err := <-errCh
	if err == nil {
		t.Error("expected error for missing script")
	}
	_ = result
}

func TestExecuteScriptStreaming_Cancellation(t *testing.T) {
	script := writeScript(t, `while true; do echo tick; sleep 0.1; done`)
	e := NewStreamingExecutor()
	_, outCh, _ := e.ExecuteScriptStreaming(script)

	// Let a few lines through then cancel
	for i := 0; i < 3; i++ {
		select {
		case <-outCh:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for output")
		}
	}
	_ = e.Stop()
	e.Wait()
	if e.IsRunning() {
		t.Error("executor should not be running after Stop()")
	}
	// Drain remaining
	for range outCh {
	}
}

func TestExecuteScriptStreaming_AlreadyRunning(t *testing.T) {
	script := writeScript(t, `sleep 5`)
	e := NewStreamingExecutor()
	_, outCh, _ := e.ExecuteScriptStreaming(script)
	defer func() {
		_ = e.Stop()
		e.Wait()
		for range outCh {
		}
	}()

	_, _, errCh2 := e.ExecuteScriptStreaming(script)
	err := <-errCh2
	if err == nil || !strings.Contains(err.Error(), "already running") {
		t.Errorf("expected 'already running' error, got: %v", err)
	}
}

func TestGetOutputHistory(t *testing.T) {
	script := writeScript(t, `echo line1
echo line2
echo line3`)
	e := NewStreamingExecutor()
	result, outCh, _ := e.ExecuteScriptStreaming(script)
	for range outCh {
	}
	e.Wait()
	history := e.GetOutputHistory(result)
	if len(history) < 3 {
		t.Errorf("GetOutputHistory returned %d lines, want at least 3", len(history))
	}
}

func TestSetFinalGetFinal_Concurrent(t *testing.T) {
	result := &StreamingResult{
		StartTime:   time.Now(),
		OutputLines: make([]OutputLine, 0),
	}
	done := make(chan struct{})
	go func() {
		time.Sleep(10 * time.Millisecond)
		result.SetFinal(true, 0, nil, time.Now())
		close(done)
	}()
	deadline := time.After(500 * time.Millisecond)
	for {
		select {
		case <-done:
			return
		case <-deadline:
			t.Fatal("timed out waiting for SetFinal")
		default:
		_, _, _, _, _ = result.GetFinal()
		}
	}
}

func TestStreamingResult_NilHandling(t *testing.T) {
	e := NewStreamingExecutor()
	if hist := e.GetOutputHistory(nil); hist != nil {
		t.Error("GetOutputHistory(nil) should return nil")
	}
}

func TestFormatOutput(t *testing.T) {
	ts := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	lines := []OutputLine{
		{Content: "hello", Timestamp: ts, Source: "stdout"},
		{Content: "world", Timestamp: ts, Source: "stderr"},
	}
	out := FormatOutput(lines, false, false)
	if !strings.Contains(out, "hello") || !strings.Contains(out, "world") {
		t.Errorf("unexpected output: %q", out)
	}
	withSource := FormatOutput(lines, false, true)
	if !strings.Contains(withSource, "[stdout]") || !strings.Contains(withSource, "[stderr]") {
		t.Errorf("expected source tags, got: %q", withSource)
	}
}

func TestTailOutput(t *testing.T) {
	lines := make([]OutputLine, 10)
	for i := range lines {
		lines[i] = OutputLine{Content: fmt.Sprintf("line%d", i)}
	}
	tail := TailOutput(lines, 3)
	if len(tail) != 3 {
		t.Errorf("TailOutput(10, 3) returned %d lines, want 3", len(tail))
	}
	if tail[0].Content != "line7" {
		t.Errorf("first tail line = %q, want line7", tail[0].Content)
	}
	all := TailOutput(lines, 20)
	if len(all) != 10 {
		t.Errorf("TailOutput(10, 20) returned %d lines, want 10", len(all))
	}
}

func TestSearchOutput(t *testing.T) {
	lines := []OutputLine{
		{Content: "ERROR: disk full"},
		{Content: "INFO: running"},
		{Content: "error: timeout"},
	}
	matches := SearchOutput(lines, "error")
	if len(matches) != 2 {
		t.Errorf("SearchOutput returned %d matches, want 2", len(matches))
	}
}

func TestFilterOutput(t *testing.T) {
	lines := []OutputLine{
		{Content: "out1", Source: "stdout"},
		{Content: "err1", Source: "stderr"},
		{Content: "out2", Source: "stdout"},
	}
	stdout := FilterOutput(lines, "stdout")
	if len(stdout) != 2 {
		t.Errorf("FilterOutput(stdout) = %d lines, want 2", len(stdout))
	}
	stderr := FilterOutput(lines, "stderr")
	if len(stderr) != 1 {
		t.Errorf("FilterOutput(stderr) = %d lines, want 1", len(stderr))
	}
}
