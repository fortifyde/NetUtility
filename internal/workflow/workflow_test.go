package workflow

import (
	"fmt"
	"testing"
	"time"

	"netutil/internal/correlation"
	"netutil/internal/jobs"
)

// newTestEngine creates a workflow engine with real dependencies for testing.
func newTestEngine() *WorkflowEngine {
	jm := jobs.NewJobManager(5)
	corr := correlation.NewCorrelator("/tmp/test-workspace")
	return NewWorkflowEngine(jm, corr, nil)
}

func TestCreateWorkflow(t *testing.T) {
	we := newTestEngine()
	w := we.CreateWorkflow("wf1", "Test Workflow", "A test")
	if w.ID != "wf1" {
		t.Errorf("ID = %q, want wf1", w.ID)
	}
	if w.Status != WorkflowStatusPending {
		t.Errorf("Status = %q, want pending", w.Status)
	}
	got, ok := we.GetWorkflow("wf1")
	if !ok || got != w {
		t.Error("GetWorkflow did not return the created workflow")
	}
}

func TestAddScriptStep(t *testing.T) {
	we := newTestEngine()
	w := we.CreateWorkflow("wf1", "Test", "")
	step := w.AddScriptStep("s1", "Scan", "/scripts/scan.sh", true)
	if step.ID != "s1" || step.ScriptPath != "/scripts/scan.sh" {
		t.Errorf("step fields wrong: ID=%q ScriptPath=%q", step.ID, step.ScriptPath)
	}
	if _, ok := w.Steps["s1"]; !ok {
		t.Error("step not added to workflow.Steps")
	}
}

func TestCompareValues(t *testing.T) {
	we := newTestEngine()
	tests := []struct {
		actual   any
		operator string
		expected any
		want     bool
		wantErr  bool
	}{
		{5, ">", 3, true, false},
		{3, ">", 5, false, false},
		{5, "<", 10, true, false},
		{5, "==", 5, true, false},
		{5, "!=", 3, true, false},
		{5, ">=", 5, true, false},
		{4, ">=", 5, false, false},
		{5, "<=", 5, true, false},
		{6, "<=", 5, false, false},
		{"hello", "==", "hello", true, false},
		{5, "unknown", 5, false, true},
	}
	for _, tt := range tests {
		got, err := we.compareValues(tt.actual, tt.operator, tt.expected)
		if tt.wantErr && err == nil {
			t.Errorf("compareValues(%v, %q, %v) expected error, got nil", tt.actual, tt.operator, tt.expected)
			continue
		}
		if !tt.wantErr && err != nil {
			t.Errorf("compareValues(%v, %q, %v) unexpected error: %v", tt.actual, tt.operator, tt.expected, err)
			continue
		}
		if got != tt.want {
			t.Errorf("compareValues(%v, %q, %v) = %v, want %v", tt.actual, tt.operator, tt.expected, got, tt.want)
		}
	}
}

func TestWorkflowStep_Helpers(t *testing.T) {
	step := &WorkflowStep{ID: "s1", Name: "test"}
	// Initial status should be zero value
	step.setRunning()
	if step.getStatus() != WorkflowStatusRunning {
		t.Error("setRunning: expected running status")
	}
	step.setDone(WorkflowStatusCompleted, nil)
	if step.getStatus() != WorkflowStatusCompleted {
		t.Error("setDone completed: expected completed status")
	}
	step2 := &WorkflowStep{ID: "s2"}
	testErr := fmt.Errorf("something failed")
	step2.setDone(WorkflowStatusFailed, testErr)
	step2.mu.Lock()
	gotErr := step2.Error
	step2.mu.Unlock()
	if gotErr != testErr {
		t.Errorf("Error = %v, want %v", gotErr, testErr)
	}
}

func TestGetDiscoveredHosts_Deduplication(t *testing.T) {
	we := newTestEngine()
	w := we.CreateWorkflow("wf1", "test", "")
	w.Results["r1"] = &correlation.ScanResult{
		Hosts: []correlation.Host{
			{IP: "192.168.1.1"},
			{IP: "192.168.1.2"},
		},
	}
	w.Results["r2"] = &correlation.ScanResult{
		Hosts: []correlation.Host{
			{IP: "192.168.1.1"}, // duplicate
			{IP: "192.168.1.3"},
		},
	}
	hosts := we.getDiscoveredHosts(w)
	if len(hosts) != 3 {
		t.Errorf("getDiscoveredHosts returned %d unique hosts, want 3", len(hosts))
	}
}

func TestExecuteDelayStep(t *testing.T) {
	we := newTestEngine()
	w := we.CreateWorkflow("wf1", "test", "")
	step := &WorkflowStep{
		ID:    "s1",
		Type:  StepTypeDelay,
		Delay: time.Nanosecond,
	}
	success, err := we.executeDelayStep(w, step)
	if !success || err != nil {
		t.Errorf("executeDelayStep = (%v, %v), want (true, nil)", success, err)
	}
}

func TestCancelWorkflow(t *testing.T) {
	we := newTestEngine()
	w := we.CreateWorkflow("wf1", "test", "")
	w.mu.Lock()
	w.Status = WorkflowStatusRunning
	w.mu.Unlock()

	if err := we.CancelWorkflow("wf1"); err != nil {
		t.Fatalf("CancelWorkflow error: %v", err)
	}
	w.mu.RLock()
	status := w.Status
	w.mu.RUnlock()
	if status != WorkflowStatusCancelled {
		t.Errorf("Status = %q, want cancelled", status)
	}
	// Cancel non-running workflow should error
	if err := we.CancelWorkflow("wf1"); err == nil {
		t.Error("CancelWorkflow on non-running workflow should return error")
	}
}

func TestWorkflow_SetStartSteps(t *testing.T) {
	we := newTestEngine()
	w := we.CreateWorkflow("wf1", "test", "")
	w.AddScriptStep("s1", "step1", "/tmp/s1.sh", true)
	w.AddScriptStep("s2", "step2", "/tmp/s2.sh", false)
	w.SetStartSteps([]string{"s1", "s2"})
	w.mu.RLock()
	starts := w.StartSteps
	w.mu.RUnlock()
	if len(starts) != 2 {
		t.Errorf("StartSteps len = %d, want 2", len(starts))
	}
}

func TestGetAllWorkflows(t *testing.T) {
	we := newTestEngine()
	we.CreateWorkflow("wf1", "A", "")
	we.CreateWorkflow("wf2", "B", "")
	all := we.GetAllWorkflows()
	if len(all) != 2 {
		t.Errorf("GetAllWorkflows returned %d, want 2", len(all))
	}
}
