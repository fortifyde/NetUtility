package workflow

import (
	"fmt"
	"sync"
	"time"

	"netutil/internal/correlation"
	"netutil/internal/executor"
	"netutil/internal/jobs"
	"netutil/internal/metadata"
)

// WorkflowStatus represents the current state of a workflow
type WorkflowStatus string

const (
	WorkflowStatusPending   WorkflowStatus = "pending"
	WorkflowStatusRunning   WorkflowStatus = "running"
	WorkflowStatusCompleted WorkflowStatus = "completed"
	WorkflowStatusFailed    WorkflowStatus = "failed"
	WorkflowStatusCancelled WorkflowStatus = "cancelled"
	WorkflowStatusPaused    WorkflowStatus = "paused"
)

// StepType represents different types of workflow steps
type StepType string

const (
	StepTypeScript      StepType = "script"
	StepTypeCondition   StepType = "condition"
	StepTypeDelay       StepType = "delay"
	StepTypeParallel    StepType = "parallel"
	StepTypeCorrelation StepType = "correlation"
)

// ConditionType represents different types of conditions
type ConditionType string

const (
	ConditionTypeHostsFound    ConditionType = "hosts_found"
	ConditionTypeServicesFound ConditionType = "services_found"
	ConditionTypeVulnsFound    ConditionType = "vulnerabilities_found"
	ConditionTypePortOpen      ConditionType = "port_open"
	ConditionTypeScriptSuccess ConditionType = "script_success"
	ConditionTypeRiskScore     ConditionType = "risk_score"
	ConditionTypeTimeElapsed   ConditionType = "time_elapsed"
)

// WorkflowStep represents a single step in a workflow
type WorkflowStep struct {
	ID         string                    `json:"id"`
	Name       string                    `json:"name"`
	Type       StepType                  `json:"type"`
	ScriptPath string                    `json:"script_path,omitempty"`
	Parameters map[string]string         `json:"parameters,omitempty"`
	Condition  *StepCondition            `json:"condition,omitempty"`
	OnSuccess  []string                  `json:"on_success,omitempty"` // Step IDs to execute on success
	OnFailure  []string                  `json:"on_failure,omitempty"` // Step IDs to execute on failure
	Timeout    time.Duration             `json:"timeout,omitempty"`
	Delay      time.Duration             `json:"delay,omitempty"`
	Parallel   []string                  `json:"parallel,omitempty"` // Step IDs to execute in parallel
	Required   bool                      `json:"required"`           // Whether workflow should fail if this step fails
	Retries    int                       `json:"retries,omitempty"`
	Status     WorkflowStatus            `json:"status"`
	StartTime  time.Time                 `json:"start_time,omitempty"`
	EndTime    time.Time                 `json:"end_time,omitempty"`
	Duration   time.Duration             `json:"duration,omitempty"`
	Result     *executor.StreamingResult `json:"result,omitempty"`
	Error      error                     `json:"error,omitempty"`
	Metadata   map[string]interface{}    `json:"metadata,omitempty"`
}

// StepCondition represents a condition for conditional execution
type StepCondition struct {
	Type     ConditionType          `json:"type"`
	Target   string                 `json:"target,omitempty"` // IP, port number, etc.
	Operator string                 `json:"operator"`         // >, <, ==, !=, contains, etc.
	Value    interface{}            `json:"value"`
	StepID   string                 `json:"step_id,omitempty"` // Reference to another step
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Workflow represents a complete automation workflow
type Workflow struct {
	ID          string                             `json:"id"`
	Name        string                             `json:"name"`
	Description string                             `json:"description"`
	Steps       map[string]*WorkflowStep           `json:"steps"`
	StartSteps  []string                           `json:"start_steps"` // Initial steps to execute
	Status      WorkflowStatus                     `json:"status"`
	StartTime   time.Time                          `json:"start_time,omitempty"`
	EndTime     time.Time                          `json:"end_time,omitempty"`
	Duration    time.Duration                      `json:"duration,omitempty"`
	Progress    float64                            `json:"progress"`            // 0.0 to 1.0
	Variables   map[string]string                  `json:"variables,omitempty"` // Workflow variables
	Results     map[string]*correlation.ScanResult `json:"results,omitempty"`
	Metadata    map[string]interface{}             `json:"metadata,omitempty"`

	// Runtime state
	completedSteps map[string]bool
	runningSteps   map[string]bool
	mu             sync.RWMutex
}

// WorkflowEngine manages workflow execution
type WorkflowEngine struct {
	workflows  map[string]*Workflow
	jobManager *jobs.JobManager
	correlator *correlation.Correlator
	registry   *metadata.ScriptRegistry
	mu         sync.RWMutex

	// Event channels
	stepStartedChan   chan *WorkflowStepEvent
	stepCompletedChan chan *WorkflowStepEvent
	workflowDoneChan  chan *WorkflowEvent
	stopChan          chan struct{}
}

// WorkflowStepEvent represents a workflow step event
type WorkflowStepEvent struct {
	WorkflowID string
	StepID     string
	Step       *WorkflowStep
	Timestamp  time.Time
}

// WorkflowEvent represents a workflow-level event
type WorkflowEvent struct {
	WorkflowID string
	Workflow   *Workflow
	Timestamp  time.Time
}

// NewWorkflowEngine creates a new workflow engine
func NewWorkflowEngine(jobManager *jobs.JobManager, correlator *correlation.Correlator, registry *metadata.ScriptRegistry) *WorkflowEngine {
	return &WorkflowEngine{
		workflows:         make(map[string]*Workflow),
		jobManager:        jobManager,
		correlator:        correlator,
		registry:          registry,
		stepStartedChan:   make(chan *WorkflowStepEvent, 100),
		stepCompletedChan: make(chan *WorkflowStepEvent, 100),
		workflowDoneChan:  make(chan *WorkflowEvent, 10),
		stopChan:          make(chan struct{}),
	}
}

// CreateWorkflow creates a new workflow
func (we *WorkflowEngine) CreateWorkflow(id, name, description string) *Workflow {
	we.mu.Lock()
	defer we.mu.Unlock()

	workflow := &Workflow{
		ID:             id,
		Name:           name,
		Description:    description,
		Steps:          make(map[string]*WorkflowStep),
		StartSteps:     make([]string, 0),
		Status:         WorkflowStatusPending,
		Variables:      make(map[string]string),
		Results:        make(map[string]*correlation.ScanResult),
		Metadata:       make(map[string]interface{}),
		completedSteps: make(map[string]bool),
		runningSteps:   make(map[string]bool),
	}

	we.workflows[id] = workflow
	return workflow
}

// AddStep adds a step to a workflow
func (w *Workflow) AddStep(step *WorkflowStep) {
	w.mu.Lock()
	defer w.mu.Unlock()

	step.Status = WorkflowStatusPending
	w.Steps[step.ID] = step
}

// AddScriptStep adds a script execution step
func (w *Workflow) AddScriptStep(id, name, scriptPath string, required bool) *WorkflowStep {
	step := &WorkflowStep{
		ID:         id,
		Name:       name,
		Type:       StepTypeScript,
		ScriptPath: scriptPath,
		Required:   required,
		Status:     WorkflowStatusPending,
		Parameters: make(map[string]string),
		Metadata:   make(map[string]interface{}),
	}

	w.AddStep(step)
	return step
}

// AddConditionStep adds a conditional step
func (w *Workflow) AddConditionStep(id, name string, condition *StepCondition) *WorkflowStep {
	step := &WorkflowStep{
		ID:        id,
		Name:      name,
		Type:      StepTypeCondition,
		Condition: condition,
		Status:    WorkflowStatusPending,
		Metadata:  make(map[string]interface{}),
	}

	w.AddStep(step)
	return step
}

// AddDelayStep adds a delay step
func (w *Workflow) AddDelayStep(id, name string, delay time.Duration) *WorkflowStep {
	step := &WorkflowStep{
		ID:       id,
		Name:     name,
		Type:     StepTypeDelay,
		Delay:    delay,
		Status:   WorkflowStatusPending,
		Metadata: make(map[string]interface{}),
	}

	w.AddStep(step)
	return step
}

// AddParallelStep adds a parallel execution step
func (w *Workflow) AddParallelStep(id, name string, parallelSteps []string) *WorkflowStep {
	step := &WorkflowStep{
		ID:       id,
		Name:     name,
		Type:     StepTypeParallel,
		Parallel: parallelSteps,
		Status:   WorkflowStatusPending,
		Metadata: make(map[string]interface{}),
	}

	w.AddStep(step)
	return step
}

// SetStartSteps sets the initial steps to execute
func (w *Workflow) SetStartSteps(stepIDs []string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.StartSteps = stepIDs
}

// ExecuteWorkflow starts workflow execution
func (we *WorkflowEngine) ExecuteWorkflow(workflowID string) error {
	we.mu.RLock()
	workflow, exists := we.workflows[workflowID]
	we.mu.RUnlock()

	if !exists {
		return fmt.Errorf("workflow %s not found", workflowID)
	}

	workflow.mu.Lock()
	if workflow.Status == WorkflowStatusRunning {
		workflow.mu.Unlock()
		return fmt.Errorf("workflow %s is already running", workflowID)
	}

	workflow.Status = WorkflowStatusRunning
	workflow.StartTime = time.Now()
	workflow.Progress = 0.0
	workflow.mu.Unlock()

	// Start execution in goroutine
	go we.executeWorkflowSteps(workflow)

	return nil
}

// executeWorkflowSteps executes workflow steps
func (we *WorkflowEngine) executeWorkflowSteps(workflow *Workflow) {
	defer func() {
		workflow.mu.Lock()
		workflow.EndTime = time.Now()
		workflow.Duration = workflow.EndTime.Sub(workflow.StartTime)

		// Determine final status
		if workflow.Status == WorkflowStatusRunning {
			allCompleted := true
			anyFailed := false

			for _, step := range workflow.Steps {
				if step.Required && step.Status == WorkflowStatusFailed {
					anyFailed = true
					break
				}
				if step.Status != WorkflowStatusCompleted && step.Status != WorkflowStatusFailed {
					allCompleted = false
				}
			}

			if anyFailed {
				workflow.Status = WorkflowStatusFailed
			} else if allCompleted {
				workflow.Status = WorkflowStatusCompleted
				workflow.Progress = 1.0
			}
		}
		workflow.mu.Unlock()

		// Send completion event
		select {
		case we.workflowDoneChan <- &WorkflowEvent{
			WorkflowID: workflow.ID,
			Workflow:   workflow,
			Timestamp:  time.Now(),
		}:
		default:
		}
	}()

	// Execute start steps
	for _, stepID := range workflow.StartSteps {
		if step, exists := workflow.Steps[stepID]; exists {
			go we.executeStep(workflow, step)
		}
	}
}

// executeStep executes a single workflow step
func (we *WorkflowEngine) executeStep(workflow *Workflow, step *WorkflowStep) {
	// Check if already running or completed
	workflow.mu.Lock()
	if workflow.runningSteps[step.ID] || workflow.completedSteps[step.ID] {
		workflow.mu.Unlock()
		return
	}
	workflow.runningSteps[step.ID] = true
	workflow.mu.Unlock()

	defer func() {
		workflow.mu.Lock()
		delete(workflow.runningSteps, step.ID)
		workflow.completedSteps[step.ID] = true
		workflow.mu.Unlock()

		// Update progress
		we.updateWorkflowProgress(workflow)

		// Send step completion event
		select {
		case we.stepCompletedChan <- &WorkflowStepEvent{
			WorkflowID: workflow.ID,
			StepID:     step.ID,
			Step:       step,
			Timestamp:  time.Now(),
		}:
		default:
		}

		// Execute next steps based on result
		we.executeNextSteps(workflow, step)
	}()

	step.Status = WorkflowStatusRunning
	step.StartTime = time.Now()

	// Send step start event
	select {
	case we.stepStartedChan <- &WorkflowStepEvent{
		WorkflowID: workflow.ID,
		StepID:     step.ID,
		Step:       step,
		Timestamp:  time.Now(),
	}:
	default:
	}

	// Execute step based on type
	var success bool
	var err error

	switch step.Type {
	case StepTypeScript:
		success, err = we.executeScriptStep(workflow, step)
	case StepTypeCondition:
		success, err = we.executeConditionStep(workflow, step)
	case StepTypeDelay:
		success, err = we.executeDelayStep(workflow, step)
	case StepTypeParallel:
		success, err = we.executeParallelStep(workflow, step)
	case StepTypeCorrelation:
		success, err = we.executeCorrelationStep(workflow, step)
	default:
		success = false
		err = fmt.Errorf("unknown step type: %s", step.Type)
	}

	step.EndTime = time.Now()
	step.Duration = step.EndTime.Sub(step.StartTime)
	step.Error = err

	if success {
		step.Status = WorkflowStatusCompleted
	} else {
		step.Status = WorkflowStatusFailed

		// Check if this is a required step failure
		if step.Required {
			workflow.mu.Lock()
			workflow.Status = WorkflowStatusFailed
			workflow.mu.Unlock()
		}
	}
}

// executeScriptStep executes a script step
func (we *WorkflowEngine) executeScriptStep(workflow *Workflow, step *WorkflowStep) (bool, error) {
	// Create a job for the script
	jobID := fmt.Sprintf("workflow_%s_step_%s", workflow.ID, step.ID)
	job := we.jobManager.CreateJob(jobID, step.Name, step.ScriptPath)

	// Start the job
	if err := we.jobManager.StartJob(job.ID); err != nil {
		return false, fmt.Errorf("failed to start job: %w", err)
	}

	// Wait for job completion with timeout
	timeout := step.Timeout
	if timeout == 0 {
		timeout = 30 * time.Minute // Default timeout
	}

	done := make(chan bool, 1)
	go func() {
		for {
			if job.IsCompleted() {
				done <- job.GetStatus() == jobs.JobStatusCompleted
				return
			}
			time.Sleep(1 * time.Second)
		}
	}()

	select {
	case success := <-done:
		step.Result = job.Result
		return success, job.GetError()
	case <-time.After(timeout):
		we.jobManager.CancelJob(job.ID)
		return false, fmt.Errorf("step timed out after %v", timeout)
	}
}

// executeConditionStep executes a condition step
func (we *WorkflowEngine) executeConditionStep(workflow *Workflow, step *WorkflowStep) (bool, error) {
	if step.Condition == nil {
		return false, fmt.Errorf("condition step has no condition defined")
	}

	return we.evaluateCondition(workflow, step.Condition)
}

// executeDelayStep executes a delay step
func (we *WorkflowEngine) executeDelayStep(workflow *Workflow, step *WorkflowStep) (bool, error) {
	time.Sleep(step.Delay)
	return true, nil
}

// executeParallelStep executes parallel steps
func (we *WorkflowEngine) executeParallelStep(workflow *Workflow, step *WorkflowStep) (bool, error) {
	var wg sync.WaitGroup
	successCount := 0
	mu := sync.Mutex{}

	for _, stepID := range step.Parallel {
		if parallelStep, exists := workflow.Steps[stepID]; exists {
			wg.Add(1)
			go func(s *WorkflowStep) {
				defer wg.Done()
				we.executeStep(workflow, s)
				// Check step status after execution
				if s.Status == WorkflowStatusCompleted {
					mu.Lock()
					successCount++
					mu.Unlock()
				}
			}(parallelStep)
		}
	}

	wg.Wait()
	return successCount > 0, nil
}

// executeCorrelationStep executes correlation analysis
func (we *WorkflowEngine) executeCorrelationStep(workflow *Workflow, step *WorkflowStep) (bool, error) {
	// Trigger correlation analysis for all workflow results
	for _, result := range workflow.Results {
		if err := we.correlator.AddScanResult(result); err != nil {
			return false, fmt.Errorf("correlation failed: %w", err)
		}
	}
	return true, nil
}

// evaluateCondition evaluates a step condition
func (we *WorkflowEngine) evaluateCondition(workflow *Workflow, condition *StepCondition) (bool, error) {
	switch condition.Type {
	case ConditionTypeHostsFound:
		count := len(we.getDiscoveredHosts(workflow))
		return we.compareValues(count, condition.Operator, condition.Value)

	case ConditionTypeServicesFound:
		count := len(we.getDiscoveredServices(workflow))
		return we.compareValues(count, condition.Operator, condition.Value)

	case ConditionTypeVulnsFound:
		count := len(we.getDiscoveredVulnerabilities(workflow))
		return we.compareValues(count, condition.Operator, condition.Value)

	case ConditionTypePortOpen:
		port, ok := condition.Value.(int)
		if !ok {
			return false, fmt.Errorf("invalid port value for condition")
		}
		return we.isPortOpen(workflow, condition.Target, port), nil

	case ConditionTypeScriptSuccess:
		if condition.StepID != "" {
			if step, exists := workflow.Steps[condition.StepID]; exists {
				return step.Status == WorkflowStatusCompleted, nil
			}
		}
		return false, fmt.Errorf("step not found: %s", condition.StepID)

	case ConditionTypeRiskScore:
		if condition.Target != "" {
			score := we.getHostRiskScore(workflow, condition.Target)
			return we.compareValues(score, condition.Operator, condition.Value)
		}
		return false, fmt.Errorf("no target host specified for risk score condition")

	default:
		return false, fmt.Errorf("unknown condition type: %s", condition.Type)
	}
}

// Helper methods for condition evaluation
func (we *WorkflowEngine) getDiscoveredHosts(workflow *Workflow) []string {
	hostSet := make(map[string]bool)
	for _, result := range workflow.Results {
		for _, host := range result.Hosts {
			hostSet[host.IP] = true
		}
	}

	hosts := make([]string, 0, len(hostSet))
	for host := range hostSet {
		hosts = append(hosts, host)
	}
	return hosts
}

func (we *WorkflowEngine) getDiscoveredServices(workflow *Workflow) []correlation.Service {
	var services []correlation.Service
	for _, result := range workflow.Results {
		services = append(services, result.Services...)
	}
	return services
}

func (we *WorkflowEngine) getDiscoveredVulnerabilities(workflow *Workflow) []correlation.Vulnerability {
	var vulns []correlation.Vulnerability
	for _, result := range workflow.Results {
		vulns = append(vulns, result.Vulnerabilities...)
	}
	return vulns
}

func (we *WorkflowEngine) isPortOpen(workflow *Workflow, host string, port int) bool {
	for _, result := range workflow.Results {
		for _, h := range result.Hosts {
			if h.IP == host {
				for _, p := range h.Ports {
					if p.Number == port && p.State == "open" {
						return true
					}
				}
			}
		}
	}
	return false
}

func (we *WorkflowEngine) getHostRiskScore(workflow *Workflow, host string) int {
	if correlation, exists := we.correlator.GetCorrelationForHost(host); exists {
		return correlation.RiskScore
	}
	return 0
}

func (we *WorkflowEngine) compareValues(actual interface{}, operator string, expected interface{}) (bool, error) {
	switch operator {
	case ">":
		if a, ok := actual.(int); ok {
			if e, ok := expected.(int); ok {
				return a > e, nil
			}
		}
	case "<":
		if a, ok := actual.(int); ok {
			if e, ok := expected.(int); ok {
				return a < e, nil
			}
		}
	case "==":
		return actual == expected, nil
	case "!=":
		return actual != expected, nil
	case ">=":
		if a, ok := actual.(int); ok {
			if e, ok := expected.(int); ok {
				return a >= e, nil
			}
		}
	case "<=":
		if a, ok := actual.(int); ok {
			if e, ok := expected.(int); ok {
				return a <= e, nil
			}
		}
	}
	return false, fmt.Errorf("unsupported comparison: %v %s %v", actual, operator, expected)
}

// executeNextSteps executes the next steps based on current step result
func (we *WorkflowEngine) executeNextSteps(workflow *Workflow, completedStep *WorkflowStep) {
	var nextSteps []string

	if completedStep.Status == WorkflowStatusCompleted {
		nextSteps = completedStep.OnSuccess
	} else {
		nextSteps = completedStep.OnFailure
	}

	for _, stepID := range nextSteps {
		if step, exists := workflow.Steps[stepID]; exists {
			go we.executeStep(workflow, step)
		}
	}
}

// updateWorkflowProgress updates the workflow progress
func (we *WorkflowEngine) updateWorkflowProgress(workflow *Workflow) {
	workflow.mu.Lock()
	defer workflow.mu.Unlock()

	total := len(workflow.Steps)
	if total == 0 {
		workflow.Progress = 0.0
		return
	}

	completed := len(workflow.completedSteps)
	workflow.Progress = float64(completed) / float64(total)
}

// GetWorkflow returns a workflow by ID
func (we *WorkflowEngine) GetWorkflow(id string) (*Workflow, bool) {
	we.mu.RLock()
	defer we.mu.RUnlock()

	workflow, exists := we.workflows[id]
	return workflow, exists
}

// GetAllWorkflows returns all workflows
func (we *WorkflowEngine) GetAllWorkflows() map[string]*Workflow {
	we.mu.RLock()
	defer we.mu.RUnlock()

	workflows := make(map[string]*Workflow)
	for k, v := range we.workflows {
		workflows[k] = v
	}
	return workflows
}

// CancelWorkflow cancels a running workflow
func (we *WorkflowEngine) CancelWorkflow(id string) error {
	we.mu.RLock()
	workflow, exists := we.workflows[id]
	we.mu.RUnlock()

	if !exists {
		return fmt.Errorf("workflow %s not found", id)
	}

	workflow.mu.Lock()
	defer workflow.mu.Unlock()

	if workflow.Status != WorkflowStatusRunning {
		return fmt.Errorf("workflow %s is not running", id)
	}

	workflow.Status = WorkflowStatusCancelled
	workflow.EndTime = time.Now()
	workflow.Duration = workflow.EndTime.Sub(workflow.StartTime)

	return nil
}

// GetEventChannels returns channels for workflow events
func (we *WorkflowEngine) GetEventChannels() (<-chan *WorkflowStepEvent, <-chan *WorkflowStepEvent, <-chan *WorkflowEvent) {
	return we.stepStartedChan, we.stepCompletedChan, we.workflowDoneChan
}

// Stop stops the workflow engine
func (we *WorkflowEngine) Stop() {
	close(we.stopChan)
}
