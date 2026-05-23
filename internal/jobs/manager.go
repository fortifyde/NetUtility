package jobs

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"netutil/internal/executor"
)

// JobStatus represents the current state of a job
type JobStatus string

const (
	JobStatusPending   JobStatus = "pending"
	JobStatusRunning   JobStatus = "running"
	JobStatusCompleted JobStatus = "completed"
	JobStatusFailed    JobStatus = "failed"
	JobStatusCancelled JobStatus = "cancelled"
)

// Job represents a single script execution job
type Job struct {
	ID         string
	Name       string
	ScriptPath string
	Status     JobStatus
	StartTime  time.Time
	EndTime    time.Time
	Duration   time.Duration
	Result     *executor.StreamingResult
	Executor   *executor.StreamingExecutor
	OutputChan <-chan executor.OutputLine
	ErrorChan  <-chan error
	Error      error

	// Phase progress, updated by the progress scanner goroutine in monitorJob.
	PhaseCurrent int
	PhaseTotal   int
	PhaseDesc    string
	PhaseUnit    string // e.g. "s" for seconds, "" for counts

	// cancelled is set atomically by CancelJob before Stop() is called,
	// so monitorJob sees it after job.Executor.Wait() returns.
	cancelled atomic.Bool

	// needsInput is set atomically when the output scanner detects
	// a prompt indicating the script is waiting for user input.
	needsInput atomic.Bool

	mu sync.RWMutex
}

// JobManager manages concurrent script execution
type JobManager struct {
	jobs          map[string]*Job
	maxConcurrent int
	runningCount  int
	mu            sync.RWMutex

	// Channels for job events
	jobStartedChan   chan *Job
	jobCompletedChan chan *Job
	jobFailedChan    chan *Job

	stopOnce sync.Once

	// onJobDone is called after each job completes (success or failure).
	onJobDone func()
}

// NewJobManager creates a new job manager
func NewJobManager(maxConcurrent int) *JobManager {
	if maxConcurrent <= 0 {
		maxConcurrent = 3 // Default to 3 concurrent jobs
	}

	return &JobManager{
		jobs:             make(map[string]*Job),
		maxConcurrent:    maxConcurrent,
		jobStartedChan:   make(chan *Job, 10),
		jobCompletedChan: make(chan *Job, 10),
		jobFailedChan:    make(chan *Job, 10),
		// stopChan removed — was never read; stopOnce handles idempotent Stop
	}
}

// SetOnJobDone registers a callback invoked after each job completes.
// The callback must not block for long.
func (jm *JobManager) SetOnJobDone(fn func()) {
	jm.mu.Lock()
	defer jm.mu.Unlock()
	jm.onJobDone = fn
}

// CreateJob creates a new job but doesn't start it
func (jm *JobManager) CreateJob(id, name, scriptPath string) *Job {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	job := &Job{
		ID:         id,
		Name:       name,
		ScriptPath: scriptPath,
		Status:     JobStatusPending,
	}

	jm.jobs[id] = job
	return job
}

// StartJob starts a job if there's capacity
func (jm *JobManager) StartJob(jobID string) error {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	job, exists := jm.jobs[jobID]
	if !exists {
		return fmt.Errorf("job %s not found", jobID)
	}

	if job.Status != JobStatusPending {
		return fmt.Errorf("job %s is not in pending state", jobID)
	}

	// Check if we can start more jobs
	if jm.runningCount >= jm.maxConcurrent {
		return fmt.Errorf("maximum concurrent jobs (%d) reached", jm.maxConcurrent)
	}

	// Create executor and start job
	job.Executor = executor.NewStreamingExecutor()
	job.StartTime = time.Now()
	job.Status = JobStatusRunning
	jm.runningCount++

	// Start execution
	result, outputChan, errorChan := job.Executor.ExecuteScriptStreaming(job.ScriptPath)
	job.Result = result
	job.OutputChan = outputChan
	job.ErrorChan = errorChan

	// Monitor job completion
	go jm.monitorJob(job)

	// Notify job started
	select {
	case jm.jobStartedChan <- job:
	default:
	}

	return nil
}

// monitorJob monitors a job's execution and updates its status
func (jm *JobManager) monitorJob(job *Job) {
	// Progress scanner: polls output lines for ##NETUTIL:PROGRESS## markers.
	progressStop := make(chan struct{})
	var progressWg sync.WaitGroup
	progressWg.Add(1)
	go func() {
		defer progressWg.Done()
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		lastIdx := 0
		for {
			select {
			case <-ticker.C:
				lines := job.GetOutputLines()
				for i := lastIdx; i < len(lines); i++ {
					text := lines[i].Content
					const pfx = "##NETUTIL:PROGRESS## "
					if strings.HasPrefix(text, pfx) {
						if c, t, d, u, ok := parsePhaseProgress(text[len(pfx):]); ok {
							job.SetPhaseProgress(c, t, d, u)
						}
						continue
					}
					// Check for interactive prompts (only on stderr;
					// tool output arrives on stdout and would false-positive).
					if !job.NeedsInput() && lines[i].Source == "stderr" {
						stripped := StripANSI(text)
						if DetectScriptPrompt(stripped) || DetectPasswordPrompt(stripped) {
							job.SetNeedsInput(true)
						}
					}
				}
				lastIdx = len(lines)
			case <-progressStop:
				return
			}
		}
	}()

	job.Executor.Wait()

	// Stop and join the progress goroutine before touching any shared state.
	close(progressStop)
	progressWg.Wait()

	// Clear input-waiting state now that the job has finished.
	job.SetNeedsInput(false)

	// Use the atomic cancelled flag (set by CancelJob before Stop()) to
	// determine whether CancelJob already handled status and runningCount.
	wasCancelled := job.cancelled.Load()

	if !wasCancelled {
		job.mu.Lock()
		job.EndTime = time.Now()
		job.Duration = job.EndTime.Sub(job.StartTime)

		if job.Result != nil {
			success, _, _, _, jobErr := job.Result.GetFinal()
			if success {
				job.Status = JobStatusCompleted
			} else {
				job.Status = JobStatusFailed
				job.Error = jobErr
			}
		} else {
			job.Status = JobStatusFailed
			job.Error = fmt.Errorf("job execution failed - no result")
		}
		job.mu.Unlock()

		jm.mu.Lock()
		jm.runningCount--
		jm.mu.Unlock()

		if job.Status == JobStatusCompleted {
			select {
			case jm.jobCompletedChan <- job:
			default:
			}
		} else {
			select {
			case jm.jobFailedChan <- job:
			default:
			}
		}
	}

	jm.mu.RLock()
	onJobDone := jm.onJobDone
	jm.mu.RUnlock()
	if onJobDone != nil {
		onJobDone()
	}

	// Start any pending jobs that were waiting for this slot.
	jm.AutoStartJobs()
}

// CancelJob cancels a running job
func (jm *JobManager) CancelJob(jobID string) error {
	// First, get the job reference without holding the manager lock
	jm.mu.RLock()
	job, exists := jm.jobs[jobID]
	if !exists {
		jm.mu.RUnlock()
		return fmt.Errorf("job %s not found", jobID)
	}

	// Check job status without holding manager lock
	job.mu.RLock()
	isRunning := job.Status == JobStatusRunning
	executor := job.Executor
	job.mu.RUnlock()
	jm.mu.RUnlock()

	if !isRunning {
		return fmt.Errorf("job %s is not running", jobID)
	}

	// Mark cancelled atomically BEFORE stopping the executor so monitorJob
	// sees it after job.Executor.Wait() returns.
	job.cancelled.Store(true)

	// Stop the executor
	if executor != nil {
		if err := executor.Stop(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to stop executor: %v\n", err)
		}
	}

	// Update job status fields under the job lock
	job.mu.Lock()
	job.Status = JobStatusCancelled
	job.EndTime = time.Now()
	job.Duration = job.EndTime.Sub(job.StartTime)
	job.mu.Unlock()

	// Update manager running count
	jm.mu.Lock()
	jm.runningCount--
	jm.mu.Unlock()

	jm.AutoStartJobs()
	return nil
}

// GetJob retrieves a job by ID
func (jm *JobManager) GetJob(jobID string) (*Job, bool) {
	jm.mu.RLock()
	defer jm.mu.RUnlock()

	job, exists := jm.jobs[jobID]
	return job, exists
}

// jobStatusPriority returns the sort priority for a job status
// Lower numbers appear first in the job list
func jobStatusPriority(status JobStatus) int {
	switch status {
	case JobStatusRunning:
		return 0
	case JobStatusPending:
		return 1
	case JobStatusCompleted:
		return 2
	case JobStatusFailed:
		return 3
	case JobStatusCancelled:
		return 4
	default:
		return 5
	}
}

// GetAllJobs returns all jobs sorted by status priority and timestamp.
// Jobs are grouped: Running -> Pending -> Completed -> Failed -> Cancelled.
// Within each group, jobs are sorted by start time (oldest first).
func (jm *JobManager) GetAllJobs() []*Job {
	jm.mu.RLock()
	type jobSnapshot struct {
		job       *Job
		priority  int
		startTime time.Time
	}
	snapshots := make([]jobSnapshot, 0, len(jm.jobs))
	for _, job := range jm.jobs {
		job.mu.RLock()
		snapshots = append(snapshots, jobSnapshot{
			job:       job,
			priority:  jobStatusPriority(job.Status),
			startTime: job.StartTime,
		})
		job.mu.RUnlock()
	}
	jm.mu.RUnlock()

	sort.Slice(snapshots, func(i, j int) bool {
		if snapshots[i].priority != snapshots[j].priority {
			return snapshots[i].priority < snapshots[j].priority
		}
		return snapshots[i].startTime.Before(snapshots[j].startTime)
	})

	jobs := make([]*Job, len(snapshots))
	for i, s := range snapshots {
		jobs[i] = s.job
	}
	return jobs
}

// GetJobsByStatus returns jobs with a specific status
func (jm *JobManager) GetJobsByStatus(status JobStatus) []*Job {
	jm.mu.RLock()
	defer jm.mu.RUnlock()

	var jobs []*Job
	for _, job := range jm.jobs {
		job.mu.RLock()
		if job.Status == status {
			jobs = append(jobs, job)
		}
		job.mu.RUnlock()
	}
	return jobs
}

// GetRunningJobs returns all currently running jobs
func (jm *JobManager) GetRunningJobs() []*Job {
	return jm.GetJobsByStatus(JobStatusRunning)
}

// GetCompletedJobs returns all completed jobs
func (jm *JobManager) GetCompletedJobs() []*Job {
	return jm.GetJobsByStatus(JobStatusCompleted)
}

// GetFailedJobs returns all failed jobs
func (jm *JobManager) GetFailedJobs() []*Job {
	return jm.GetJobsByStatus(JobStatusFailed)
}

// GetQueuedJobs returns all pending jobs
func (jm *JobManager) GetQueuedJobs() []*Job {
	return jm.GetJobsByStatus(JobStatusPending)
}

// GetStats returns job manager statistics
func (jm *JobManager) GetStats() JobManagerStats {
	jm.mu.RLock()
	defer jm.mu.RUnlock()

	stats := JobManagerStats{
		TotalJobs:     len(jm.jobs),
		RunningJobs:   jm.runningCount,
		MaxConcurrent: jm.maxConcurrent,
	}

	for _, job := range jm.jobs {
		job.mu.RLock()
		switch job.Status {
		case JobStatusPending:
			stats.PendingJobs++
		case JobStatusCompleted:
			stats.CompletedJobs++
		case JobStatusFailed:
			stats.FailedJobs++
		case JobStatusCancelled:
			stats.CancelledJobs++
		}
		job.mu.RUnlock()
	}

	return stats
}

// JobManagerStats contains statistics about the job manager
type JobManagerStats struct {
	TotalJobs     int
	RunningJobs   int
	PendingJobs   int
	CompletedJobs int
	FailedJobs    int
	CancelledJobs int
	MaxConcurrent int
}

// CanStartNewJob returns whether a new job can be started
func (jm *JobManager) CanStartNewJob() bool {
	jm.mu.RLock()
	defer jm.mu.RUnlock()
	return jm.runningCount < jm.maxConcurrent
}

// SetMaxConcurrent updates the maximum number of concurrent jobs.
func (jm *JobManager) SetMaxConcurrent(n int) {
	if n <= 0 {
		return
	}
	jm.mu.Lock()
	jm.maxConcurrent = n
	jm.mu.Unlock()
	// Fill any newly available slots
	jm.AutoStartJobs()
}

// GetNextPendingJob returns the next pending job that can be started
func (jm *JobManager) GetNextPendingJob() *Job {
	jm.mu.RLock()
	defer jm.mu.RUnlock()

	for _, job := range jm.jobs {
		job.mu.RLock()
		if job.Status == JobStatusPending {
			job.mu.RUnlock()
			return job
		}
		job.mu.RUnlock()
	}
	return nil
}

// AutoStartJobs automatically starts pending jobs if capacity allows
func (jm *JobManager) AutoStartJobs() int {
	started := 0

	for jm.CanStartNewJob() {
		job := jm.GetNextPendingJob()
		if job == nil {
			break
		}

		if err := jm.StartJob(job.ID); err != nil {
			break
		}
		started++
	}

	return started
}

// RemoveJob removes a completed or failed job from the manager
func (jm *JobManager) RemoveJob(jobID string) error {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	job, exists := jm.jobs[jobID]
	if !exists {
		return fmt.Errorf("job %s not found", jobID)
	}

	job.mu.RLock()
	status := job.Status
	job.mu.RUnlock()

	if status == JobStatusRunning {
		return fmt.Errorf("cannot remove running job %s", jobID)
	}

	delete(jm.jobs, jobID)
	return nil
}

// ClearCompletedJobs removes all completed and failed jobs
func (jm *JobManager) ClearCompletedJobs() int {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	removed := 0
	for id, job := range jm.jobs {
		job.mu.RLock()
		status := job.Status
		job.mu.RUnlock()

		if status == JobStatusCompleted || status == JobStatusFailed || status == JobStatusCancelled {
			delete(jm.jobs, id)
			removed++
		}
	}

	return removed
}

// GetJobEventChannels returns channels for job events
func (jm *JobManager) GetJobEventChannels() (<-chan *Job, <-chan *Job, <-chan *Job) {
	return jm.jobStartedChan, jm.jobCompletedChan, jm.jobFailedChan
}

// Stop stops the job manager and cancels all running jobs
func (jm *JobManager) Stop() {
	jm.stopOnce.Do(func() {
		jm.mu.Lock()
		defer jm.mu.Unlock()

		// Cancel all running jobs
		for _, job := range jm.jobs {
			job.mu.RLock()
			if job.Status == JobStatusRunning && job.Executor != nil {
			_ = job.Executor.Stop()
			}
			job.mu.RUnlock()
		}
	})
}

// Helper methods for Job

// GetStatus returns the job status thread-safely
func (j *Job) GetStatus() JobStatus {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.Status
}

// GetDuration returns the job duration thread-safely
func (j *Job) GetDuration() time.Duration {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.Duration
}

// GetError returns the job error thread-safely
func (j *Job) GetError() error {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.Error
}

// IsRunning returns whether the job is currently running
func (j *Job) IsRunning() bool {
	return j.GetStatus() == JobStatusRunning
}

// IsCompleted returns whether the job has completed (successfully or failed)
func (j *Job) IsCompleted() bool {
	status := j.GetStatus()
	return status == JobStatusCompleted || status == JobStatusFailed || status == JobStatusCancelled
}

// SetNeedsInput marks the job as waiting for user input.
func (j *Job) SetNeedsInput(needs bool) {
	j.needsInput.Store(needs)
}

// NeedsInput returns whether the job is waiting for user input.
func (j *Job) NeedsInput() bool {
	return j.needsInput.Load()
}

// SetPhaseProgress stores phase progress thread-safely.
func (j *Job) SetPhaseProgress(current, total int, desc, unit string) {
	j.mu.Lock()
	j.PhaseCurrent = current
	j.PhaseTotal = total
	j.PhaseDesc = desc
	j.PhaseUnit = unit
	j.mu.Unlock()
}

// GetPhaseProgress returns the last-seen phase progress.
func (j *Job) GetPhaseProgress() (int, int, string, string) {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.PhaseCurrent, j.PhaseTotal, j.PhaseDesc, j.PhaseUnit
}

// GetOutputLines safely returns a copy of the output lines.
func (j *Job) GetOutputLines() []executor.OutputLine {
	j.mu.RLock()
	result := j.Result
	j.mu.RUnlock()

	if result == nil {
		return nil
	}
	return result.GetOutputLines()
}

// parsePhaseProgress parses a ##NETUTIL:PROGRESS## payload (the part after the prefix).
// Handles two forms:
//
//	"[3/8] Phase 3: DNS Reverse Lookup"        → current=3, total=8
//	"[2/3 VLANs] V100:3/8 V200:done V300:1/8" → current=2, total=3
//	"[300s/600s] Capturing on eth0"            → current=300, total=600, unit="s"
//
// Returns ok=false when the format is not recognised.
func parsePhaseProgress(text string) (current, total int, desc, unit string, ok bool) {
	if len(text) == 0 || text[0] != '[' {
		return
	}
	closeIdx := strings.IndexByte(text, ']')
	if closeIdx < 0 {
		return
	}
	bracket := text[1:closeIdx]
	rest := strings.TrimSpace(text[closeIdx+1:])
	slashIdx := strings.IndexByte(bracket, '/')
	if slashIdx < 0 {
		return
	}
	totalField := bracket[slashIdx+1:]
	if sp := strings.IndexByte(totalField, ' '); sp >= 0 {
		totalField = totalField[:sp]
	}
	curStr := strings.TrimSpace(bracket[:slashIdx])
	totStr := strings.TrimSpace(totalField)
	// Detect unit suffix (e.g. "300s" → unit "s").
	if strings.HasSuffix(curStr, "s") && strings.HasSuffix(totStr, "s") {
		unit = "s"
		curStr = strings.TrimSuffix(curStr, "s")
		totStr = strings.TrimSuffix(totStr, "s")
	}
	cur, err1 := strconv.Atoi(curStr)
	tot, err2 := strconv.Atoi(totStr)
	if err1 != nil || err2 != nil || tot <= 0 {
		return
	}
	return cur, tot, rest, unit, true
}
// VLANStatus represents the progress of a single VLAN scan.
type VLANStatus struct {
	ID      string
	Current int
	Total   int
	Done    bool
}

// ParseVLANBreakdown extracts per-VLAN progress from a progress description
// like "V100:3/8 V200:done V300:1/8". Returns nil if no VLAN entries found.
func ParseVLANBreakdown(desc string) []VLANStatus {
	if desc == "" {
		return nil
	}
	fields := strings.Fields(desc)
	var result []VLANStatus
	for _, f := range fields {
		// Form: "V100:3/8" or "V100:done"
		colonIdx := strings.IndexByte(f, ':')
		if colonIdx < 0 {
			continue
		}
		id := f[:colonIdx]
		// Skip fields that don't look like VLAN identifiers.
		// Accept: letter-prefixed IDs (V10, vlan10), or numeric IDs ≥2 chars (10, 100).
		// Reject: single-char or non-alnum-start tokens (phase numbers, punctuation).
		if colonIdx == 0 {
			continue
		}
		first := rune(id[0])
		if !unicode.IsLetter(first) && !unicode.IsDigit(first) {
			continue
		}
		// Numeric IDs must be at least 2 chars to avoid phase numbers like "3:".
		if unicode.IsDigit(first) && colonIdx < 2 {
			continue
		}
		val := f[colonIdx+1:]
		if val == "done" || val == "✓" {
			result = append(result, VLANStatus{ID: id, Done: true})
			continue
		}
		slashIdx := strings.IndexByte(val, '/')
		if slashIdx < 0 {
			result = append(result, VLANStatus{ID: id})
			continue
		}
		cur, err1 := strconv.Atoi(val[:slashIdx])
		tot, err2 := strconv.Atoi(val[slashIdx+1:])
		if err1 != nil || err2 != nil || tot <= 0 {
			result = append(result, VLANStatus{ID: id})
			continue
		}
		done := cur >= tot
		result = append(result, VLANStatus{ID: id, Current: cur, Total: tot, Done: done})
	}
	return result
}
