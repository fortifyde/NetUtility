package jobs

import (
	"fmt"
	"sync"
	"time"

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
	mu         sync.RWMutex
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
	stopChan         chan struct{}
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
		stopChan:         make(chan struct{}),
	}
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
	job.Executor.Wait()

	job.mu.Lock()
	job.EndTime = time.Now()
	job.Duration = job.EndTime.Sub(job.StartTime)

	// Update status based on result
	if job.Result != nil {
		if job.Result.Success {
			job.Status = JobStatusCompleted
		} else {
			job.Status = JobStatusFailed
			job.Error = job.Result.Error
		}
	} else {
		job.Status = JobStatusFailed
		job.Error = fmt.Errorf("job execution failed - no result")
	}
	job.mu.Unlock()

	// Update manager state
	jm.mu.Lock()
	jm.runningCount--
	jm.mu.Unlock()

	// Notify completion
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

	// Stop the executor (this should interrupt any waiting operations)
	if executor != nil {
		executor.Stop()
	}

	// Update job status
	job.mu.Lock()
	job.Status = JobStatusCancelled
	job.EndTime = time.Now()
	job.Duration = job.EndTime.Sub(job.StartTime)
	job.mu.Unlock()

	// Update manager running count
	jm.mu.Lock()
	jm.runningCount--
	jm.mu.Unlock()

	return nil
}

// GetJob retrieves a job by ID
func (jm *JobManager) GetJob(jobID string) (*Job, bool) {
	jm.mu.RLock()
	defer jm.mu.RUnlock()

	job, exists := jm.jobs[jobID]
	return job, exists
}

// GetAllJobs returns all jobs
func (jm *JobManager) GetAllJobs() []*Job {
	jm.mu.RLock()
	defer jm.mu.RUnlock()

	jobs := make([]*Job, 0, len(jm.jobs))
	for _, job := range jm.jobs {
		jobs = append(jobs, job)
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
	jm.mu.Lock()
	defer jm.mu.Unlock()

	// Cancel all running jobs
	for _, job := range jm.jobs {
		job.mu.RLock()
		if job.Status == JobStatusRunning && job.Executor != nil {
			job.Executor.Stop()
		}
		job.mu.RUnlock()
	}

	// Signal stop
	close(jm.stopChan)
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
