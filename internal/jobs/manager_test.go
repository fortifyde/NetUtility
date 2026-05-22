package jobs

import (
	"testing"
	"time"
)

func TestParsePhaseProgress_StandardForm(t *testing.T) {
	tests := []struct {
		input  string
		wantC  int
		wantT  int
		wantD  string
		wantOK bool
	}{
		{"[3/8] Phase 3: DNS Reverse Lookup", 3, 8, "Phase 3: DNS Reverse Lookup", true},
		{"[1/1] Done", 1, 1, "Done", true},
		{"[2/3 VLANs] V100:3/8 V200:done", 2, 3, "V100:3/8 V200:done", true},
		{"", 0, 0, "", false},
		{"no brackets", 0, 0, "", false},
		{"[invalid] text", 0, 0, "", false},
		{"[0/0]", 0, 0, "", false},
	}
	for _, tt := range tests {
		c, tot, d, ok := parsePhaseProgress(tt.input)
		if ok != tt.wantOK {
			t.Errorf("parsePhaseProgress(%q) ok=%v, want %v", tt.input, ok, tt.wantOK)
			continue
		}
		if !ok {
			continue
		}
		if c != tt.wantC || tot != tt.wantT || d != tt.wantD {
			t.Errorf("parsePhaseProgress(%q) = (%d, %d, %q), want (%d, %d, %q)",
				tt.input, c, tot, d, tt.wantC, tt.wantT, tt.wantD)
		}
	}
}

func TestJobManager_CreateAndGetJob(t *testing.T) {
	jm := NewJobManager(2)
	job := jm.CreateJob("j1", "Test Job", "/tmp/test.sh")
	if job == nil {
		t.Fatal("CreateJob returned nil")
	}
	got, ok := jm.GetJob("j1")
	if !ok || got != job {
		t.Error("GetJob did not return the created job")
	}
	_, ok = jm.GetJob("nonexistent")
	if ok {
		t.Error("GetJob should return false for nonexistent job")
	}
}

func TestJobManager_GetStats(t *testing.T) {
	jm := NewJobManager(2)
	jm.CreateJob("j1", "A", "/tmp/a.sh")
	jm.CreateJob("j2", "B", "/tmp/b.sh")
	stats := jm.GetStats()
	if stats.TotalJobs != 2 {
		t.Errorf("TotalJobs = %d, want 2", stats.TotalJobs)
	}
	if stats.PendingJobs != 2 {
		t.Errorf("PendingJobs = %d, want 2", stats.PendingJobs)
	}
	if stats.MaxConcurrent != 2 {
		t.Errorf("MaxConcurrent = %d, want 2", stats.MaxConcurrent)
	}
}

func TestJobManager_CanStartNewJob(t *testing.T) {
	jm := NewJobManager(1)
	if !jm.CanStartNewJob() {
		t.Error("should be able to start when runningCount=0, max=1")
	}
	jm.mu.Lock()
	jm.runningCount = 1
	jm.mu.Unlock()
	if jm.CanStartNewJob() {
		t.Error("should not be able to start when runningCount=max")
	}
}

func TestJobManager_RemoveJob_RunningBlocked(t *testing.T) {
	jm := NewJobManager(2)
	job := jm.CreateJob("j1", "Test", "/tmp/test.sh")
	job.mu.Lock()
	job.Status = JobStatusRunning
	job.mu.Unlock()
	if err := jm.RemoveJob("j1"); err == nil {
		t.Error("RemoveJob should fail for running job")
	}
}

func TestJobManager_ClearCompletedJobs(t *testing.T) {
	jm := NewJobManager(2)
	j1 := jm.CreateJob("j1", "A", "/tmp/a.sh")
	j2 := jm.CreateJob("j2", "B", "/tmp/b.sh")
	j3 := jm.CreateJob("j3", "C", "/tmp/c.sh")
	j1.mu.Lock()
	j1.Status = JobStatusCompleted
	j1.mu.Unlock()
	j2.mu.Lock()
	j2.Status = JobStatusFailed
	j2.mu.Unlock()
	j3.mu.Lock()
	j3.Status = JobStatusRunning
	j3.mu.Unlock()
	removed := jm.ClearCompletedJobs()
	if removed != 2 {
		t.Errorf("ClearCompletedJobs removed %d, want 2", removed)
	}
	if _, ok := jm.GetJob("j3"); !ok {
		t.Error("running job should not have been removed")
	}
}

func TestJob_IsCompleted(t *testing.T) {
	j := &Job{Status: JobStatusRunning}
	if j.IsCompleted() {
		t.Error("running job should not be completed")
	}
	j.mu.Lock()
	j.Status = JobStatusCompleted
	j.mu.Unlock()
	if !j.IsCompleted() {
		t.Error("completed job should be completed")
	}
	j.mu.Lock()
	j.Status = JobStatusCancelled
	j.mu.Unlock()
	if !j.IsCompleted() {
		t.Error("cancelled job should be completed")
	}
}

func TestJob_PhaseProgress(t *testing.T) {
	j := &Job{}
	j.SetPhaseProgress(3, 8, "DNS Lookup")
	c, tot, d := j.GetPhaseProgress()
	if c != 3 || tot != 8 || d != "DNS Lookup" {
		t.Errorf("GetPhaseProgress = (%d, %d, %q), want (3, 8, DNS Lookup)", c, tot, d)
	}
}

func TestJobManager_SetMaxConcurrent(t *testing.T) {
	jm := NewJobManager(1)
	jm.SetMaxConcurrent(5)
	jm.mu.RLock()
	max := jm.maxConcurrent
	jm.mu.RUnlock()
	if max != 5 {
		t.Errorf("maxConcurrent = %d, want 5", max)
	}
	jm.SetMaxConcurrent(0) // invalid — should be a no-op
	jm.mu.RLock()
	max = jm.maxConcurrent
	jm.mu.RUnlock()
	if max != 5 {
		t.Errorf("maxConcurrent after invalid set = %d, want 5", max)
	}
}

func TestGetAllJobs_Sorting(t *testing.T) {
	jm := NewJobManager(10)
	now := time.Now()
	j1 := jm.CreateJob("j1", "A", "/tmp/a.sh")
	j2 := jm.CreateJob("j2", "B", "/tmp/b.sh")
	j3 := jm.CreateJob("j3", "C", "/tmp/c.sh")
	j1.mu.Lock()
	j1.Status = JobStatusCompleted
	j1.StartTime = now.Add(-3 * time.Second)
	j1.mu.Unlock()
	j2.mu.Lock()
	j2.Status = JobStatusRunning
	j2.StartTime = now.Add(-2 * time.Second)
	j2.mu.Unlock()
	j3.mu.Lock()
	j3.Status = JobStatusPending
	j3.StartTime = now.Add(-1 * time.Second)
	j3.mu.Unlock()
	jobs := jm.GetAllJobs()
	if len(jobs) != 3 {
		t.Fatalf("GetAllJobs returned %d jobs, want 3", len(jobs))
	}
	if jobs[0].ID != "j2" {
		t.Errorf("first job = %s, want j2 (running)", jobs[0].ID)
	}
	if jobs[1].ID != "j3" {
		t.Errorf("second job = %s, want j3 (pending)", jobs[1].ID)
	}
	if jobs[2].ID != "j1" {
		t.Errorf("third job = %s, want j1 (completed)", jobs[2].ID)
	}
}
func TestParseVLANBreakdown(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []VLANStatus
	}{
		{
			name:  "empty string",
			input: "",
			want:  nil,
		},
		{
			name:  "no VLAN entries",
			input: "Phase 3: DNS Lookup",
			want:  nil,
		},
		{
			name:  "single VLAN with progress",
			input: "V100:3/8",
			want:  []VLANStatus{{ID: "V100", Current: 3, Total: 8}},
		},
		{
			name:  "single VLAN done",
			input: "V200:done",
			want:  []VLANStatus{{ID: "V200", Done: true}},
		},
		{
			name:  "multiple VLANs mixed",
			input: "V100:3/8 V200:done V300:1/8",
			want: []VLANStatus{
				{ID: "V100", Current: 3, Total: 8},
				{ID: "V200", Done: true},
				{ID: "V300", Current: 1, Total: 8},
			},
		},
		{
			name:  "checkmark variant",
			input: "V100:✓",
			want:  []VLANStatus{{ID: "V100", Done: true}},
		},
		{
			name:  "zero current count",
			input: "V100:0/5",
			want:  []VLANStatus{{ID: "V100", Current: 0, Total: 5}},
		},
		{
			name:  "completed count equals total",
			input: "V100:8/8",
			want:  []VLANStatus{{ID: "V100", Current: 8, Total: 8, Done: true}},
		},
		{
			name:  "invalid value after colon",
			input: "V100:abc",
			want:  []VLANStatus{{ID: "V100"}},
		},
		{
			name:  "invalid total",
			input: "V100:3/0",
			want:  []VLANStatus{{ID: "V100"}},
		},
		{
			name:  "mixed with non-VLAN text",
			input: "some text V100:3/8 more text V200:done",
			want: []VLANStatus{
				{ID: "V100", Current: 3, Total: 8},
				{ID: "V200", Done: true},
			},
		},
		{
			name:  "numeric VLAN IDs (L2 flow)",
			input: "10:3/8 20:done 30:1/8",
			want: []VLANStatus{
				{ID: "10", Current: 3, Total: 8},
				{ID: "20", Done: true},
				{ID: "30", Current: 1, Total: 8},
			},
		},
		{
			name:  "single digit numeric rejected",
			input: "3: DNS Lookup",
			want:  nil,
		},
		{
			name:  "mixed letter and numeric VLAN IDs",
			input: "V100:3/8 20:done 30:1/8",
			want: []VLANStatus{
				{ID: "V100", Current: 3, Total: 8},
				{ID: "20", Done: true},
				{ID: "30", Current: 1, Total: 8},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseVLANBreakdown(tt.input)
			if len(got) != len(tt.want) {
				t.Fatalf("ParseVLANBreakdown(%q) returned %d entries, want %d", tt.input, len(got), len(tt.want))
			}
			for i, v := range got {
				w := tt.want[i]
				if v.ID != w.ID || v.Current != w.Current || v.Total != w.Total || v.Done != w.Done {
					t.Errorf("entry[%d] = %+v, want %+v", i, v, w)
				}
			}
		})
	}
}
