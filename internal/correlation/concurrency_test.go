package correlation

import (
	"sync"
	"testing"
)

func TestConcurrentAddScanResult(t *testing.T) {
	tmpDir := t.TempDir()
	c := newCorrelatorWithDataDir(tmpDir, tmpDir)

	var wg sync.WaitGroup
	errors := make(chan error, 20)

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			result := &ScanResult{
				ID:   string(ScanTypeNetworkEnum) + "-" + string(rune('A'+idx)),
				Type: ScanTypeNetworkEnum,
				Hosts: []Host{
					{IP: "192.168.1." + string(rune('0'+idx%10))},
				},
			}
			if err := c.AddScanResult(result); err != nil {
				errors <- err
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("concurrent AddScanResult error: %v", err)
	}
}

func TestBatchAddConsistency(t *testing.T) {
	tmpDir1 := t.TempDir()
	c1 := newCorrelatorWithDataDir(tmpDir1, tmpDir1)

	tmpDir2 := t.TempDir()
	c2 := newCorrelatorWithDataDir(tmpDir2, tmpDir2)

	results := []*ScanResult{
		{
			ID:   "scan-1",
			Type: ScanTypeNetworkEnum,
			Hosts: []Host{
				{IP: "10.0.0.1"},
				{IP: "10.0.0.2"},
			},
		},
		{
			ID:   "scan-2",
			Type: ScanTypePortScan,
			Hosts: []Host{
				{IP: "10.0.0.1"},
				{IP: "10.0.0.3"},
			},
		},
	}

	// Individual adds
	for _, r := range results {
		if err := c1.AddScanResult(r); err != nil {
			t.Fatalf("individual AddScanResult error: %v", err)
		}
	}

	// Batch add
	if err := c2.BatchAddScanResults(results); err != nil {
		t.Fatalf("BatchAddScanResults error: %v", err)
	}

	corr1 := c1.GetAllCorrelations()
	corr2 := c2.GetAllCorrelations()

	if len(corr1) != len(corr2) {
		t.Errorf("correlation count mismatch: individual=%d batch=%d", len(corr1), len(corr2))
	}

	for ip := range corr1 {
		if _, exists := corr2[ip]; !exists {
			t.Errorf("host %s in individual results but not batch", ip)
		}
	}
}

func TestConcurrentReadsAfterWrite(t *testing.T) {
	tmpDir := t.TempDir()
	c := newCorrelatorWithDataDir(tmpDir, tmpDir)

	result := &ScanResult{
		ID:   "scan-1",
		Type: ScanTypeNetworkEnum,
		Hosts: []Host{
			{IP: "172.16.0.1"},
		},
	}
	if err := c.AddScanResult(result); err != nil {
		t.Fatalf("AddScanResult error: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.GetAllCorrelations()
			c.GetCorrelationForHost("172.16.0.1")
			c.GetHighRiskHosts(50)
		}()
	}
	wg.Wait()
}
