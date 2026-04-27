package correlation

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewTopologyGenerator(t *testing.T) {
	tg := NewTopologyGenerator("/tmp/test")
	if tg == nil {
		t.Fatal("expected non-nil TopologyGenerator")
	}
	if tg.workspaceDir != "/tmp/test" {
		t.Errorf("workspaceDir = %q, want %q", tg.workspaceDir, "/tmp/test")
	}
}
func TestGenerateHTMLViewer_Empty(t *testing.T) {
	tg := NewTopologyGenerator(t.TempDir())
	_, err := tg.GenerateHTMLViewer(map[string]*CorrelationResult{})
	if err == nil {
		t.Fatal("expected error for empty correlations")
	}
}

func TestGenerateHTMLViewer_BasicOutput(t *testing.T) {
	dir := t.TempDir()
	tg := NewTopologyGenerator(dir)

	correlations := map[string]*CorrelationResult{
		"10.0.0.1": {
			Host: "10.0.0.1",
			HostInfo: &Host{
				IP:       "10.0.0.1",
				Hostname: "webserver",
				OS:       "Linux 5.15",
				Attributes: map[string]string{
					"category": "linux",
					"vlan_id":  "100",
				},
				Ports: []Port{
					{Number: 80, Protocol: "tcp", State: "open", Service: "http"},
				},
			},
		},
	}

	htmlPath, err := tg.GenerateHTMLViewer(correlations)
	if err != nil {
		t.Fatalf("GenerateHTMLViewer failed: %v", err)
	}

	if !filepath.IsAbs(htmlPath) {
		t.Errorf("expected absolute path, got %q", htmlPath)
	}
	if !strings.HasSuffix(htmlPath, ".html") {
		t.Errorf("expected .html suffix, got %q", htmlPath)
	}

	data, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("reading HTML file: %v", err)
	}
	content := string(data)

	for _, want := range []string{
		"<!DOCTYPE html>",
		"Network Topology Viewer",
		"10.0.0.1",
		"webserver",
		"Linux 5.15",
		"const VLANS",
		"graph-container",
		"const CONNECTIONS",
		"tab-bar",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("HTML viewer missing %q", want)
		}
	}

	// Should be self-contained (no external references)
	if strings.Contains(content, "src=\"") || strings.Contains(content, "href=\"http") {
		t.Error("HTML viewer should not reference external resources")
	}
}

// ─── GenerateAll ────────────────────────────────────────────────

func TestGenerateAll_Empty(t *testing.T) {
	tg := NewTopologyGenerator(t.TempDir())
	_, err := tg.GenerateAll(map[string]*CorrelationResult{})
	if err == nil {
		t.Fatal("expected error for empty correlations")
	}
}


func TestGenerateAll_BasicOutput(t *testing.T) {
	dir := t.TempDir()
	tg := NewTopologyGenerator(dir)

	correlations := map[string]*CorrelationResult{
		"10.0.0.1": {
			Host: "10.0.0.1",
			HostInfo: &Host{
				IP:       "10.0.0.1",
				Hostname: "webserver",
				Attributes: map[string]string{
					"category": "linux",
					"vlan_id":  "100",
				},
			},
		},
		"10.0.1.10": {
			Host: "10.0.1.10",
			HostInfo: &Host{
				IP: "10.0.1.10",
				Attributes: map[string]string{
					"category": "windows",
					"vlan_id":  "200",
				},
			},
		},
	}

	out, err := tg.GenerateAll(correlations)
	if err != nil {
		t.Fatalf("GenerateAll failed: %v", err)
	}

	if out.HTMLViewer == "" {
		t.Error("expected HTMLViewer path")
	}
	if !strings.HasSuffix(out.HTMLViewer, ".html") {
		t.Errorf("expected .html suffix, got %q", out.HTMLViewer)
	}
}


// ─── Connection Inference ──────────────────────────────────────

func TestInferConnections_NoGateways(t *testing.T) {
	tg := NewTopologyGenerator(t.TempDir())
	correlations := map[string]*CorrelationResult{
		"10.0.0.1": {
			Host: "10.0.0.1",
			HostInfo: &Host{IP: "10.0.0.1", Attributes: map[string]string{"vlan_id": "100"}},
		},
		"10.0.0.2": {
			Host: "10.0.0.2",
			HostInfo: &Host{IP: "10.0.0.2", Attributes: map[string]string{"vlan_id": "100"}},
		},
	}
	vlanGroups := tg.groupByVLAN(correlations)
	conns := tg.inferConnections(correlations, vlanGroups)

	// Single VLAN, no gateways — only same_vlan links
	for _, c := range conns {
		if c.Type != "same_vlan" {
			t.Errorf("expected only same_vlan connections, got %q", c.Type)
		}
	}
	// Should have a link between the two hosts
	if len(conns) != 1 {
		t.Errorf("expected 1 same_vlan connection, got %d", len(conns))
	}
	conns[0].Source = "10.0.0.1"
	conns[0].Target = "10.0.0.2"
}

func TestInferConnections_WithGateway(t *testing.T) {
	tg := NewTopologyGenerator(t.TempDir())
	correlations := map[string]*CorrelationResult{
		"10.0.0.1": {
			Host: "10.0.0.1",
			HostInfo: &Host{IP: "10.0.0.1", Attributes: map[string]string{"vlan_id": "100"}},
		},
		"10.0.1.1": {
			Host: "10.0.1.1",
			HostInfo: &Host{IP: "10.0.1.1", Attributes: map[string]string{"vlan_id": "200"}},
		},
		"10.0.0.254": {
			Host: "10.0.0.254",
			HostInfo: &Host{IP: "10.0.0.254", Attributes: map[string]string{"vlan_id": "100", "device_type": "router"}},
		},
	}
	vlanGroups := tg.groupByVLAN(correlations)
	conns := tg.inferConnections(correlations, vlanGroups)

	hasGateway := false
	for _, c := range conns {
		if c.Type == "gateway" {
			hasGateway = true
			break
		}
	}
	if !hasGateway {
		t.Error("expected at least one gateway connection")
	}
}

func TestIsGateway(t *testing.T) {
	tests := []struct {
		name   string
		corr   *CorrelationResult
		expect bool
	}{
		{"nil hostinfo", &CorrelationResult{}, false},
		{"nil attrs", &CorrelationResult{HostInfo: &Host{}}, false},
		{"router", &CorrelationResult{HostInfo: &Host{Attributes: map[string]string{"device_type": "router"}}}, true},
		{"gateway", &CorrelationResult{HostInfo: &Host{Attributes: map[string]string{"device_type": "gateway"}}}, true},
		{"firewall", &CorrelationResult{HostInfo: &Host{Attributes: map[string]string{"device_type": "firewall"}}}, true},
		{"switch", &CorrelationResult{HostInfo: &Host{Attributes: map[string]string{"device_type": "switch"}}}, false},
		{"caps router", &CorrelationResult{HostInfo: &Host{Attributes: map[string]string{"capabilities": "router"}}}, true},
		{"caps switch only", &CorrelationResult{HostInfo: &Host{Attributes: map[string]string{"capabilities": "switch"}}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isGateway(tt.corr)
			if got != tt.expect {
				t.Errorf("isGateway() = %v, want %v", got, tt.expect)
			}
		})
	}
}

// ─── IsLocal Detection ────────────────────────────────────────

func TestGenerateHTMLViewer_IsLocal(t *testing.T) {
	dir := t.TempDir()
	tg := NewTopologyGenerator(dir)

	// Single VLAN scenario — only hosts on same subnet are local
	correlations := map[string]*CorrelationResult{
		"10.0.0.1": {
			Host: "10.0.0.1",
			HostInfo: &Host{IP: "10.0.0.1", Attributes: map[string]string{"vlan_id": "100"}},
		},
		"10.0.0.2": {
			Host: "10.0.0.2",
			HostInfo: &Host{IP: "10.0.0.2", Attributes: map[string]string{"vlan_id": "100"}},
		},
	}

	htmlPath, err := tg.GenerateHTMLViewer(correlations)
	if err != nil {
		t.Fatalf("GenerateHTMLViewer failed: %v", err)
	}

	data, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("reading HTML: %v", err)
	}
	content := string(data)

	// Both hosts are on same subnet, single VLAN, so both should be is_local:true
	if !strings.Contains(content, `"is_local":true`) {
		t.Error("expected is_local:true for hosts on same segment")
	}
}

func TestGenerateHTMLViewer_MultiVLANAllLocal(t *testing.T) {
	dir := t.TempDir()
	tg := NewTopologyGenerator(dir)

	// Multi-VLAN scenario — all hosts are considered local (trunk connection)
	correlations := map[string]*CorrelationResult{
		"10.0.0.1": {
			Host: "10.0.0.1",
			HostInfo: &Host{IP: "10.0.0.1", Attributes: map[string]string{"vlan_id": "100"}},
		},
		"10.0.1.1": {
			Host: "10.0.1.1",
			HostInfo: &Host{IP: "10.0.1.1", Attributes: map[string]string{"vlan_id": "200"}},
		},
	}

	htmlPath, err := tg.GenerateHTMLViewer(correlations)
	if err != nil {
		t.Fatalf("GenerateHTMLViewer failed: %v", err)
	}

	data, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("reading HTML: %v", err)
	}
	content := string(data)

	// Multi-VLAN means trunk, so all hosts should be local
	localCount := strings.Count(content, `"is_local":true`)
	if localCount != 2 {
		t.Errorf("expected 2 is_local:true for multi-VLAN trunk, got %d", localCount)
	}
}

func TestGenerateHTMLViewer_RiskAndVulnData(t *testing.T) {
	dir := t.TempDir()
	tg := NewTopologyGenerator(dir)

	correlations := map[string]*CorrelationResult{
		"10.0.0.1": {
			Host: "10.0.0.1",
			HostInfo: &Host{IP: "10.0.0.1", Attributes: map[string]string{"vlan_id": "100"}},
			RiskScore: 500,
			RiskDetails: RiskBreakdown{
				VulnerabilityScore: 200,
				SSLIssues:          100,
				ServiceExposure:    100,
				OpenPortScore:      100,
				Total:              500,
			},
			Vulnerabilities: []Vulnerability{{
				Host:     "10.0.0.1",
				Title:    "Test Vuln",
				Severity: "high",
			}},
			Recommendations: []string{"Patch immediately"},
		},
	}

	htmlPath, err := tg.GenerateHTMLViewer(correlations)
	if err != nil {
		t.Fatalf("GenerateHTMLViewer failed: %v", err)
	}

	data, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("reading HTML: %v", err)
	}
	content := string(data)

	for _, want := range []string{
		`"risk_score":500`,
		`"vulnerability_score":200`,
		`"Test Vuln"`,
		`"Patch immediately"`,
	} {
		if !strings.Contains(content, want) {
			t.Errorf("HTML viewer missing risk/vuln data: %q", want)
		}
	}
}