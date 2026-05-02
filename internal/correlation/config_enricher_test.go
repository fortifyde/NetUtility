package correlation

import (
	"os"
	"path/filepath"
	"testing"
)

// ─── normalizeMAC ────────────────────────────────────────────────

func TestNormalizeMAC_CiscoDot(t *testing.T) {
	got := normalizeMAC("aabb.cc00.0102")
	want := "aa:bb:cc:00:01:02"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestNormalizeMAC_HPDash(t *testing.T) {
	got := normalizeMAC("aabb-cc00-0102")
	want := "aa:bb:cc:00:01:02"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestNormalizeMAC_Colon(t *testing.T) {
	got := normalizeMAC("AA:BB:CC:00:01:02")
	want := "aa:bb:cc:00:01:02"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestNormalizeMAC_Invalid(t *testing.T) {
	if got := normalizeMAC("not-a-mac"); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

// ─── parseMACTable ────────────────────────────────────────────────

func TestParseMACTable_CiscoIOS(t *testing.T) {
	input := `
=== show mac address-table ===

          Mac Address Table
-------------------------------------------
Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
  10    aabb.cc00.0100    DYNAMIC     Gi0/1
  20    aabb.cc00.0200    DYNAMIC     Gi0/2
   1    aabb.cc00.0300    STATIC      Gi0/3
`
	idx := newMACIndex()
	idx.parse(input, "10.0.0.1")

	cases := []struct {
		mac   string
		iface string
		vlan  int
	}{
		{"aa:bb:cc:00:01:00", "Gi0/1", 10},
		{"aa:bb:cc:00:02:00", "Gi0/2", 20},
		{"aa:bb:cc:00:03:00", "Gi0/3", 1},
	}
	for _, c := range cases {
		e, ok := idx.entries[c.mac]
		if !ok {
			t.Errorf("MAC %s not found in index", c.mac)
			continue
		}
		if e.Interface != c.iface {
			t.Errorf("MAC %s: iface got %q want %q", c.mac, e.Interface, c.iface)
		}
		if e.VLAN != c.vlan {
			t.Errorf("MAC %s: vlan got %d want %d", c.mac, e.VLAN, c.vlan)
		}
	}
}

func TestParseMACTable_HPDash(t *testing.T) {
	input := `
display mac-address
MAC ADDR        VLAN ID   STATE           PORT INDEX
aabb-cc00-0101  10        Learned         GE1/0/1
`
	idx := newMACIndex()
	idx.parse(input, "10.0.0.2")
	mac := "aa:bb:cc:00:01:01"
	e, ok := idx.entries[mac]
	if !ok {
		t.Fatalf("MAC %s not found", mac)
	}
	if e.Interface != "GE1/0/1" {
		t.Errorf("iface got %q want GE1/0/1", e.Interface)
	}
}

// ─── checkCompliance ─────────────────────────────────────────────

func TestCheckCompliance_TelnetEnabled(t *testing.T) {
	cfg := `
hostname SW-CORE
!
line vty 0 4
 transport input telnet
 exec-timeout 5 0
`
	findings, severity := checkCompliance(cfg, "cisco_ios")
	if severity != "critical" {
		t.Errorf("severity got %q want critical", severity)
	}
	found := false
	for _, f := range findings {
		if f.Check == "Telnet enabled" && f.Severity == "critical" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected Telnet enabled critical finding, got: %+v", findings)
	}
}

func TestCheckCompliance_Clean(t *testing.T) {
	cfg := `
hostname SW-CORE
service password-encryption
aaa new-model
enable secret 5 $1$abc
ip ssh version 2
ntp server 10.0.0.1
logging 10.0.0.2
banner login ^Authorized access only^
!
line vty 0 4
 transport input ssh
 exec-timeout 5 0
`
	findings, severity := checkCompliance(cfg, "cisco_ios")
	if severity == "critical" {
		t.Errorf("expected no critical findings, got: %+v", findings)
	}
	for _, f := range findings {
		if f.Severity == "critical" {
			t.Errorf("unexpected critical finding: %+v", f)
		}
	}
}

func TestCheckCompliance_DefaultSNMP(t *testing.T) {
	cfg := `snmp-server community public RO`
	findings, severity := checkCompliance(cfg, "cisco_ios")
	if severity != "critical" {
		t.Errorf("severity got %q want critical", severity)
	}
	found := false
	for _, f := range findings {
		if f.Check == "Default SNMP community" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected default SNMP finding")
	}
}

// ─── ConfigEnricher ──────────────────────────────────────────────

func TestConfigEnricher_HasConfigs_Empty(t *testing.T) {
	dir := t.TempDir()
	ce := NewConfigEnricher(dir)
	if ce.HasConfigs() {
		t.Error("expected HasConfigs to return false for empty workspace")
	}
}

func TestConfigEnricher_HasConfigs_WithDir(t *testing.T) {
	dir := t.TempDir()
	deviceDir := filepath.Join(dir, "configs", "10.0.0.1")
	if err := os.MkdirAll(deviceDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deviceDir, "metadata.txt"),
		[]byte("IP Address: 10.0.0.1\nVendor/OS: cisco_ios\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ce := NewConfigEnricher(dir)
	if !ce.HasConfigs() {
		t.Error("expected HasConfigs to return true")
	}
}

func TestConfigEnricher_Enrich_ComplianceAndMAC(t *testing.T) {
	dir := t.TempDir()
	deviceDir := filepath.Join(dir, "configs", "10.0.0.1")
	if err := os.MkdirAll(deviceDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Write metadata
	if err := os.WriteFile(filepath.Join(deviceDir, "metadata.txt"),
		[]byte("IP Address: 10.0.0.1\nVendor/OS: cisco_ios\nHostname: SW-CORE\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Running config with telnet enabled
	if err := os.WriteFile(filepath.Join(deviceDir, "running_config.txt"),
		[]byte("hostname SW-CORE\nline vty 0 4\n transport input telnet\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Compliance output with MAC table entry for a host
	if err := os.WriteFile(filepath.Join(deviceDir, "compliance_commands.txt"),
		[]byte("show mac address-table\n  10    aabb.cc00.0200    DYNAMIC     Gi0/5\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	correlations := map[string]*CorrelationResult{
		"10.0.0.1": {
			Host:     "10.0.0.1",
			HostInfo: &Host{IP: "10.0.0.1"},
		},
		"10.0.0.2": {
			Host: "10.0.0.2",
			HostInfo: &Host{
				IP:         "10.0.0.2",
				MACAddress: "aa:bb:cc:00:02:00",
			},
		},
	}

	ce := NewConfigEnricher(dir)
	if err := ce.Enrich(correlations); err != nil {
		t.Fatalf("Enrich error: %v", err)
	}

	sw := correlations["10.0.0.1"]
	if sw.ComplianceSeverity != "critical" {
		t.Errorf("switch compliance severity got %q want critical", sw.ComplianceSeverity)
	}
	if len(sw.ComplianceFindings) == 0 {
		t.Error("expected compliance findings on switch")
	}

	host := correlations["10.0.0.2"]
	if len(host.PhysicalLinks) == 0 {
		t.Error("expected physical link on host")
	} else {
		pl := host.PhysicalLinks[0]
		if pl.SwitchIP != "10.0.0.1" {
			t.Errorf("physical link switch IP got %q want 10.0.0.1", pl.SwitchIP)
		}
		if pl.Interface != "Gi0/5" {
			t.Errorf("physical link interface got %q want Gi0/5", pl.Interface)
		}
	}
}
