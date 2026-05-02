package correlation

import (
	"regexp"
	"strings"
)

// checkCompliance runs all compliance checks against a device's running config text.
// vendor is the value from metadata.txt (e.g. "cisco_ios", "hp_comware", "aruba_cx").
// Returns the list of findings and the overall worst severity ("critical", "warning", "ok", or "").
func checkCompliance(runningConfig, vendor string) ([]ComplianceFinding, string) {
	cfg := runningConfig
	lower := strings.ToLower(vendor)

	var findings []ComplianceFinding
	switch {
	case strings.Contains(lower, "cisco"):
		findings = checkCiscoIOS(cfg)
	case strings.Contains(lower, "hp_comware"), strings.Contains(lower, "comware"):
		findings = checkHPComware(cfg)
	case strings.Contains(lower, "aruba_cx"):
		findings = checkArubaCX(cfg)
	case strings.Contains(lower, "aruba_switch"), strings.Contains(lower, "provision"):
		findings = checkArubaSwitch(cfg)
	case strings.Contains(lower, "aruba"):
		findings = checkArubaCX(cfg)
	default:
		findings = checkGeneric(cfg)
	}

	worst := worstSeverity(findings)
	return findings, worst
}

func worstSeverity(findings []ComplianceFinding) string {
	worst := ""
	for _, f := range findings {
		switch f.Severity {
		case "critical":
			return "critical"
		case "warning":
			worst = "warning"
		case "ok":
			if worst == "" {
				worst = "ok"
			}
		}
	}
	return worst
}

// --- Cisco IOS / NX-OS ---

func checkCiscoIOS(cfg string) []ComplianceFinding {
	var out []ComplianceFinding
	out = append(out, checkTelnet(cfg))
	out = append(out, checkHTTPServer(cfg))
	out = append(out, checkDefaultSNMP(cfg))
	out = append(out, checkSSHVersion(cfg))
	out = append(out, checkAAA(cfg))
	out = append(out, checkEnableSecret(cfg))
	out = append(out, checkPasswordEncryption(cfg))
	out = append(out, checkLoginBanner(cfg))
	out = append(out, checkNTP(cfg))
	out = append(out, checkSyslog(cfg))
	out = append(out, checkVTYTimeout(cfg))
	return out
}

// checkTelnet detects telnet enabled on VTY lines.
var reTelnetEnabled = regexp.MustCompile(`(?m)^\s*transport input\s+(telnet|all)\s*$`)

func checkTelnet(cfg string) ComplianceFinding {
	if reTelnetEnabled.MatchString(cfg) {
		return ComplianceFinding{"Telnet enabled", "critical", "VTY line allows telnet (transport input telnet/all)"}
	}
	return ComplianceFinding{"Telnet disabled", "ok", ""}
}

// checkHTTPServer detects unmanaged HTTP management server.
// "no ip http server" negates it; bare "ip http server" is a finding.
func checkHTTPServer(cfg string) ComplianceFinding {
	lines := strings.Split(cfg, "\n")
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if t == "ip http server" {
			return ComplianceFinding{"HTTP management server enabled", "critical", "\"ip http server\" enables unencrypted management access"}
		}
	}
	return ComplianceFinding{"HTTP management server disabled", "ok", ""}
}

// checkDefaultSNMP detects default/well-known SNMP community strings.
var reDefaultSNMP = regexp.MustCompile(`(?mi)^\s*snmp-server community\s+(public|private)\b`)

func checkDefaultSNMP(cfg string) ComplianceFinding {
	if reDefaultSNMP.MatchString(cfg) {
		return ComplianceFinding{"Default SNMP community", "critical", "SNMP community \"public\" or \"private\" configured"}
	}
	return ComplianceFinding{"SNMP community strings", "ok", ""}
}

// checkSSHVersion detects absence of explicit SSH v2 enforcement.
var reSSHv2 = regexp.MustCompile(`(?m)^\s*ip ssh version 2\s*$`)

func checkSSHVersion(cfg string) ComplianceFinding {
	if !reSSHv2.MatchString(cfg) {
		return ComplianceFinding{"SSH version not locked to v2", "warning", "\"ip ssh version 2\" not found; SSHv1 may be negotiated"}
	}
	return ComplianceFinding{"SSH v2 enforced", "ok", ""}
}

// checkAAA detects absence of AAA.
var reAAA = regexp.MustCompile(`(?m)^\s*aaa new-model\s*$`)

func checkAAA(cfg string) ComplianceFinding {
	if !reAAA.MatchString(cfg) {
		return ComplianceFinding{"AAA not configured", "warning", "\"aaa new-model\" not found"}
	}
	return ComplianceFinding{"AAA configured", "ok", ""}
}

// checkEnableSecret detects use of enable password instead of enable secret.
var reEnableSecret = regexp.MustCompile(`(?m)^\s*enable secret\b`)
var reEnablePassword = regexp.MustCompile(`(?m)^\s*enable password\b`)

func checkEnableSecret(cfg string) ComplianceFinding {
	hasSecret := reEnableSecret.MatchString(cfg)
	hasPassword := reEnablePassword.MatchString(cfg)
	if hasPassword && !hasSecret {
		return ComplianceFinding{"Weak enable credential", "warning", "\"enable password\" used instead of \"enable secret\" (MD5 vs scrypt)"}
	}
	if hasSecret {
		return ComplianceFinding{"Enable secret configured", "ok", ""}
	}
	return ComplianceFinding{"No enable credential", "warning", "Neither \"enable secret\" nor \"enable password\" found"}
}

// checkPasswordEncryption detects absence of service password-encryption.
var rePasswordEncryption = regexp.MustCompile(`(?m)^\s*service password-encryption\s*$`)

func checkPasswordEncryption(cfg string) ComplianceFinding {
	if !rePasswordEncryption.MatchString(cfg) {
		return ComplianceFinding{"Password encryption disabled", "warning", "\"service password-encryption\" not found; passwords may be stored in plaintext"}
	}
	return ComplianceFinding{"Password encryption enabled", "ok", ""}
}

// checkLoginBanner detects absence of login or MOTD banner.
var reBanner = regexp.MustCompile(`(?m)^\s*banner (login|motd)\b`)

func checkLoginBanner(cfg string) ComplianceFinding {
	if !reBanner.MatchString(cfg) {
		return ComplianceFinding{"No login banner", "warning", "No \"banner login\" or \"banner motd\" configured"}
	}
	return ComplianceFinding{"Login banner configured", "ok", ""}
}

// checkNTP detects absence of NTP server configuration.
var reNTP = regexp.MustCompile(`(?m)^\s*ntp server\b`)

func checkNTP(cfg string) ComplianceFinding {
	if !reNTP.MatchString(cfg) {
		return ComplianceFinding{"NTP not configured", "warning", "No \"ntp server\" found"}
	}
	return ComplianceFinding{"NTP configured", "ok", ""}
}

// checkSyslog detects absence of a logging destination (syslog server IP).
var reSyslogServer = regexp.MustCompile(`(?m)^\s*logging\s+\d+\.\d+\.\d+\.\d+`)

func checkSyslog(cfg string) ComplianceFinding {
	if !reSyslogServer.MatchString(cfg) {
		return ComplianceFinding{"Syslog server not configured", "warning", "No \"logging <ip>\" server found"}
	}
	return ComplianceFinding{"Syslog configured", "ok", ""}
}

// --- HP Comware ---
var reComwareTelnet = regexp.MustCompile(`(?mi)^\s*protocol inbound telnet`)
var reComwareSNMP = regexp.MustCompile(`(?mi)snmp-agent community\s+(read|write)\s+(public|private)\b`)
var reComwareSSH = regexp.MustCompile(`(?mi)ssh server enable`)
var reComwareNTP = regexp.MustCompile(`(?mi)ntp-service unicast-server`)
var reComwareSyslog = regexp.MustCompile(`(?mi)info-center loghost`)

// --- ArubaOS-CX ---
var reArubaCXTelnet = regexp.MustCompile(`(?mi)^\s*telnet-server`)
var reArubaCXSSH = regexp.MustCompile(`(?mi)^\s*ssh server`)
var reArubaCXSNMP = regexp.MustCompile(`(?mi)^\s*snmp-server community\s+(public|private)\b`)
var reArubaCXNTP = regexp.MustCompile(`(?mi)^\s*ntp server\b`)
var reArubaCXSyslog = regexp.MustCompile(`(?mi)^\s*logging\s+\d+\.\d+\.\d+\.\d+`)

// --- ArubaOS-Switch / ProVision ---
var reArubaSwitchTelnet = regexp.MustCompile(`(?mi)^\s*(telnet-server|ip telnet)`)
var reArubaSwitchSSH = regexp.MustCompile(`(?mi)^\s*(ip ssh|crypto ssh)`)
var reArubaSwitchSNMP = regexp.MustCompile(`(?mi)^\s*snmp-server community\s+(public|private)\b`)
var reArubaSwitchNTP = regexp.MustCompile(`(?mi)^\s*(timep|sntp)\s+`)
var reArubaSwitchSyslog = regexp.MustCompile(`(?mi)^\s*logging\s+\d+\.\d+\.\d+\.\d+`)

// --- Generic / fallback ---
var reGenericSNMP = regexp.MustCompile(`(?mi)(community|snmp).*\b(public|private)\b`)


// checkVTYTimeout detects absence of exec-timeout on VTY lines.
// Scans for a "line vty" block and checks for exec-timeout inside it.
func checkVTYTimeout(cfg string) ComplianceFinding {
	lines := strings.Split(cfg, "\n")
	inVTY := false
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "line vty") {
			inVTY = true
			continue
		}
		if inVTY {
			if strings.HasPrefix(t, "line ") || (len(t) > 0 && t[0] != ' ' && t[0] != '!') {
				// left the VTY block without finding exec-timeout
				break
			}
			if strings.HasPrefix(t, "no exec-timeout") {
				return ComplianceFinding{"VTY timeout disabled", "warning", "\"no exec-timeout\" disables session timeout (infinite session)"}
			}
			if strings.HasPrefix(t, "exec-timeout") {
				return ComplianceFinding{"VTY session timeout configured", "ok", ""}
			}
		}
	}
	if inVTY {
		return ComplianceFinding{"No VTY session timeout", "warning", "\"exec-timeout\" not found in line vty block"}
	}
	return ComplianceFinding{"VTY lines not found", "warning", "No \"line vty\" block in config"}
}

// --- HP Comware ---

func checkHPComware(cfg string) []ComplianceFinding {
	var out []ComplianceFinding
	// Telnet: look for "user-interface vty" block with "protocol inbound telnet"
	if reComwareTelnet.MatchString(cfg) {
		out = append(out, ComplianceFinding{"Telnet enabled", "critical", "\"protocol inbound telnet\" in user-interface vty"})
	} else {
		out = append(out, ComplianceFinding{"Telnet disabled", "ok", ""})
	}
	// SNMP default communities
	if reComwareSNMP.MatchString(cfg) {
		out = append(out, ComplianceFinding{"Default SNMP community", "critical", "SNMP community \"public\" or \"private\" configured"})
	} else {
		out = append(out, ComplianceFinding{"SNMP community strings", "ok", ""})
	}
	// SSH
	if !reComwareSSH.MatchString(cfg) {
		out = append(out, ComplianceFinding{"SSH server not enabled", "warning", "\"ssh server enable\" not found"})
	} else {
		out = append(out, ComplianceFinding{"SSH enabled", "ok", ""})
	}
	// NTP
	if !reComwareNTP.MatchString(cfg) {
		out = append(out, ComplianceFinding{"NTP not configured", "warning", "No \"ntp-service unicast-server\" found"})
	} else {
		out = append(out, ComplianceFinding{"NTP configured", "ok", ""})
	}
	// Syslog
	if !reComwareSyslog.MatchString(cfg) {
		out = append(out, ComplianceFinding{"Syslog server not configured", "warning", "No \"info-center loghost\" found"})
	} else {
		out = append(out, ComplianceFinding{"Syslog configured", "ok", ""})
	}
	return out
}

// --- ArubaOS-CX ---

func checkArubaCX(cfg string) []ComplianceFinding {
	var out []ComplianceFinding
	// Telnet
	if reArubaCXTelnet.MatchString(cfg) {
		out = append(out, ComplianceFinding{"Telnet enabled", "critical", "\"telnet-server\" found in running config"})
	} else {
		out = append(out, ComplianceFinding{"Telnet disabled", "ok", ""})
	}
	// SNMP default communities
	if reArubaCXSNMP.MatchString(cfg) {
		out = append(out, ComplianceFinding{"Default SNMP community", "critical", "SNMP community \"public\" or \"private\" configured"})
	} else {
		out = append(out, ComplianceFinding{"SNMP community strings", "ok", ""})
	}
	// SSH
	if !reArubaCXSSH.MatchString(cfg) {
		out = append(out, ComplianceFinding{"SSH server not configured", "warning", "\"ssh server\" not found"})
	} else {
		out = append(out, ComplianceFinding{"SSH configured", "ok", ""})
	}
	// NTP
	if !reArubaCXNTP.MatchString(cfg) {
		out = append(out, ComplianceFinding{"NTP not configured", "warning", "No \"ntp server\" found"})
	} else {
		out = append(out, ComplianceFinding{"NTP configured", "ok", ""})
	}
	// Syslog
	if !reArubaCXSyslog.MatchString(cfg) {
		out = append(out, ComplianceFinding{"Syslog server not configured", "warning", "No \"logging <ip>\" found"})
	} else {
		out = append(out, ComplianceFinding{"Syslog configured", "ok", ""})
	}
	return out
}

// --- ArubaOS-Switch / ProVision ---

func checkArubaSwitch(cfg string) []ComplianceFinding {
	var out []ComplianceFinding
	// Telnet
	if reArubaSwitchTelnet.MatchString(cfg) {
		out = append(out, ComplianceFinding{"Telnet enabled", "critical", "\"telnet-server\" or \"ip telnet\" found in running config"})
	} else {
		out = append(out, ComplianceFinding{"Telnet disabled", "ok", ""})
	}
	// SNMP default communities
	if reArubaSwitchSNMP.MatchString(cfg) {
		out = append(out, ComplianceFinding{"Default SNMP community", "critical", "SNMP community \"public\" or \"private\" configured"})
	} else {
		out = append(out, ComplianceFinding{"SNMP community strings", "ok", ""})
	}
	// SSH
	if !reArubaSwitchSSH.MatchString(cfg) {
		out = append(out, ComplianceFinding{"SSH not configured", "warning", "\"ip ssh\" or \"crypto ssh\" not found"})
	} else {
		out = append(out, ComplianceFinding{"SSH configured", "ok", ""})
	}
	// NTP
	if !reArubaSwitchNTP.MatchString(cfg) {
		out = append(out, ComplianceFinding{"NTP not configured", "warning", "No \"timep\" or \"sntp\" configuration found"})
	} else {
		out = append(out, ComplianceFinding{"NTP configured", "ok", ""})
	}
	// Syslog
	if !reArubaSwitchSyslog.MatchString(cfg) {
		out = append(out, ComplianceFinding{"Syslog server not configured", "warning", "No \"logging <ip>\" found"})
	} else {
		out = append(out, ComplianceFinding{"Syslog configured", "ok", ""})
	}
	return out
}

// --- Generic / fallback ---

func checkGeneric(cfg string) []ComplianceFinding {
	var out []ComplianceFinding
	telnetFound := false
	for _, line := range strings.Split(cfg, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "!") || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "no ") {
			continue
		}
		if strings.Contains(strings.ToLower(t), "telnet") {
			telnetFound = true
			break
		}
	}
	if telnetFound {
		out = append(out, ComplianceFinding{"Possible telnet reference", "warning", "\"telnet\" found in config \u2014 verify it is not enabled for management access"})
	} else {
		out = append(out, ComplianceFinding{"No telnet reference", "ok", ""})
	}
	// Default SNMP communities (keyword pattern works across vendors)
	if reGenericSNMP.MatchString(cfg) {
		out = append(out, ComplianceFinding{"Default SNMP community", "critical", "\"public\" or \"private\" SNMP community string detected"})
	}
	return out
}
