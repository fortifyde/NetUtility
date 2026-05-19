#!/usr/bin/env python3
"""
Network Config Gatherer — netmiko-based replacement for gather_network_configs.sh.

SSH into network devices, auto-detect vendor, extract running configs and
compliance data. Handles pagination correctly even when terminal paging commands
(terminal length 0, etc.) are blocked by AAA authorization.

Supports: Cisco IOS, Cisco Nexus, HP Comware, HP ProVision, HP Aruba CX/Switch
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
    from paramiko.ssh_exception import IncompatiblePeer
except ImportError:
    print("Error: netmiko is required. Install with: pip install netmiko", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VERSION = "1.0.0"
SCRIPT_DIR = Path(__file__).resolve().parent
COMMANDS_DIR = SCRIPT_DIR / "commands"
WORKDIR = os.environ.get("NETUTIL_WORKDIR", str(Path.home()))

# Vendor name → netmiko device_type
NETMIKO_DEVICE_MAP = {
    "cisco_ios": "cisco_ios",
    "cisco_nexus": "cisco_nxos",
    "hp_comware": "hp_comware",
    "hp_provision": "hp_procurve",
    "aruba_switch": "aruba_osswitch",
    "aruba_cx": "aruba_os",
    "generic": "autodetect",
}

# Vendor name → terminal paging disable command
TERMINAL_SETUP = {
    "cisco_ios": "terminal length 0",
    "cisco_nexus": "terminal length 0",
    "hp_comware": "screen-length disable",
    "hp_provision": "no page",
    "aruba_switch": "no page",
    "aruba_cx": "no paging",
}

# Vendor name → fallback terminal command when primary fails
# (mirrors get_terminal_fallback() in the shell script)
TERMINAL_FALLBACK = {
    "cisco_nexus": "terminal pager cat",
    "hp_comware": "screen-length 0 temporary",
    "hp_provision": "terminal length 0",
    "aruba_switch": "terminal length 0",
    "aruba_cx": "terminal length 0",
}

# Pagination markers that indicate output was truncated
PAGINATION_MARKERS = ("--More--", "---- More ----", "Press any key")

# Legacy SSH config for devices that need old ciphers/kex/hostkey algorithms.
# Written to a temp file and passed to sshpass via -F.
LEGACY_SSH_CONFIG = """\
KexAlgorithms +diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1
HostKeyAlgorithms +ssh-rsa
Ciphers +aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc
MACs +hmac-sha1,hmac-md5
"""

# Try importing pexpect (optional, used for pagination fallback)
try:
    import pexpect
    HAS_PEXPECT = True
except ImportError:
    HAS_PEXPECT = False

# netmiko device_type → vendor name (reverse lookup for version-based detection)
VENDOR_PATTERNS = [
    (r"Cisco IOS Software|IOS \(tm\)|Cisco Internetwork", "cisco_ios"),
    (r"NX-OS|Nexus Operating System|cisco Nexus", "cisco_nexus"),
    (r"Comware Software|HPE Comware|HP Comware Platform", "hp_comware"),
    (r"ArubaOS-CX", "aruba_cx"),
    (r"ArubaOS-Switch|Aruba", "aruba_switch"),
    (r"[A-Z][A-Z]\.[0-9][0-9]\.[0-9]", "aruba_switch"),
    (r"J[0-9]{4}", "aruba_switch"),
    (r"ProVision|Image stamp", "hp_provision"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def log(msg, prefix="ℹ"):
    """Print info message to stderr for TUI compatibility."""
    print(f"{prefix} {msg}", file=sys.stderr)


def log_step(msg):
    print(f"→ {msg}", file=sys.stderr)


def log_success(msg):
    print(f"✓ {msg}", file=sys.stderr)


def log_error(msg):
    print(f"✗ ERROR: {msg}", file=sys.stderr)


def log_warning(msg):
    print(f"⚠ WARNING: {msg}", file=sys.stderr)


def prompt(text: str) -> str:
    """Display prompt to stderr (TUI-compatible) and read from stdin.

    Python's input() sends its prompt argument to stdout, which is
    line-buffered when piped through the TUI.  The TUI reads stdout
    line-by-line, so a prompt without a trailing newline is never
    displayed until *after* the user sends input.  Writing the prompt
    to stderr (with a trailing newline) matches the convention used
    by all shell scripts in this project (printf "..." >&2).
    """
    print(text, file=sys.stderr, flush=True)
    return input("")


def print_header():
    print("=" * 50, file=sys.stderr)
    print("  Network Config Gatherer (netmiko)", file=sys.stderr)
    print("=" * 50, file=sys.stderr)
    print(file=sys.stderr)


def rotate_file(path: Path):
    """If file exists, rename with timestamp prefix."""
    if path.is_file():
        ts = datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y%m%d_%H%M%S")
        rotated = path.parent / f"{ts}_{path.name}"
        path.rename(rotated)


def save_file(path: Path, data: str):
    """Write data to path, rotating any existing file."""
    rotate_file(path)
    path.write_text(data)


# ---------------------------------------------------------------------------
# Command file parsing
# ---------------------------------------------------------------------------

class VendorCommands:
    """Parsed .cmds file for a vendor."""

    def __init__(self, vendor: str):
        self.vendor = vendor
        self.version_cmd: str | None = None
        self.running_config_cmd: str | None = None
        self.running_config_all_cmd: str | None = None
        self.startup_config_cmd: str | None = None
        self.compliance_cmds: list[str] = []

    @classmethod
    def load(cls, vendor: str) -> "VendorCommands | None":
        cmd_file = COMMANDS_DIR / f"{vendor}.cmds"
        if not cmd_file.is_file():
            cmd_file = COMMANDS_DIR / "generic.cmds"
        if not cmd_file.is_file():
            return None

        vc = cls(vendor)
        for line in cmd_file.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("@VERSION "):
                vc.version_cmd = line[len("@VERSION "):]
            elif line.startswith("@RUNNING_CONFIG_ALL "):
                vc.running_config_all_cmd = line[len("@RUNNING_CONFIG_ALL "):]
            elif line.startswith("@RUNNING_CONFIG "):
                vc.running_config_cmd = line[len("@RUNNING_CONFIG "):]
            elif line.startswith("@STARTUP_CONFIG "):
                vc.startup_config_cmd = line[len("@STARTUP_CONFIG "):]
            elif not line.startswith("@"):
                vc.compliance_cmds.append(line)
        return vc


# ---------------------------------------------------------------------------
# Vendor detection
# ---------------------------------------------------------------------------

def detect_vendor(version_output: str) -> str:
    """Detect vendor from version output text."""
    for pattern, vendor in VENDOR_PATTERNS:
        if re.search(pattern, version_output, re.IGNORECASE):
            return vendor
    return "generic"


def netmiko_device_type(vendor: str) -> str:
    """Map our vendor name to netmiko device_type string."""
    return NETMIKO_DEVICE_MAP.get(vendor, "autodetect")


# ---------------------------------------------------------------------------
# Connection management
# ---------------------------------------------------------------------------

# Connection result: either a netmiko connection (for normal path)
# or a dict of SSH parameters (for subprocess/expect fallback path).


def connect_device(ip: str, username: str, password: str,
                   device_type: str = "autodetect",
                   enable_pass: str | None = None,
                   timeout: int = 15,
                   legacy_ssh: bool = False) -> "ConnectHandler":
    """Establish netmiko SSH connection to a device.

    If legacy_ssh is True, disable rsa-sha2-* to allow ssh-rsa host keys
    (required for older switches that only support ssh-rsa).
    """
    device = {
        "device_type": device_type,
        "host": ip,
        "username": username,
        "password": password,
        "timeout": timeout,
        "conn_timeout": 10,
        "global_delay_factor": 1,
        "fast_cli": False,
    }

    if enable_pass:
        device["secret"] = enable_pass

    # Allow ssh-rsa host keys (required for old switches where paramiko 2.9+
    # refuses to connect because it prefers rsa-sha2-256/512).
    if legacy_ssh:
        device["disabled_algorithms"] = {
            "pubkeys": ["rsa-sha2-256", "rsa-sha2-512"],
        }

    connection = ConnectHandler(**device)

    if enable_pass and not connection.check_enable_mode():
        connection.enable()

    return connection


def _test_sshpass(ip: str, username: str, password: str,
                  ssh_config: str | None = None) -> bool:
    """Test if sshpass+ssh can connect. Returns True on success."""
    cmd = ["sshpass", "-e", "ssh"]
    if ssh_config:
        cmd += ["-F", ssh_config]
    cmd += [
        "-o", "ConnectTimeout=5",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
        f"{username}@{ip}",
        "exit",
    ]
    env = os.environ.copy()
    env["SSHPASS"] = password
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=15, env=env)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def try_connect(ip: str, username: str, password: str,
                enable_pass: str | None = None) -> tuple:
    """Try connecting with a full fallback cascade.

    Returns one of:
      ("netmiko", connection, device_type)
      ("subprocess", ssh_opts_dict)

    The ssh_opts_dict contains: ip, username, password, enable_pass, ssh_config
    """
    # --- Attempt 1: Normal netmiko ---
    _incompatible_peer = False
    for dt in ["autodetect", "cisco_ios", "cisco_nxos", "hp_comware",
               "aruba_osswitch", "aruba_os"]:
        try:
            conn = connect_device(ip, username, password, dt, enable_pass)
            return "netmiko", conn, conn.device_type
        except (NetmikoTimeoutException, NetmikoAuthenticationException):
            raise
        except IncompatiblePeer:
            _incompatible_peer = True
            break  # negotiation failure → try legacy below
        except Exception:
            continue

    # --- Attempt 2: netmiko with legacy ssh-rsa host key ---
    if _incompatible_peer:
        log_step("Retrying with legacy SSH settings (ssh-rsa host key)...")
    for dt in ["autodetect", "cisco_ios", "cisco_nxos", "hp_comware",
               "aruba_osswitch", "aruba_os"]:
        try:
            conn = connect_device(ip, username, password, dt, enable_pass,
                                  legacy_ssh=True)
            return "netmiko", conn, conn.device_type
        except (NetmikoTimeoutException, NetmikoAuthenticationException):
            raise
        except IncompatiblePeer:
            break  # still failing → try subprocess
        except Exception:
            continue

    # --- Attempt 3: sshpass + ssh with legacy algorithms config ---
    log_step("Netmiko cannot negotiate SSH, trying sshpass with legacy ciphers...")

    # 3a: normal sshpass
    if _test_sshpass(ip, username, password):
        log_success("Connected via sshpass (normal mode)")
        return "subprocess", {
            "ip": ip, "username": username, "password": password,
            "enable_pass": enable_pass, "ssh_config": None,
        }

    # 3b: sshpass with legacy SSH config
    ssh_config_file = None
    try:
        fd, ssh_config_file = tempfile.mkstemp(prefix="netutil_ssh_")
        os.write(fd, LEGACY_SSH_CONFIG.encode())
        os.close(fd)
        os.chmod(ssh_config_file, 0o600)

        if _test_sshpass(ip, username, password, ssh_config_file):
            log_success("Connected via sshpass (legacy SSH mode)")
            return "subprocess", {
                "ip": ip, "username": username, "password": password,
                "enable_pass": enable_pass, "ssh_config": ssh_config_file,
            }
    except Exception:
        pass
    finally:
        # Config file will be cleaned up later; keep it for command execution
        pass

    # 3c: sshpass with legacy config + PTY mode (for Nexus etc.)
    cmd = ["sshpass", "-e", "ssh", "-t"]
    if ssh_config_file:
        cmd += ["-F", ssh_config_file]
    cmd += [
        "-o", "ConnectTimeout=10",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
        f"{username}@{ip}",
    ]
    env = os.environ.copy()
    env["SSHPASS"] = password
    try:
        result = subprocess.run(
            cmd, input="\nexit\n", capture_output=True,
            timeout=15, text=True, env=env,
        )
        if result.returncode == 0:
            log_success("Connected via sshpass (PTY + legacy mode)")
            return "subprocess", {
                "ip": ip, "username": username, "password": password,
                "enable_pass": enable_pass, "ssh_config": ssh_config_file,
                "pty": True,
            }
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Clean up temp file on total failure
    if ssh_config_file:
        try:
            os.unlink(ssh_config_file)
        except OSError:
            pass

    raise ConnectionError(f"Failed to connect to {ip} with any method")


# ---------------------------------------------------------------------------
# Hostname extraction
# ---------------------------------------------------------------------------

def extract_hostname(version_output: str) -> str:
    """Extract hostname from version output."""
    # Cisco IOS: "<hostname> uptime is ..."
    m = re.search(r"^([A-Za-z0-9._-]+) uptime is", version_output, re.MULTILINE)
    if m:
        return m.group(1)
    # "You are connected to <hostname>"
    m = re.search(r"connected to ([A-Za-z0-9._-]+)", version_output, re.IGNORECASE)
    if m:
        return m.group(1)
    # Generic: "hostname: ..." or "device name: ..." or "system name: ..."
    m = re.search(r"^\s*(?:hostname|device\s+name|system\s+name)\s*:\s*(.+)",
                  version_output, re.MULTILINE | re.IGNORECASE)
    if m:
        return m.group(1).strip()
    return "Unknown"


# ---------------------------------------------------------------------------
# Device processing
# ---------------------------------------------------------------------------

def process_device(ip: str, username: str, password: str,
                   enable_pass: str | None = None,
                   dry_run: bool = False) -> bool:
    """Process a single device: connect, detect vendor, collect configs and compliance.

    Returns True on success.
    """
    configs_dir = Path(WORKDIR) / "configs" / ip
    configs_dir.mkdir(parents=True, exist_ok=True)

    log_file = configs_dir / "connection.log"
    metadata_file = configs_dir / "metadata.txt"
    failures_file = Path(WORKDIR) / "configs" / "failures.txt"

    def write_log(msg):
        with open(log_file, "a") as f:
            f.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} | {msg}\n")

    write_log(f"=== Session started for {ip} ===")
    write_log(f"Username: {username}")

    # --- Connect ---
    log_step(f"Connecting to {ip}...")
    conn = None
    ssh_opts = None  # Used when fallback to subprocess path
    try:
        result = try_connect(ip, username, password, enable_pass)
        mode = result[0]
        if mode == "netmiko":
            conn, dt = result[1], result[2]
            write_log("SUCCESS: Connection established (netmiko)")
        else:
            ssh_opts = result[1]
            write_log("SUCCESS: Connection established (subprocess fallback)")
    except NetmikoAuthenticationException:
        log_error(f"Authentication failed for {ip}")
        write_log("FAILURE: Authentication failed")
        _record_failure(failures_file, ip, "authentication_failed")
        return False
    except NetmikoTimeoutException:
        log_error(f"Connection timed out for {ip}")
        write_log("FAILURE: Connection timed out")
        _record_failure(failures_file, ip, "connection_timeout")
        return False
    except Exception as e:
        log_error(f"Failed to connect to {ip}: {e}")
        write_log(f"FAILURE: {e}")
        _record_failure(failures_file, ip, "connection_failed")
        return False

    try:
        # --- Detect vendor ---
        log_step(f"Detecting vendor for {ip}...")

        vendor = "generic"
        version_output = ""

        if conn:
            # Netmiko path: get version via send_command
            dt = conn.device_type if hasattr(conn, 'device_type') else ""
            vendor = _netmiko_type_to_vendor(dt, conn)
            try:
                version_output = conn.send_command("show version", read_timeout=30)
            except Exception:
                pass
            if not version_output or "Invalid input" in version_output:
                for alt_cmd in ["display version", "show system", "show system information"]:
                    try:
                        version_output = conn.send_command(alt_cmd, read_timeout=30)
                        if version_output and "Invalid input" not in version_output:
                            break
                    except Exception:
                        continue
        else:
            # Subprocess path: get version via sshpass
            for vcmd in ["show version", "display version", "show system", "show system information"]:
                raw = _exec_ssh_subprocess(ssh_opts, vcmd, vendor="generic", timeout=30)
                if raw and "Invalid input" not in raw:
                    version_output = raw
                    break

            # Map version output to vendor using pattern matching
            for pattern, v in VENDOR_PATTERNS:
                if re.search(pattern, version_output, re.IGNORECASE):
                    vendor = v
                    break

        if version_output:
            save_file(configs_dir / "version.txt", version_output)
            write_log("SUCCESS: Version retrieved")

            # Refine vendor detection from version output (netmiko path only;
            # subprocess path already detected via VENDOR_PATTERNS above)
            if conn:
                detected = detect_vendor(version_output)
                if detected != "generic":
                    vendor = detected
        else:
            log_warning(f"Could not retrieve version info from {ip}")
            write_log("WARNING: Version retrieval failed")

        log_success(f"Detected vendor: {vendor} for {ip}")
        write_log(f"Vendor: {vendor}")

        # --- Write metadata ---
        hostname = extract_hostname(version_output) if version_output else "Unknown"
        metadata = (
            f"IP Address: {ip}\n"
            f"Vendor/OS: {vendor}\n"
            f"Hostname: {hostname}\n"
            f"Timestamp: {datetime.now():%Y-%m-%d %H:%M:%S}\n"
            f"Username: {username}\n"
            f"Collector: {'netmiko' if conn else 'sshpass'}\n"
        )
        metadata_file.write_text(metadata)

        if dry_run:
            log_success(f"Dry-run complete for {ip}")
            write_log("DRY-RUN: Completed successfully")
            return True

        # --- Load commands ---
        vc = VendorCommands.load(vendor)
        if vc is None:
            log_warning(f"No commands found for vendor: {vendor}")
            write_log(f"FAILURE: No commands for vendor {vendor}")
            return False

        # --- Set terminal paging (best-effort, failures are non-fatal) ---
        term_cmd = TERMINAL_SETUP.get(vendor)
        if term_cmd and conn:
            try:
                conn.send_command(term_cmd, read_timeout=10)
                write_log(f"Terminal setup: {term_cmd}")
            except Exception:
                write_log(f"Terminal setup failed (non-fatal): {term_cmd}")

        # --- Pass 1: Per-file config commands ---
        _collect_config(conn, ssh_opts, vc.running_config_cmd, configs_dir / "running_config.txt",
                        ip, "running_config.txt", log_file, term_cmd, enable_pass, vendor,
                        username, password)
        _collect_config(conn, ssh_opts, vc.running_config_all_cmd, configs_dir / "running_config_all.txt",
                        ip, "running_config_all.txt", log_file, term_cmd, enable_pass, vendor,
                        username, password)
        _collect_config(conn, ssh_opts, vc.startup_config_cmd, configs_dir / "startup_config.txt",
                        ip, "startup_config.txt", log_file, term_cmd, enable_pass, vendor,
                        username, password)

        # --- Pass 2: Compliance commands (one per send_command) ---
        if vc.compliance_cmds:
            compliance_file = configs_dir / "compliance_commands.txt"
            rotate_file(compliance_file)
            with open(compliance_file, "w") as f:
                f.write(f"=== Compliance Commands Output for {ip} ===\n")
                f.write(f"Timestamp: {datetime.now():%Y-%m-%d %H:%M:%S}\n\n")

            log_step(f"Executing {len(vc.compliance_cmds)} compliance commands on {ip}...")
            for cmd in vc.compliance_cmds:
                try:
                    if conn:
                        output = conn.send_command(cmd, read_timeout=60)
                    else:
                        output = _exec_ssh_subprocess(
                            ssh_opts, cmd, terminal_cmd=term_cmd,
                            enable_pass=enable_pass, vendor=vendor, timeout=60)
                    if output:
                        with open(compliance_file, "a") as f:
                            f.write(f"\n=== {cmd} ===\n{output}\n")
                        write_log(f"SUCCESS: {cmd}")
                    else:
                        log_warning(f"Empty output: {cmd}")
                        write_log(f"EMPTY: {cmd}")
                except Exception as e:
                    log_warning(f"Failed: {cmd} ({e})")
                    write_log(f"FAILED: {cmd} — {e}")

            log_success(f"Saved: compliance_commands.txt")

        log_success(f"Completed extraction for {ip}")
        write_log("SUCCESS: Extraction complete")
        return True

    except Exception as e:
        log_error(f"Unexpected error processing {ip}: {e}")
        write_log(f"FAILURE: Unexpected error — {e}")
        _record_failure(failures_file, ip, "processing_error")
        return False

    finally:
        if conn:
            try:
                conn.disconnect()
            except Exception:
                pass
        # Clean up temp SSH config file if subprocess path was used
        if ssh_opts and ssh_opts.get("ssh_config"):
            try:
                os.unlink(ssh_opts["ssh_config"])
            except OSError:
                pass


def _collect_config(conn, ssh_opts, cmd: str | None, dest: Path,
                    ip: str, label: str, log_file: Path,
                    terminal_cmd: str | None = None,
                    enable_pass: str | None = None,
                    vendor: str | None = None,
                    username: str = "", password: str = ""):
    """Collect a single config file via netmiko or subprocess fallback.

    Detects pagination in output and retries with fallback terminal commands
    or pexpect if needed.
    """
    if not cmd:
        return

    def write_log(msg):
        with open(log_file, "a") as f:
            f.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} | {msg}\n")

    log_step(f"Executing: {cmd} on {ip}")
    try:
        if conn:
            output = conn.send_command(cmd, read_timeout=120)

            # Check for pagination in netmiko output
            if output and any(marker in output for marker in PAGINATION_MARKERS):
                log_warning(f"Pagination detected in {label}, attempting fallback...")
                write_log(f"WARNING: Pagination detected for {cmd}")

                # Try fallback terminal command
                fallback = TERMINAL_FALLBACK.get(vendor, "") if vendor else ""
                if fallback and fallback != terminal_cmd:
                    log_step(f"Retrying with fallback: {fallback}")
                    try:
                        conn.send_command(fallback, read_timeout=10)
                    except Exception:
                        pass
                    output = conn.send_command(cmd, read_timeout=120)

                # If still paginated, try pexpect
                if output and any(marker in output for marker in PAGINATION_MARKERS):
                    if HAS_PEXPECT:
                        # Build ssh_opts from connection info for pexpect fallback
                        _opts = {
                            "ip": ip,
                            "username": username,
                            "password": password,
                            "ssh_config": None,
                        }
                        pexpect_output = _exec_ssh_pexpect(
                            _opts, cmd, terminal_cmd, enable_pass, timeout=120)
                        if pexpect_output:
                            output = pexpect_output

                    if any(marker in (output or "") for marker in PAGINATION_MARKERS):
                        log_warning(f"Output may be truncated: {label}")
                        write_log(f"WARNING: Output may be truncated for {cmd}")
                        output = "!!! WARNING: OUTPUT MAY BE TRUNCATED !!!\n" + (output or "")
        else:
            output = _exec_ssh_subprocess(
                ssh_opts, cmd, terminal_cmd=terminal_cmd,
                enable_pass=enable_pass, vendor=vendor, timeout=120)

        if output:
            save_file(dest, output)
            log_success(f"Saved: {label}")
            write_log(f"SUCCESS: {cmd}")
        else:
            log_warning(f"Failed or empty output: {cmd}")
            write_log(f"FAILED: {cmd}")
    except Exception as e:
        log_warning(f"Error running {cmd}: {e}")
        write_log(f"FAILED: {cmd} — {e}")


def _netmiko_type_to_vendor(dt: str, conn) -> str:
    """Map netmiko device_type to our vendor name."""
    mapping = {
        "cisco_ios": "cisco_ios",
        "cisco_xe": "cisco_ios",
        "cisco_xr": "cisco_ios",
        "cisco_nxos": "cisco_nexus",
        "hp_comware": "hp_comware",
        "hp_procurve": "hp_provision",
        "aruba_osswitch": "aruba_switch",
        "aruba_os": "aruba_cx",
    }
    return mapping.get(dt, "generic")


def _record_failure(failures_file: Path, ip: str, reason: str):
    """Append failure record to failures file."""
    failures_file.parent.mkdir(parents=True, exist_ok=True)
    with open(failures_file, "a") as f:
        f.write(f"{datetime.now():%Y-%m-%d %H:%M:%S},{ip},{reason}\n")

# ---------------------------------------------------------------------------
# Subprocess / expect command execution (fallback for legacy SSH devices)
# ---------------------------------------------------------------------------

def _clean_output(raw: str) -> str:
    """Remove ANSI codes, pagination artifacts, and command echoes from SSH output."""
    # Remove ANSI escape sequences
    cleaned = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', raw)
    # Remove --More-- lines
    cleaned = re.sub(r'^\s*--More--\s*$', '', cleaned, flags=re.MULTILINE)
    cleaned = re.sub(r'^\s*---- More ----\s*$', '', cleaned, flags=re.MULTILINE)
    cleaned = re.sub(r'^\s*Press any key.*$', '', cleaned, flags=re.MULTILINE)
    # Remove carriage returns
    cleaned = cleaned.replace('\r\n', '\n').replace('\r', '')
    # Remove leading/trailing blank lines
    lines = [l for l in cleaned.splitlines() if l.strip()]
    return '\n'.join(lines) + '\n' if lines else ''


def _exec_ssh_subprocess(ssh_opts: dict, command: str,
                         terminal_cmd: str | None = None,
                         enable_pass: str | None = None,
                         vendor: str | None = None,
                         timeout: int = 120) -> str:
    """Execute command via sshpass+ssh subprocess with PTY.

    Handles pagination by detecting --More-- and retrying with fallback
    terminal commands or pexpect if available.
    """
    ip = ssh_opts["ip"]
    username = ssh_opts["username"]
    password = ssh_opts["password"]
    ssh_config = ssh_opts.get("ssh_config")

    # Build stdin input: newlines to dismiss banners, optional enable + terminal setup
    stdin_parts = ["\n\n"]
    if enable_pass:
        stdin_parts.append(f"enable\n{enable_pass}\n")
    if terminal_cmd:
        stdin_parts.append(f"{terminal_cmd}\n")
    stdin_parts.append(f"{command}\nexit\n")
    stdin_input = "".join(stdin_parts)

    env = os.environ.copy()
    env["SSHPASS"] = password
    cmd = ["sshpass", "-e", "ssh", "-tt"]
    if ssh_config:
        cmd += ["-F", ssh_config]
    cmd += [
        "-o", "ConnectTimeout=10",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
        f"{username}@{ip}",
    ]

    raw = _run_ssh_command(cmd, stdin_input, timeout, env=env)
    output = _clean_output(raw)

    # Check for pagination in output
    if any(marker in raw for marker in PAGINATION_MARKERS):
        log_warning("Pagination detected in output, attempting fallback...")

        # Try fallback terminal command
        fallback_term = TERMINAL_FALLBACK.get(vendor, "") if vendor else ""
        if fallback_term and fallback_term != terminal_cmd:
            log_step(f"Retrying with fallback terminal command: {fallback_term}")
            stdin_parts_fb = ["\n\n"]
            if enable_pass:
                stdin_parts_fb.append(f"enable\n{enable_pass}\n")
            stdin_parts_fb.append(f"{fallback_term}\n")
            stdin_parts_fb.append(f"{command}\nexit\n")
            raw = _run_ssh_command(cmd, "".join(stdin_parts_fb), timeout, env=env)
            output = _clean_output(raw)

        # If still paginated, try pexpect
        if any(marker in raw for marker in PAGINATION_MARKERS):
            if HAS_PEXPECT:
                log_step("Using pexpect for paginated output collection")
                output = _exec_ssh_pexpect(ssh_opts, command, terminal_cmd, enable_pass, timeout)
                if output:
                    return output
            log_warning("Output may be truncated (pagination could not be fully disabled)")
            output = "!!! WARNING: OUTPUT MAY BE TRUNCATED !!!\n" + output

    return output


def _run_ssh_command(cmd: list[str], stdin_input: str, timeout: int,
                     env: dict | None = None) -> str:
    """Run an SSH command via subprocess and return raw stdout."""
    result = subprocess.run(
        cmd, input=stdin_input, capture_output=True,
        timeout=timeout + 5, text=True, env=env,
    )
    return result.stdout or ""


def _exec_ssh_pexpect(ssh_opts: dict, command: str,
                      terminal_cmd: str | None = None,
                      enable_pass: str | None = None,
                      timeout: int = 120) -> str:
    """Execute command via pexpect for reliable pagination handling.

    Mirrors exec_ssh_with_expect() from the shell script.
    """
    ip = ssh_opts["ip"]
    username = ssh_opts["username"]
    password = ssh_opts["password"]
    ssh_config = ssh_opts.get("ssh_config")

    ssh_cmd = ("sshpass -e ssh -tt -o ConnectTimeout=10 "
               "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
               "-o LogLevel=ERROR")
    if ssh_config:
        ssh_cmd += f" -F {ssh_config}"
    ssh_cmd += f" {username}@{ip}"

    env = os.environ.copy()
    env["SSHPASS"] = password

    try:
        child = pexpect.spawn(ssh_cmd, timeout=timeout, encoding="utf-8",
                              env=env)

        # Wait for prompt (login banner, initial prompt)
        prompts = [r"[#>]\s*$", "Press any key to continue", pexpect.TIMEOUT]
        idx = child.expect(prompts)
        if idx == 1:
            child.sendline("")
            child.expect([r"[#>]\s*$", pexpect.TIMEOUT])
        elif idx == 2:
            child.close()
            return ""

        # Enter enable mode if needed
        if enable_pass:
            child.sendline("enable")
            child.expect("Password:")
            child.sendline(enable_pass)
            child.expect([r"[#>]\s*$", pexpect.TIMEOUT])

        # Send terminal setup
        if terminal_cmd:
            child.sendline(terminal_cmd)
            child.expect([r"[#>]\s*$", pexpect.TIMEOUT])

        # Send command and collect paginated output
        child.sendline(command)
        output_parts = []
        while True:
            idx = child.expect([
                r"--More--",
                r"---- More ----",
                r"Press any key",
                r"\n\S+[#>] ?$",
                pexpect.TIMEOUT,
            ])
            output_parts.append(child.before or "")
            if idx in (0, 1, 2):
                # Pagination prompt — send space to continue
                child.send(" ")
            elif idx in (3, 4):
                # Got prompt or timeout — done
                break

        child.sendline("exit")
        child.close()
        raw = "".join(output_parts)
        return _clean_output(raw)
    except Exception as e:
        log_warning(f"pexpect failed: {e}")
        return ""


# ---------------------------------------------------------------------------
# Target resolution
# ---------------------------------------------------------------------------

def resolve_targets(args) -> list[str]:
    """Resolve target IPs from args or interactive selection."""
    if args.targets:
        target_str = args.targets
        # Check if it's a file reference
        if target_str.startswith("-iL "):
            host_file = Path(target_str[4:].strip())
            if host_file.is_file():
                return _read_host_file(host_file)
        # Direct IPs (comma or space separated)
        return [ip.strip() for ip in re.split(r"[,\s]+", target_str) if ip.strip()]

    # Interactive: present 4-option target selection menu
    # (mirrors select_config_targets in scripts/common/utils.sh)
    print(file=sys.stderr)
    log("Target selection for config gathering:")
    print("1. Single IP address", file=sys.stderr)
    print("2. Custom host file (manual path)", file=sys.stderr)
    print("3. Discovered network devices", file=sys.stderr)
    print("4. Recent targets", file=sys.stderr)
    print(file=sys.stderr)

    while True:
        print(file=sys.stderr)
        try:
            choice = prompt("Select target type (1-4): ").strip()
        except (EOFError, KeyboardInterrupt):
            return []

        if choice == "1":
            print(file=sys.stderr)
            try:
                ip_input = prompt("Enter IP address: ").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip_input):
                return [ip_input]
            log_error(f"Invalid IP address: {ip_input}")

        elif choice == "2":
            print(file=sys.stderr)
            try:
                filepath = prompt("Enter path to host file: ").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            p = Path(filepath)
            if p.is_file():
                return _read_host_file(p)
            log_error(f"File not found: {filepath}")

        elif choice == "3":
            host_files = _find_discovery_hostfiles("network_devices")
            if not host_files:
                continue
            selected = _select_host_file(host_files)
            if selected:
                return _read_host_file(selected)

        elif choice == "4":
            recent = _get_recent_targets()
            if not recent:
                log_error("No recent targets found")
                continue
            print("Recent targets:", file=sys.stderr)
            for i, t in enumerate(recent, 1):
                print(f"  {i}. {t}", file=sys.stderr)
            print(file=sys.stderr)
            try:
                sel = prompt(f"Select target (1-{len(recent)}): ").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            if sel.isdigit():
                idx = int(sel) - 1
                if 0 <= idx < len(recent):
                    target = recent[idx]
                    # Could be a file path or an IP
                    p = Path(target)
                    if p.is_file():
                        return _read_host_file(p)
                    return [target]
            log_error("Invalid selection")

        else:
            log_error("Invalid option. Please select 1-4")


def _read_host_file(path: Path) -> list[str]:
    """Read IPs from a host file, handling various formats."""
    ips = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Handle nmap-style output lines (fields separated by spaces)
        parts = line.split()
        for p in parts:
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", p):
                ips.append(p)
                break
        else:
            # Plain IP-per-line
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", line):
                ips.append(line)
    return ips


def _find_discovery_hostfiles(filter_category: str | None = None) -> list[tuple[Path, str]]:
    """Find categorized host files in discovery sessions.

    Mirrors select_host_file() from scripts/common/utils.sh.
    Returns list of (path, display_name) tuples.
    """
    base_dir = Path(WORKDIR) / "discovery"
    if not base_dir.is_dir():
        log_error(f"Discovery directory {base_dir} not found")
        return []

    results: list[tuple[Path, str]] = []

    # Find session directories sorted newest-first
    session_dirs = sorted(
        [d for d in base_dir.iterdir() if d.is_dir() and d.name != "raw"],
        key=lambda d: d.name,
        reverse=True,
    )

    for session_dir in session_dirs:
        session_name = session_dir.name
        hostfiles_dir = session_dir / "hostfiles"

        if hostfiles_dir.is_dir():
            # Standalone session: hostfiles directly in session dir
            _scan_hostfiles_dir(hostfiles_dir, f"{session_name}", filter_category, results)
        else:
            # Auto-discover session: look for subdirectories with hostfiles
            for network_dir in sorted(session_dir.iterdir()):
                if not network_dir.is_dir():
                    continue
                name = network_dir.name
                if name in ("main_network",) or name.startswith("vlan_") or name[0:1].isdigit():
                    sub_hostfiles = network_dir / "hostfiles"
                    if sub_hostfiles.is_dir():
                        _scan_hostfiles_dir(sub_hostfiles, f"{session_name}/{name}",
                                           filter_category, results)

    if not results:
        log_error("No categorized host files found in discovery sessions")
    return results


def _scan_hostfiles_dir(hf_dir: Path, prefix: str, filter_category: str | None,
                        results: list[tuple[Path, str]]):
    """Scan a hostfiles directory for matching files."""
    if filter_category:
        # Match both <filter>_hosts.txt and <filter>.txt naming conventions
        patterns = [f"{filter_category}_hosts.txt", f"{filter_category}.txt"]
        for pat in patterns:
            f = hf_dir / pat
            if f.is_file():
                category = f.stem
                results.append((f, f"{prefix}/{category}"))

        # For network_devices, also look for vendor-specific files
        if filter_category == "network_devices":
            skip = {"network_devices_hosts.txt", "network_devices.txt",
                    "all_discovered_hosts.txt", "unknown.txt"}
            for f in sorted(hf_dir.iterdir()):
                if not f.is_file() or f.name in skip:
                    continue
                if f.suffix == ".txt" and not f.name.endswith("_enriched.txt") and \
                   not f.name.endswith("_hosts.txt"):
                    results.append((f, f"{prefix}/{f.stem}"))
    else:
        # Find all categorized host files (exclude enriched and debug)
        for f in sorted(hf_dir.iterdir()):
            if f.is_file() and f.suffix == ".txt" and not f.name.endswith("_enriched.txt"):
                results.append((f, f"{prefix}/{f.stem}"))


def _select_host_file(files: list[tuple[Path, str]]) -> Path | None:
    """Display host file list and let user pick one. Returns the file path or None."""
    print("Available categorized host files:", file=sys.stderr)
    for i, (_, display) in enumerate(files, 1):
        print(f"  {i}. {display}", file=sys.stderr)
    print(file=sys.stderr)

    while True:
        print(file=sys.stderr)
        try:
            sel = prompt(f"Select host file (1-{len(files)}): ").strip()
        except (EOFError, KeyboardInterrupt):
            return None
        if not sel.isdigit():
            log_error("Please enter a number")
            continue
        idx = int(sel) - 1
        if 0 <= idx < len(files):
            return files[idx][0]
        log_error(f"Please enter a number between 1 and {len(files)}")


def _get_recent_targets() -> list[str]:
    """Read recent targets from target memory file."""
    config_file = Path.home() / ".netutil" / "target_memory"
    if not config_file.is_file():
        return []
    lines = []
    for line in config_file.read_text().splitlines():
        line = line.strip()
        if line:
            lines.append(line)
    return lines[:10]


# ---------------------------------------------------------------------------
# Credential resolution
# ---------------------------------------------------------------------------

def resolve_credentials(args) -> tuple[str, str, str | None]:
    """Get credentials based on mode."""
    if args.cred_mode == "file":
        return _creds_from_file(args.cred_file)
    if args.cred_mode == "session":
        # Session credentials would come from the Go TUI app environment
        user = os.environ.get("NETUTIL_USERNAME", "")
        passwd = os.environ.get("NETUTIL_PASSWORD", "")
        enable = os.environ.get("NETUTIL_ENABLE", "")
        if user and passwd:
            return user, passwd, enable or None

    # Default: prompt
    print(file=sys.stderr)
    print("Enter common credentials for all devices:", file=sys.stderr)
    try:
        username = prompt("Username: ").strip()
        password = prompt("Password: ")
        enable_pass = None
        need_enable = prompt("Enable (privileged) mode required? (y/n): ").strip().lower()
        if need_enable == "y":
            enable_pass = prompt("Enable password: ")
    except (EOFError, KeyboardInterrupt):
        print(file=sys.stderr)
        sys.exit(1)

    return username, password, enable_pass or None


def _creds_from_file(filepath: str | None) -> tuple[str, str, str | None]:
    """Read credentials from CSV file (IP,user,pass[,enable])."""
    if not filepath:
        log_error("--cred-file required when using --cred-mode file")
        sys.exit(1)

    path = Path(filepath)
    if not path.is_file():
        log_error(f"Credentials file not found: {filepath}")
        sys.exit(1)

    # Read first non-comment, non-empty line
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",", 3)
            if len(parts) >= 3:
                enable = parts[3].strip() if len(parts) > 3 else None
                return parts[1].strip(), parts[2].strip(), enable or None

    log_error("No valid credential entries found in file")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Retry logic
# ---------------------------------------------------------------------------

def offer_retry(failed_ips: list[str], username: str, password: str,
                enable_pass: str | None, concurrency: int) -> tuple[int, int]:
    """Offer retry for failed devices with different credentials."""
    if not failed_ips:
        return 0, 0

    print(file=sys.stderr)
    log_warning(f"{len(failed_ips)} device(s) failed during extraction")
    print(file=sys.stderr)
    try:
        response = prompt("Retry failed devices with different credentials? (y/n): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return 0, 0

    if response != "y":
        return 0, 0

    print(file=sys.stderr)
    try:
        new_user = prompt("Username: ").strip()
        new_pass = prompt("Password: ")
        new_enable = None
        need_enable = prompt("Enable (privileged) mode required? (y/n): ").strip().lower()
        if need_enable == "y":
            new_enable = prompt("Enable password: ")
    except (EOFError, KeyboardInterrupt):
        return 0, 0

    success, failure = process_devices(
        failed_ips, new_user, new_pass, new_enable or None,
        concurrency=concurrency, dry_run=False
    )
    return success, failure


# ---------------------------------------------------------------------------
# Concurrent processing
# ---------------------------------------------------------------------------

def process_devices(ips: list[str], username: str, password: str,
                    enable_pass: str | None, concurrency: int = 5,
                    dry_run: bool = False) -> tuple[int, int]:
    """Process devices concurrently. Returns (success_count, failure_count)."""
    total = len(ips)
    success = 0
    failure = 0

    log(f"Processing {total} device(s){' (dry-run)' if dry_run else ''}, "
        f"concurrency: {concurrency}")

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = {}
        for ip in ips:
            future = executor.submit(
                process_device, ip, username, password, enable_pass, dry_run
            )
            futures[future] = ip

        for future in as_completed(futures):
            ip = futures[future]
            try:
                if future.result():
                    success += 1
                else:
                    failure += 1
            except Exception as e:
                log_error(f"Unexpected error for {ip}: {e}")
                failure += 1

    return success, failure


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SSH into network devices, auto-detect vendor, "
                    "extract running configs and compliance data."
    )
    parser.add_argument(
        "--targets", "-t",
        help="Device IPs (comma/space separated) or host file path"
    )
    parser.add_argument(
        "--concurrency", "-c",
        type=int, default=5,
        help="Maximum parallel connections (default: 5)"
    )
    parser.add_argument(
        "--cred-mode",
        choices=["prompt", "session", "file"],
        default="prompt",
        help="Credential input method (default: prompt)"
    )
    parser.add_argument(
        "--cred-file",
        help="Path to credentials file (CSV: IP,user,pass[,enable])"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Test connectivity only, no extraction"
    )
    parser.add_argument(
        "--version", "-V",
        action="version",
        version=f"%(prog)s {VERSION}"
    )
    return parser.parse_args()


def main():
    args = parse_args()
    print_header()

    # Resolve targets
    ips = resolve_targets(args)
    if not ips:
        log_error("No targets selected")
        sys.exit(1)

    log_success(f"Targets selected ({len(ips)} device(s))")

    # Resolve credentials
    username, password, enable_pass = resolve_credentials(args)

    # Process
    total = len(ips)
    success, failure = process_devices(
        ips, username, password, enable_pass,
        concurrency=args.concurrency,
        dry_run=args.dry_run,
    )

    # Summary
    print(file=sys.stderr)
    print_header()
    log_success("Processing Complete!")
    print(file=sys.stderr)
    print(f"Total Devices:    {total}", file=sys.stderr)
    print(f"Successful:       {success}", file=sys.stderr)
    print(f"Failed:           {failure}", file=sys.stderr)
    print(file=sys.stderr)
    log(f"Results saved to: {WORKDIR}/configs/")

    if failure > 0:
        log_warning(f"  Failed: {failure} (see configs/failures.txt)")

        # Offer retry
        failures_file = Path(WORKDIR) / "configs" / "failures.txt"
        failed_ips = []
        if failures_file.is_file():
            for line in failures_file.read_text().splitlines():
                parts = line.split(",")
                if len(parts) >= 2:
                    failed_ips.append(parts[1])

        retry_success, retry_failure = offer_retry(
            failed_ips, username, password, enable_pass, args.concurrency
        )
        success += retry_success
        failure -= retry_success

    print(file=sys.stderr)
    log_success("Session complete.")


if __name__ == "__main__":
    main()
