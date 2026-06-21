# Defense

**Open-source, behavior-based endpoint security agent.**

No signature database. No telemetry. Your data stays on your machine.

Defense monitors process behavior, filesystem changes, network connections, registry modifications, and USB devices in real time. Rules are written in TOML — you can write your own without touching any code.

---

## Supported Platforms

- Windows 10/11
- Linux (Ubuntu 22.04+, Arch, Debian-based)
- macOS 12+

---

## Installation

### Download a pre-built binary

Go to [Releases](https://github.com/Defense-open/defense-open/releases) and download the binary for your platform:

| Platform | File |
|----------|------|
| Linux | `defense-agent-linux-x86_64` |
| macOS | `defense-agent-macos-x86_64` |
| Windows | `defense-agent-windows-x86_64.exe` |

### Build from source

```bash
git clone https://github.com/Defense-open/defense-open.git
cd defense-open
cargo build --release
```

Output: `target/release/defense-agent`

**Requirements:** Rust 1.78+ — install via [rustup.rs](https://rustup.rs)

---

## Usage

```bash
# Start with all collectors (default)
defense-agent --rules-dir ./rules

# Write alerts to a file
defense-agent --rules-dir ./rules --alert-file alerts.jsonl

# Run specific collectors only
defense-agent --rules-dir ./rules --collectors process,fs,network

# Filter high-severity alerts (requires jq)
defense-agent --rules-dir ./rules | jq 'select(.score >= 70)'

# Help
defense-agent --help
```

### Collectors

| Name | What it monitors |
|------|-----------------|
| `process` | Process creation, command-line arguments |
| `fs` | File create, modify, delete events |
| `network` | Network interface stats, TCP connections (Linux) |
| `registry` | Windows registry Run/Winlogon/Services keys |
| `usb` | USB / removable disk connections |

---

## Alert Format

One JSON line per matching rule:

```json
{
  "timestamp": "2026-06-22T14:30:00Z",
  "event_id": 42,
  "rule_id": "PROC-001",
  "rule_name": "PowerShell Encoded Command",
  "score": 85,
  "category": "execution",
  "mitre": "T1059.001",
  "recommended_action": "investigate",
  "event": {
    "kind": "process",
    "pid": 1234,
    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "command_line": "powershell.exe -EncodedCommand SQBFAFgA"
  }
}
```

**Score:** 0–100 threat score. 70+ warrants attention, 90+ is critical.  
**MITRE:** The ATT&CK technique the alert maps to.

---

## Writing Rules

Rules live in the `rules/` directory as `.toml` files. You can add your own:

```toml
[[rules]]
id = "CUSTOM-001"
name = "Suspicious Python Script"
score = 60
category = "execution"
mitre = "T1059.006"
recommended_action = "investigate"
match_mode = "all"   # "all" = AND, "any" = OR

[[rules.conditions]]
field = "process.image"
op = "ends_with"
value = "python.exe"

[[rules.conditions]]
field = "process.command_line"
op = "contains"
value = "base64"
```

### Available Fields

| Prefix | Fields |
|--------|--------|
| `process.` | `image`, `command_line`, `pid`, `parent_image` |
| `fs.` | `path`, `event_type` |
| `network.` | `dst_ip`, `dst_port`, `protocol`, `bytes_sent` |
| `registry.` | `key`, `value_name`, `operation` |
| `usb.` | `device_id`, `device_class` |

### Operators

`contains`, `not_contains`, `equals`, `not_equals`, `starts_with`, `ends_with`, `gt`, `lt`, `eq`

All string comparisons are case-insensitive.

---

## Included Rules

50 rules across 5 categories, all MITRE ATT&CK tagged:

- **Process (15):** PowerShell encoded command, Mimikatz, shadow copy deletion, PsExec, WMI process creation...
- **FileSystem (15):** Ransomware extensions, LSASS dump, startup folder writes, temp directory...
- **Network (10):** C2 ports (4444/1337/31337), Tor (9050/9051), high data transfer...
- **Registry (7):** Run key persistence, Windows Defender disabled, UAC bypass...
- **USB (3):** Mass storage device, unknown class, Rubber Ducky pattern...

---

## Privacy

Defense **never sends any data off your machine.** All analysis happens locally.

Alert output **contains**: process names, PIDs, file paths, external IP addresses, timestamps.  
Alert output **never contains**: file contents, network payload, passwords, usernames, browser history, keystrokes.

See [PRIVACY.md](PRIVACY.md) for details.

---

## Sharing Logs (Optional)

Sharing threats you find helps us improve the rule set. Before sharing, please:
- Anonymize paths containing your username (e.g. `C:\Users\[USER]\...`)
- Remove internal IP addresses
- Strip any command-line arguments you'd rather keep private

Share via:
- **GitHub Discussions:** https://github.com/Defense-open/defense-open/discussions
- **Discord:** `#threats-found` channel

---

## Contributing

### Rule Contributions

Found a new threat pattern? Open a rule PR:

1. Edit the appropriate `.toml` file in `rules/`
2. Include a sample event that triggers the rule
3. Title the PR as `[Rule] RULE-ID: Rule name`

**Every accepted rule PR = 3 months of Pro license** (in upcoming releases).

### Code Contributions

```bash
git clone https://github.com/Defense-open/defense-open.git
cd defense-open
cargo test --all
cargo clippy --all-targets -- -D warnings
```

Make sure all tests and clippy checks pass before opening a PR.

For security vulnerabilities, see [SECURITY.md](SECURITY.md).

---

## CI Status

[![CI](https://github.com/Defense-open/defense-open/actions/workflows/ci.yml/badge.svg)](https://github.com/Defense-open/defense-open/actions/workflows/ci.yml)

Build & test on Ubuntu, macOS, and Windows + cargo-audit + cargo-deny on every push.

---

## License

MIT — see [LICENSE](LICENSE).

Rule files (`rules/`) are licensed under Apache 2.0.
