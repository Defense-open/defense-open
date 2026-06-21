# Privacy Policy

**Last updated:** 2026-06-22

Defense operates on a zero-telemetry principle. This document explains exactly what is and is not collected.

---

## What Is Collected

While running, Defense produces and stores the following data **locally on your device only**:

### Alert Output (alerts.jsonl or stdout)

| Data | Example |
|------|---------|
| Process name and full path | `C:\Windows\System32\cmd.exe` |
| Command-line arguments | `cmd.exe /c powershell -enc ...` |
| PID and parent process info | `pid: 1234, parent: WINWORD.EXE` |
| File path | `C:\Users\[USER]\AppData\Temp\evil.exe` |
| Network connection (destination IP and port) | `185.220.101.47:443` |
| Registry key path | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` |
| USB device class | `MassStorage` |
| Timestamp | `2026-06-22T14:30:00Z` |
| Threat score and rule ID | `score: 85, rule: PROC-001` |

---

## What Is Never Collected

Defense **never** collects or processes:

- File contents (files are never read or analyzed)
- Network payload (no packet data, HTTP content, or encrypted traffic)
- Passwords or credentials
- Usernames (may appear in file paths only)
- Browser history or cookies
- Keystrokes (this is not a keylogger)
- Screenshots
- Geographic location
- Hardware identifiers (MAC address, serial numbers, etc.)
- License or usage statistics

---

## Where Data Is Stored

All data stays **on your local device only**:

- Alert output: the file you specify via `--alert-file`, or terminal stdout
- Nothing is automatically sent anywhere
- No cloud connections are made
- There is no "phone home" mechanism

You can verify this by monitoring network traffic or auditing the source code.

---

## Data Sharing

Defense **never** shares your data with third parties.

**Optional community sharing:** If you choose to share detected threats with the community, this is entirely your decision and is always manual. We recommend removing sensitive information (username, internal IPs, etc.) before sharing.

---

## Deleting Your Data

To remove all data produced by Defense:

```bash
# Delete the alert file (whichever file you specified)
rm alerts.jsonl

# If you used stdout, no local file was written
```

Uninstalling Defense leaves no backdoors, services, or persistent data behind.

---

## Open Source Guarantee

Defense is fully open source. Every claim in this privacy policy can be verified from the source code:

- No outbound network calls: `grep -r "reqwest\|ureq\|hyper" defense-core/src/` — no HTTP client dependency exists
- File contents are never read: the filesystem collector only listens to inotify/FSEvents/RDCW events; it never opens or reads file contents

For any concerns, please use the contact channels in [SECURITY.md](SECURITY.md).

---

## Contact

For privacy-related questions, use GitHub Discussions or the contact channels in [SECURITY.md](SECURITY.md).
