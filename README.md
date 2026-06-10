# PanicScan 🛡️

**The Next-Generation Local-First Security Shield.**

PanicScan is a high-performance, privacy-focused security engine designed to detect, intercept, and analyze malicious activity without ever sending your private data to the cloud. It is built to be the definitive shield for your system—rapidly identifying USB trojans, miners, stealers, browser hijackers, and stealthy persistence mechanisms.

Unlike traditional cloud-dependent security tools, PanicScan believes in **Zero Telemetry** and **Local Execution**. Your system, your rules, your data.

## 🚀 Core Philosophy

- **Privacy First (Zero Telemetry):** We do not upload your files, hashes, or logs to a central server. Everything runs and stays on your machine.
- **Lightning Fast Triage:** Scans memory, startups, and critical system registries in milliseconds.
- **Deep System Interrogation:** Hunts for suspicious scripts, unauthorized LaunchAgents, hidden systemd services, and risky shortcuts.
- **Opt-In Action:** PanicScan will never blindly delete your files. Quarantine and removal are always manual, reversible, and explicit.

## 📥 Installation (For End Users)

1. Go to the [Releases](https://github.com/PanicScan/panic-scan-open/releases) page.
2. Download the latest `.zip` or executable for your operating system (Windows, macOS, or Linux).
3. Extract the downloaded file.

*Note: PanicScan is currently provided as a Command-Line Interface (CLI) tool. Our Graphical User Interface (GUI) and fully automated background Daemon are in active development.*

## ⚡ Usage (CLI)

```bash
# Run a blazing-fast memory and critical paths scan
panicscan quick --html report.html

# Run a full system scan with a specific time budget (e.g., 15 minutes)
panicscan full --max-minutes 15 --html full-report.html

# Safely scan a newly inserted USB or removable media
panicscan usb <drive-or-mount-path> --html usb-report.html

# Generate a privacy-preserving feature map for advanced analysis
panicscan features report.json --json features.json

# Safely quarantine a detected threat
panicscan quarantine file <path> --finding-id <finding-id> --quarantine-dir .panicscan-quarantine --yes

# Restore a file from quarantine if needed
panicscan quarantine restore .panicscan-quarantine/<id>.json --yes
```

> **Note:** Scan progress is continuously streamed to `stderr`. The final analytical report is output as JSON to `stdout` for easy integration with your own scripts or automation pipelines.

## 🛠️ For Developers (Local Testing)

PanicScan is built to run efficiently. Developers can verify baseline stability on their own hardware using built-in synthetic tests:

```bash
scripts/perf_usb_10k_smoke.sh
scripts/perf_quick_memory_smoke.sh
```

- The USB script generates a synthetic file structure to verify media scanning logic.
- The memory script runs a rapid system scan to ensure memory footprint (`memory_peak_kb`) remains highly optimized.

## 🏗️ What is PanicScan Building Towards?

PanicScan is currently in its initial engine phases (v1.x), providing a robust **Triage & Detection Engine**. We are actively laying the groundwork for:

- **Active Defense:** Evolving from high-speed scanning into a continuous shield.
- **Zero-Trust Network Analysis:** Recognizing and warning against hostile environments.
- **Behavioral Detection:** Moving beyond signature matching to catch zero-day behaviors before they execute.

*Welcome to the future of decentralized, local-first endpoint security.*
