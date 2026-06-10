# PanicScan

Portable cross-platform second-opinion malware triage scanner.

PanicScan focuses on USB trojans, miners, stealers, browser hijackers, suspicious scripts, startup entries, scheduled tasks, LaunchAgents, systemd user units, services, and risky shortcuts.

## Quick Start

```bash
panicscan quick --html report.html
panicscan full --max-minutes 15 --html full-report.html
panicscan usb <drive-or-mount-path> --html usb-report.html
panicscan features report.json --json features.json
panicscan quarantine file <path> --finding-id <finding-id> --quarantine-dir .panicscan-quarantine --yes
panicscan quarantine restore .panicscan-quarantine/<id>.json --yes
```

`full --max-minutes` enforces a file-collection time budget so manual full-disk tests can stop cleanly instead of walking indefinitely.

`quarantine file` and `quarantine restore` refuse to run without `--yes`; quarantine actions are intentionally opt-in.

Scan progress is written to stderr. The final report JSON remains on stdout for scripting.

## Local Performance Smoke

```bash
scripts/perf_usb_10k_smoke.sh
scripts/perf_quick_memory_smoke.sh
```

The script creates a synthetic 10,000-file removable-media tree under `/tmp`, runs `panicscan usb`, and fails if the scan report exceeds 90 seconds.
The memory script runs `panicscan quick` and fails if `memory_peak_kb` exceeds 300 MB.

## Docs

- `docs/compatibility-contract.md`: portability rules for current and future OS releases.
- `docs/ai-agent-architecture.md`: safe LLM/ML/decentralized intelligence architecture.
- `docs/feature-schema-v1.json`: schema for privacy-preserving ML feature export.
- `docs/release.md`: packaging, artifact smoke, signing, and notarization preflight.
- `docs/ml-roadmap.md`: safe ML/self-learning roadmap and zero-day detection limits.
- `scripts/workflow_contract_audit.sh`: verify local CI/Release workflow evidence contracts.
- `scripts/platform_evidence_smoke.sh`: collect OS-specific CI evidence reports.
- `scripts/evidence_next_steps.sh`: print current evidence status and next commands.
- `scripts/physical_usb_acceptance.sh`: read-only real removable-media acceptance check.

## What PanicScan Is

- portable scanner
- fast triage tool
- local report generator
- reversible quarantine tool

## What PanicScan Is Not

- not a real-time antivirus
- not a Defender, XProtect, Gatekeeper, ClamAV, or EDR replacement
- not a kernel rootkit detector
- not a 99.9% guarantee for every attack, vulnerability, or zero-day
- not a guarantee that a PC is clean
