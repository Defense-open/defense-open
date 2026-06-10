use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use indicatif::{ProgressBar, ProgressStyle};
use owo_colors::OwoColorize;
use panicscan_core::report::{Finding, FindingSeverity, RecommendedAction, ScanReport};
use panicscan_core::{ScanMode, ScanRequest, ScanRunner};

use anyhow::Result;

// ── Public entry point ────────────────────────────────────────────────────────

/// Run a scan and render results to the terminal with colours and a live
/// progress counter.  Returns the completed `ScanReport` so the caller can
/// write JSON/HTML output files.
pub fn run_scan_with_ui(request: ScanRequest) -> Result<ScanReport> {
    let mode_label = mode_label(&request.mode);
    print_header(mode_label);

    // Shared counter — the runner increments it, we read it in the UI loop.
    let progress = Arc::new(AtomicU64::new(0));
    let runner = ScanRunner::with_progress(progress.clone());

    let pb = make_spinner(format!("Scanning ({mode_label})…"));
    let scan_start = Instant::now();

    // Run the scan in a background thread so we can update the UI concurrently.
    let (done_tx, done_rx) = std::sync::mpsc::channel::<Result<ScanReport>>();
    std::thread::spawn(move || {
        let _ = done_tx.send(runner.run(request));
    });

    // UI loop: update the spinner message every 250 ms until the scan finishes.
    let report = loop {
        match done_rx.recv_timeout(Duration::from_millis(250)) {
            Ok(result) => break result?,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                let files = progress.load(Ordering::Relaxed);
                let elapsed = scan_start.elapsed().as_secs();
                pb.set_message(format!(
                    "Scanning ({mode_label})… {} dosya | {}",
                    format_number(files),
                    format_elapsed(elapsed),
                ));
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                anyhow::bail!("scanner thread panicked unexpectedly");
            }
        }
    };

    pb.finish_and_clear();
    render_report(&report);
    Ok(report)
}

// ── Header ────────────────────────────────────────────────────────────────────

fn print_header(mode: &str) {
    let title = format!(" PanicScan  ·  {mode} ");
    let width = title.len() + 4;
    let bar = "═".repeat(width);
    eprintln!();
    eprintln!("  ╔{bar}╗");
    eprintln!("  ║  {}  ║", title.bold());
    eprintln!("  ╚{bar}╝");
    eprintln!();
}

// ── Spinner ───────────────────────────────────────────────────────────────────

fn make_spinner(msg: String) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.enable_steady_tick(Duration::from_millis(100));
    pb.set_style(
        ProgressStyle::with_template("  {spinner:.cyan}  {msg}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    pb.set_message(msg);
    pb
}

// ── Report renderer ───────────────────────────────────────────────────────────

pub fn render_report(report: &ScanReport) {
    let counts = SeverityCounts::from(report);
    let divider = "─".repeat(60);

    // ── findings ──────────────────────────────────────────────────────────
    if report.findings.is_empty() {
        eprintln!("  {}", "✓  No threats found.".green().bold());
    } else {
        eprintln!("  {divider}");
        let mut sorted = report.findings.clone();
        sorted.sort_by_key(|f| severity_sort_key(&f.severity));
        for finding in &sorted {
            print_finding(finding);
        }
    }

    // ── summary ───────────────────────────────────────────────────────────
    eprintln!("  {divider}");
    eprintln!();
    eprint!("  Summary: ");
    if counts.critical > 0 {
        eprint!("{}  ", format!("{} CRITICAL", counts.critical).red().bold());
    }
    if counts.high > 0 {
        eprint!("{}  ", format!("{} HIGH", counts.high).yellow().bold());
    }
    if counts.medium > 0 {
        eprint!("{}  ", format!("{} MEDIUM", counts.medium).bright_yellow());
    }
    if counts.low > 0 {
        eprint!("{}  ", format!("{} LOW", counts.low).bright_blue());
    }
    if counts.info > 0 {
        eprint!("{}  ", format!("{} INFO", counts.info).dimmed());
    }
    if counts.total() == 0 {
        eprint!("{}", "Clean".green());
    }
    eprintln!();
    eprintln!(
        "  Files: {}    Duration: {}",
        format_number(report.scanned_files).bold(),
        format_elapsed(report.duration_ms / 1000).bold(),
    );
    eprintln!();

    // ── quarantine hint ───────────────────────────────────────────────────
    let quarantinable: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| f.recommended_action == RecommendedAction::Quarantine)
        .collect();

    if !quarantinable.is_empty() {
        eprintln!("  {}", "To quarantine a finding:".dimmed());
        eprintln!(
            "  {}",
            "  panicscan quarantine file <path> --finding-id <id> --yes"
                .dimmed()
                .italic()
        );
        eprintln!();
    }
}

// ── Single finding printer ────────────────────────────────────────────────────

fn print_finding(f: &Finding) {
    let badge = severity_badge(&f.severity);
    let score_str = format!("[{:>3}]", f.score);
    let score = score_str.dimmed();
    eprintln!();
    eprintln!("  {}  {}  {}", badge, score, f.title.bold());

    // location
    if let Some(path) = &f.item_path {
        eprintln!("  {}  {}", " ".repeat(10), path.dimmed());
    } else if let Some(loc) = &f.persistence_location {
        eprintln!("  {}  {}", " ".repeat(10), loc.dimmed());
    } else if let Some(pid) = f.process_id {
        eprintln!("  {}  PID {}", " ".repeat(10), pid.to_string().dimmed());
    }

    // explanation (word-wrapped at 70 chars)
    for line in wrap(&f.explanation, 70) {
        eprintln!("  {}  {}", " ".repeat(10), line.dimmed().italic());
    }

    // evidence codes
    if !f.evidences.is_empty() {
        let codes: Vec<&str> = f.evidences.iter().map(|e| e.code.as_str()).collect();
        eprintln!(
            "  {}  {}",
            " ".repeat(10),
            format!("evidence: {}", codes.join(", ")).dimmed()
        );
    }

    // action hint
    let action = match &f.recommended_action {
        RecommendedAction::Quarantine => Some("→ quarantine recommended"),
        RecommendedAction::ManualExpertReview => Some("→ manual expert review"),
        RecommendedAction::OfflineSecurityScan => Some("→ offline security scan"),
        RecommendedAction::Review => Some("→ review"),
        RecommendedAction::Ignore => None,
    };
    if let Some(hint) = action {
        eprintln!("  {}  {}", " ".repeat(10), hint.bright_cyan());
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn severity_badge(s: &FindingSeverity) -> String {
    match s {
        FindingSeverity::Critical => " CRITICAL ".red().bold().to_string(),
        FindingSeverity::High => "  HIGH    ".yellow().bold().to_string(),
        FindingSeverity::Medium => "  MEDIUM  ".bright_yellow().to_string(),
        FindingSeverity::Low => "  LOW     ".bright_blue().to_string(),
        FindingSeverity::Info => "  INFO    ".dimmed().to_string(),
    }
}

fn severity_sort_key(s: &FindingSeverity) -> u8 {
    match s {
        FindingSeverity::Critical => 0,
        FindingSeverity::High => 1,
        FindingSeverity::Medium => 2,
        FindingSeverity::Low => 3,
        FindingSeverity::Info => 4,
    }
}

fn mode_label(mode: &ScanMode) -> &'static str {
    match mode {
        ScanMode::Quick => "Quick Scan",
        ScanMode::Full => "Full Scan",
        ScanMode::Usb => "USB Scan",
    }
}

/// Format a number with thousands separator (e.g. 12345 → "12,345").
fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, ch) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(ch);
    }
    result.chars().rev().collect()
}

/// Format elapsed seconds as "HH:MM:SS".
fn format_elapsed(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

/// Naive word-wrap: split text into lines of at most `width` chars.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.is_empty() {
            current.push_str(word);
        } else if current.len() + 1 + word.len() <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(current.clone());
            current = word.to_string();
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

// ── Severity counter ──────────────────────────────────────────────────────────

struct SeverityCounts {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
}

impl SeverityCounts {
    fn from(report: &ScanReport) -> Self {
        let mut c = Self {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
        };
        for f in &report.findings {
            match f.severity {
                FindingSeverity::Critical => c.critical += 1,
                FindingSeverity::High => c.high += 1,
                FindingSeverity::Medium => c.medium += 1,
                FindingSeverity::Low => c.low += 1,
                FindingSeverity::Info => c.info += 1,
            }
        }
        c
    }

    fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low + self.info
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_short_text_is_single_line() {
        let lines = wrap("hello world", 80);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0], "hello world");
    }

    #[test]
    fn wrap_long_text_splits_at_word_boundary() {
        let text = "one two three four five six seven eight nine ten";
        let lines = wrap(text, 20);
        for line in &lines {
            assert!(line.len() <= 20, "line too long: {line:?}");
        }
    }

    #[test]
    fn severity_sort_critical_first() {
        assert!(
            severity_sort_key(&FindingSeverity::Critical)
                < severity_sort_key(&FindingSeverity::High)
        );
    }

    #[test]
    fn format_number_inserts_commas() {
        assert_eq!(format_number(0), "0");
        assert_eq!(format_number(999), "999");
        assert_eq!(format_number(1000), "1,000");
        assert_eq!(format_number(1_234_567), "1,234,567");
    }

    #[test]
    fn format_elapsed_pads_correctly() {
        assert_eq!(format_elapsed(0), "00:00:00");
        assert_eq!(format_elapsed(61), "00:01:01");
        assert_eq!(format_elapsed(3661), "01:01:01");
    }

    #[test]
    fn severity_counts_totals_correctly() {
        use panicscan_core::scan::ScanMode;

        let make_finding = |sev: FindingSeverity| Finding {
            id: "x".into(),
            severity: sev,
            score: 50,
            title: "t".into(),
            explanation: "e".into(),
            item_path: None,
            process_id: None,
            persistence_location: None,
            evidences: vec![],
            recommended_action: RecommendedAction::Review,
        };

        let report = ScanReport {
            schema_version: "1".into(),
            app_version: "0.1.0".into(),
            mode: ScanMode::Quick,
            started_at: "".into(),
            finished_at: "".into(),
            duration_ms: 0,
            memory_peak_kb: None,
            scanned_files: 0,
            scanned_persistence_entries: 0,
            findings: vec![
                make_finding(FindingSeverity::Critical),
                make_finding(FindingSeverity::Critical),
                make_finding(FindingSeverity::High),
                make_finding(FindingSeverity::Medium),
            ],
            warnings: vec![],
        };

        let counts = SeverityCounts::from(&report);
        assert_eq!(counts.critical, 2);
        assert_eq!(counts.high, 1);
        assert_eq!(counts.medium, 1);
        assert_eq!(counts.total(), 4);
    }
}
