use std::fs;
use std::path::Path;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use panicscan_core::report::{features, html, json};
use panicscan_core::{ScanMode, ScanReport, ScanRequest, ScanRunner};

mod ipc_client;
mod ui;

#[derive(Debug, Parser)]
#[command(name = "panicscan")]
#[command(about = "Portable cross-platform second-opinion malware triage scanner")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    // ── Eski on-demand tarama komutları (korundu) ──────────────────────────
    Quick {
        #[arg(long)]
        json: Option<String>,
        #[arg(long)]
        html: Option<String>,
    },
    Full {
        #[arg(long, default_value_t = 15)]
        max_minutes: u64,
        #[arg(long)]
        json: Option<String>,
        #[arg(long)]
        html: Option<String>,
    },
    Usb {
        drive: String,
        #[arg(long)]
        json: Option<String>,
        #[arg(long)]
        html: Option<String>,
    },
    Features {
        report: String,
        #[arg(long)]
        json: Option<String>,
    },
    Quarantine {
        #[command(subcommand)]
        command: QuarantineCommand,
    },

    // ── Daemon IPC komutları (yeni) ────────────────────────────────────────
    /// Arka planda çalışan daemon'ın durumunu göster.
    Status,

    /// Daemon'a belirli bir dosyayı anında tarat.
    #[command(name = "daemon-scan")]
    DaemonScan {
        /// Taranacak dosya veya klasör yolu.
        path: String,
    },

    /// Daemon'ın tarama olaylarını listele (son N adet).
    Events {
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
}

#[derive(Debug, Subcommand)]
enum QuarantineCommand {
    File {
        path: String,
        #[arg(long)]
        finding_id: String,
        #[arg(long, default_value = ".panicscan-quarantine")]
        quarantine_dir: String,
        #[arg(long, required = true)]
        yes: bool,
    },
    Restore {
        metadata: String,
        #[arg(long, required = true)]
        yes: bool,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("warn")
        .without_time()
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    // Daemon IPC komutları async runtime gerektiriyor.
    match &cli.command {
        Commands::Status | Commands::DaemonScan { .. } | Commands::Events { .. } => {
            let rt = tokio::runtime::Runtime::new()?;
            return rt.block_on(run_daemon_command(cli.command));
        }
        _ => {}
    }

    // Eski on-demand tarama komutları (değişmedi).
    match cli.command {
        Commands::Quick { json, html } => run_scan(ScanRequest::new(ScanMode::Quick), json, html),
        Commands::Full {
            max_minutes,
            json,
            html,
        } => run_scan(
            ScanRequest::new(ScanMode::Full).with_max_minutes(max_minutes),
            json,
            html,
        ),
        Commands::Usb { drive, json, html } => {
            run_scan(ScanRequest::new(ScanMode::Usb).with_root(drive), json, html)
        }
        Commands::Features { report, json } => run_features(&report, json),
        Commands::Quarantine { command } => run_quarantine(command),
        _ => unreachable!(),
    }
}

// ─── Daemon IPC komut handler'ları ───────────────────────────────────────────

async fn run_daemon_command(command: Commands) -> Result<()> {
    use panicscan_daemon::ipc_types::{IpcRequest, IpcResponse};

    match command {
        Commands::Status => {
            let response = ipc_client::send_request(&IpcRequest::Status).await?;
            match response {
                IpcResponse::Status(s) => {
                    let uptime = chrono::Utc::now()
                        .signed_duration_since(s.started_at)
                        .to_std()
                        .unwrap_or_default();

                    let h = uptime.as_secs() / 3600;
                    let m = (uptime.as_secs() % 3600) / 60;
                    let sec = uptime.as_secs() % 60;

                    println!("╔══════════════════════════════════════════════╗");
                    println!("║      🛡️  PanicScan Daemon Durumu             ║");
                    println!("╠══════════════════════════════════════════════╣");
                    println!("║ Durum     : ✅ Çalışıyor                     ║");
                    println!("║ Versiyon  : v{:<33}║", s.version);
                    println!(
                        "║ Çalışma   : {:02}sa {:02}dk {:02}sn{:<20}║",
                        h, m, sec, ""
                    );
                    println!("║ Taranan   : {:<34}║", s.total_scans);
                    println!("║ Uyarılar  : {:<34}║", s.total_alerts);
                    println!("║ İzlenen   : {} klasör{:<27}║", s.watched_dirs, "");
                    println!("╠══════════════════════════════════════════════╣");
                    println!("║ {}  ║", s.protection_mode);
                    println!("╚══════════════════════════════════════════════╝");
                }
                IpcResponse::Error { message, .. } => {
                    eprintln!("❌ {message}");
                }
                _ => eprintln!("Beklenmeyen cevap."),
            }
        }

        Commands::DaemonScan { path } => {
            println!("🔍 Daemon'a tarama isteği gönderiliyor: {path}");
            let response = ipc_client::send_request(&IpcRequest::ScanFile { path }).await?;
            match response {
                IpcResponse::ScanResult(r) => {
                    println!("╔══════════════════════════════════╗");
                    println!("║ Tarama Sonucu                    ║");
                    println!("╠══════════════════════════════════╣");
                    println!("║ Dosya    : {:<22}...║", &r.path[..r.path.len().min(22)]);
                    println!("║ Bulgular : {:<22}║", r.finding_count);
                    println!("║ Seviye   : {:<22}║", r.highest_severity.to_uppercase());
                    println!("║ Süre     : {}ms{:<19}║", r.duration_ms, "");
                    println!("╚══════════════════════════════════╝");

                    if r.highest_severity == "high" || r.highest_severity == "critical" {
                        eprintln!("\n⚠️  YÜKSEK TEHDİT TESPİT EDİLDİ!");
                    }
                }
                IpcResponse::Error { message, .. } => {
                    eprintln!("❌ {message}");
                }
                _ => eprintln!("Beklenmeyen cevap."),
            }
        }

        Commands::Events { limit } => {
            let response = ipc_client::send_request(&IpcRequest::ListEvents { limit }).await?;
            match response {
                IpcResponse::Events(events) if events.is_empty() => {
                    println!("Henüz tarama olayı yok.");
                }
                IpcResponse::Events(events) => {
                    println!("{:<36} {:<12} {:<8}", "Zaman", "Seviye", "Bulgular");
                    println!("{}", "-".repeat(60));
                    for e in events {
                        println!(
                            "{:<36} {:<12} {}",
                            e.detected_at.format("%Y-%m-%d %H:%M:%S"),
                            e.severity.to_uppercase(),
                            e.finding_count,
                        );
                    }
                }
                IpcResponse::Error { message, .. } => {
                    eprintln!("❌ {message}");
                }
                _ => eprintln!("Beklenmeyen cevap."),
            }
        }

        _ => unreachable!(),
    }

    Ok(())
}

fn run_scan(
    request: ScanRequest,
    json_path: Option<String>,
    html_path: Option<String>,
) -> Result<()> {
    // Legacy path: if stdout is piped (not a TTY) or --json/--html requested
    // without interactive terminal, keep the original behaviour so CI and
    // scripts are not broken.
    let is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());
    let report = if is_tty {
        ui::run_scan_with_ui(request)?
    } else {
        eprintln!("{}", scan_start_message(&request));
        ScanRunner::default().run(request)?
    };

    write_reports(&report, json_path, html_path)?;

    // Only dump raw JSON to stdout when explicitly requested (--json flag)
    // or when running non-interactively.
    if !is_tty {
        println!("{}", json::to_pretty_json(&report)?);
    }

    Ok(())
}

fn run_features(report_path: &str, json_path: Option<String>) -> Result<()> {
    let report: ScanReport = serde_json::from_slice(&fs::read(report_path)?)?;
    let export = features::export_feature_vectors(&report);
    let output = serde_json::to_string_pretty(&export)?;
    if let Some(path) = json_path {
        fs::write(path, &output)?;
    }
    println!("{output}");
    Ok(())
}

fn scan_start_message(request: &ScanRequest) -> String {
    format!("panicscan: starting {:?} scan", request.mode)
}

fn write_reports(
    report: &ScanReport,
    json_path: Option<String>,
    html_path: Option<String>,
) -> Result<()> {
    if let Some(path) = json_path {
        fs::write(path, json::to_pretty_json(report)?)?;
    }
    if let Some(path) = html_path {
        fs::write(path, html::render_html(report))?;
    }
    Ok(())
}

fn run_quarantine(command: QuarantineCommand) -> Result<()> {
    match command {
        QuarantineCommand::File {
            path,
            finding_id,
            quarantine_dir,
            yes,
        } => {
            if !yes {
                bail!("refusing to quarantine without explicit --yes confirmation");
            }
            let manager = panicscan_core::quarantine::QuarantineManager::new(quarantine_dir);
            let metadata = manager.quarantine_file(Path::new(&path), &finding_id)?;
            println!("{}", serde_json::to_string_pretty(&metadata)?);
            Ok(())
        }
        QuarantineCommand::Restore { metadata, yes } => {
            if !yes {
                bail!("refusing to restore without explicit --yes confirmation");
            }
            let metadata_path = Path::new(&metadata);
            let metadata: panicscan_core::quarantine::QuarantineMetadata =
                serde_json::from_slice(&fs::read(metadata_path)?)?;
            let quarantine_root = metadata_path.parent().unwrap_or_else(|| Path::new("."));
            let manager = panicscan_core::quarantine::QuarantineManager::new(quarantine_root);
            manager.restore_file(&metadata)?;
            println!("{}", serde_json::to_string_pretty(&metadata)?);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quarantine_file_requires_explicit_yes_flag() {
        let result = Cli::try_parse_from([
            "panicscan",
            "quarantine",
            "file",
            "/tmp/bad.exe",
            "--finding-id",
            "finding-1",
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn quarantine_file_accepts_explicit_yes_flag() {
        let result = Cli::try_parse_from([
            "panicscan",
            "quarantine",
            "file",
            "/tmp/bad.exe",
            "--finding-id",
            "finding-1",
            "--yes",
        ]);

        assert!(result.is_ok());
    }

    #[test]
    fn quarantine_restore_requires_explicit_yes_flag() {
        let result = Cli::try_parse_from([
            "panicscan",
            "quarantine",
            "restore",
            "/tmp/quarantine/finding.json",
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn quarantine_restore_accepts_explicit_yes_flag() {
        let result = Cli::try_parse_from([
            "panicscan",
            "quarantine",
            "restore",
            "/tmp/quarantine/finding.json",
            "--yes",
        ]);

        assert!(result.is_ok());
    }

    #[test]
    fn quick_scan_progress_message_is_human_readable() {
        let message = scan_start_message(&ScanRequest::new(ScanMode::Quick));

        assert!(message.contains("starting Quick scan"));
    }

    #[test]
    fn features_command_accepts_report_path() {
        let result = Cli::try_parse_from(["panicscan", "features", "/tmp/report.json"]);

        assert!(result.is_ok());
    }
}
