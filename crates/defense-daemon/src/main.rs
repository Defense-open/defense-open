//! PanicScan Daemon — Ana giriş noktası.
//!
//! Kullanım:
//!   panicscan-daemon install    — OS servisini kur
//!   panicscan-daemon uninstall  — OS servisini kaldır
//!   panicscan-daemon start      — servisi başlat
//!   panicscan-daemon stop       — servisi durdur
//!   panicscan-daemon run        — daemon loop'unu çalıştır (servis tarafından çağrılır)
//!   panicscan-daemon status     — IPC üzerinden daemon durumunu sorgula

use anyhow::Result;
use clap::{Parser, Subcommand};

// ─── CLI arayüzü ─────────────────────────────────────────────────────────────

#[derive(Debug, Parser)]
#[command(
    name = "panicscan-daemon",
    about = "PanicScan gerçek zamanlı koruma daemon'ı",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: DaemonCommand,
}

#[derive(Debug, Subcommand)]
enum DaemonCommand {
    /// Daemon'ı OS servisi olarak kur (yönetici yetkisi gerekir).
    Install,
    /// Daemon'ı OS servis listesinden kaldır.
    Uninstall,
    /// Kurulu servisi başlat.
    Start,
    /// Çalışan servisi durdur.
    Stop,
    /// Daemon loop'unu doğrudan çalıştır — servis tarafından kullanılır.
    /// Manuel test için: `sudo panicscan-daemon run`
    Run,
    /// IPC üzerinden daemon'ın durumunu göster.
    Status,
}

// ─── Giriş noktası ───────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    // Logging başlat — PANICSCAN_LOG env ile seviye ayarlanabilir.
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("PANICSCAN_LOG")
                .unwrap_or_else(|_| "panicscan_daemon=info,warn".to_string()),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();

    match cli.command {
        DaemonCommand::Install => cmd_install(),
        DaemonCommand::Uninstall => cmd_uninstall(),
        DaemonCommand::Start => cmd_start(),
        DaemonCommand::Stop => cmd_stop(),
        DaemonCommand::Run => panicscan_daemon::run_daemon_loop().await,
        DaemonCommand::Status => cmd_status().await,
    }
}

// ─── Servis komutları ─────────────────────────────────────────────────────────

fn cmd_install() -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        panicscan_daemon::service::windows::install()
    }

    #[cfg(target_os = "linux")]
    {
        panicscan_daemon::service::linux::install()
    }

    #[cfg(target_os = "macos")]
    {
        panicscan_daemon::service::macos::install()
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        anyhow::bail!("Bu platform için servis kurulumu desteklenmiyor.")
    }
}

fn cmd_uninstall() -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        panicscan_daemon::service::windows::uninstall()
    }

    #[cfg(target_os = "linux")]
    {
        panicscan_daemon::service::linux::uninstall()
    }

    #[cfg(target_os = "macos")]
    {
        panicscan_daemon::service::macos::uninstall()
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        anyhow::bail!("Bu platform desteklenmiyor.")
    }
}

fn cmd_start() -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        panicscan_daemon::service::windows::start()
    }

    #[cfg(target_os = "linux")]
    {
        panicscan_daemon::service::linux::start()
    }

    #[cfg(target_os = "macos")]
    {
        panicscan_daemon::service::macos::start()
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        anyhow::bail!("Bu platform desteklenmiyor.")
    }
}

fn cmd_stop() -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        panicscan_daemon::service::windows::stop()
    }

    #[cfg(target_os = "linux")]
    {
        panicscan_daemon::service::linux::stop()
    }

    #[cfg(target_os = "macos")]
    {
        panicscan_daemon::service::macos::stop()
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        anyhow::bail!("Bu platform desteklenmiyor.")
    }
}

// ─── IPC status komutu ────────────────────────────────────────────────────────

async fn cmd_status() -> Result<()> {
    // CLI-side IPC client — daemon'a bağlan ve Status isteği gönder.
    // Daemon çalışmıyorsa anlamlı bir hata ver.
    let socket_path = panicscan_daemon::ipc::socket_path();

    #[cfg(unix)]
    {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::UnixStream;

        let stream = UnixStream::connect(&socket_path).await.map_err(|e| {
            anyhow::anyhow!(
                "Daemon'a bağlanılamadı ({}): {}\n\
                 Daemon çalışıyor mu? `panicscan-daemon start` ile başlatın.",
                socket_path,
                e
            )
        })?;

        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);

        let request =
            serde_json::to_string(&panicscan_daemon::ipc_types::IpcRequest::Status)? + "\n";
        write_half.write_all(request.as_bytes()).await?;
        write_half.flush().await?;

        let mut line = String::new();
        reader.read_line(&mut line).await?;

        let response: panicscan_daemon::ipc_types::IpcResponse = serde_json::from_str(line.trim())?;
        print_status_response(response);
    }

    #[cfg(windows)]
    {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::windows::named_pipe::ClientOptions;

        let pipe = ClientOptions::new().open(&socket_path).map_err(|e| {
            anyhow::anyhow!(
                "Daemon'a bağlanılamadı: {}\n\
                 Daemon çalışıyor mu? `panicscan-daemon start` ile başlatın.",
                e
            )
        })?;

        let (read_half, mut write_half) = tokio::io::split(pipe);
        let mut reader = BufReader::new(read_half);

        let request =
            serde_json::to_string(&panicscan_daemon::ipc_types::IpcRequest::Status)? + "\n";
        write_half.write_all(request.as_bytes()).await?;
        write_half.flush().await?;

        let mut line = String::new();
        reader.read_line(&mut line).await?;

        let response: panicscan_daemon::ipc_types::IpcResponse = serde_json::from_str(line.trim())?;
        print_status_response(response);
    }

    Ok(())
}

fn print_status_response(response: panicscan_daemon::ipc_types::IpcResponse) {
    match response {
        panicscan_daemon::ipc_types::IpcResponse::Status(s) => {
            let uptime = chrono::Utc::now()
                .signed_duration_since(s.started_at)
                .to_std()
                .unwrap_or_default();
            let uptime_str = format!(
                "{}s {}dk {}sa",
                uptime.as_secs() % 60,
                (uptime.as_secs() / 60) % 60,
                uptime.as_secs() / 3600,
            );

            println!("╔══════════════════════════════════════╗");
            println!("║     PanicScan Daemon Durumu          ║");
            println!("╠══════════════════════════════════════╣");
            println!("║ Durum     : ✅ Çalışıyor             ║");
            println!("║ Versiyon  : v{:<28}║", s.version);
            println!("║ Çalışma   : {:<28}║", uptime_str);
            println!("║ Taranan   : {:<28}║", s.total_scans);
            println!("║ Uyarılar  : {:<28}║", s.total_alerts);
            println!("║ İzlenen   : {} klasör{:<21}║", s.watched_dirs, "");
            println!("║ Koruma    : {}  ║", s.protection_mode);
            println!("╚══════════════════════════════════════╝");
        }
        panicscan_daemon::ipc_types::IpcResponse::Error { message, .. } => {
            eprintln!("❌ Hata: {message}");
        }
        other => {
            eprintln!("Beklenmeyen cevap: {other:?}");
        }
    }
}

// Daemon loop moved to lib.rs
