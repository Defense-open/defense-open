use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use tokio::signal;
use tokio::sync::mpsc;

use defense_core::collector::{Collector, EventBus};
use defense_core::collectors::filesystem::FileSystemCollector;
use defense_core::collectors::network::NetworkCollector;
use defense_core::collectors::process::ProcessCollector;
use defense_core::collectors::registry::RegistryCollector;
use defense_core::collectors::usb::UsbCollector;
use defense_core::rule_engine::RuleEngine;
use defense_core::rules::loader::load_from_dir;

mod alert;

use alert::AlertSink;

#[derive(Parser)]
#[command(
    name = "defense-agent",
    version,
    about = "Defense XDR — community endpoint agent"
)]
struct Cli {
    /// Kural TOML dosyalarının bulunduğu dizin
    #[arg(long, default_value = "rules")]
    rules_dir: PathBuf,

    /// Alert çıktı dosyası (belirtilmezse stdout)
    #[arg(long)]
    alert_file: Option<PathBuf>,

    /// EventBus tampon boyutu
    #[arg(long, default_value_t = 1024)]
    buffer: usize,

    /// Hangi collector'lar aktif (virgülle ayrılmış: process,fs,network,registry,usb)
    #[arg(long, default_value = "process,fs,network,registry,usb")]
    collectors: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    eprintln!(
        "[Defense] Starting — rules dir: {}",
        cli.rules_dir.display()
    );

    // Kural motoru yükle
    let engine = Arc::new(load_from_dir(&cli.rules_dir)?);
    eprintln!("[Defense] Rule engine ready.");

    // Alert sink
    let sink = Arc::new(AlertSink::new(cli.alert_file.clone())?);

    // EventBus
    let mut bus = EventBus::new(cli.buffer);

    // Aktif collector listesi
    let active: Vec<&str> = cli.collectors.split(',').map(str::trim).collect();

    // Collector'ları spawn et
    let mut handles = Vec::new();
    for name in &active {
        let tx = bus.sender();
        match *name {
            "process" => {
                eprintln!("[Defense] ProcessCollector starting...");
                let c = ProcessCollector::default();
                handles.push(tokio::spawn(async move {
                    if let Err(e) = c.run(tx).await {
                        eprintln!("[Defense] ProcessCollector error: {e}");
                    }
                }));
            }
            "fs" => {
                eprintln!("[Defense] FileSystemCollector starting...");
                let c = FileSystemCollector::default();
                handles.push(tokio::spawn(async move {
                    if let Err(e) = c.run(tx).await {
                        eprintln!("[Defense] FileSystemCollector error: {e}");
                    }
                }));
            }
            "network" => {
                eprintln!("[Defense] NetworkCollector starting...");
                let c = NetworkCollector::default();
                handles.push(tokio::spawn(async move {
                    if let Err(e) = c.run(tx).await {
                        eprintln!("[Defense] NetworkCollector error: {e}");
                    }
                }));
            }
            "registry" => {
                eprintln!("[Defense] RegistryCollector starting...");
                let c = RegistryCollector::default();
                handles.push(tokio::spawn(async move {
                    if let Err(e) = c.run(tx).await {
                        eprintln!("[Defense] RegistryCollector error: {e}");
                    }
                }));
            }
            "usb" => {
                eprintln!("[Defense] UsbCollector starting...");
                let c = UsbCollector::default();
                handles.push(tokio::spawn(async move {
                    if let Err(e) = c.run(tx).await {
                        eprintln!("[Defense] UsbCollector error: {e}");
                    }
                }));
            }
            other => {
                eprintln!("[Defense] Unknown collector: {other}, skipping.");
            }
        }
    }

    eprintln!("[Defense] Running. Press Ctrl+C to stop.");

    // Shutdown kanalı
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
    tokio::spawn(async move {
        let _ = signal::ctrl_c().await;
        eprintln!("\n[Defense] Shutting down...");
        let _ = shutdown_tx.send(()).await;
    });

    // Ana event loop
    loop {
        tokio::select! {
            event = bus.recv() => {
                match event {
                    Some(ev) => {
                        let matches = engine.evaluate(&ev);
                        if !matches.is_empty() {
                            sink.emit(&ev, &matches)?;
                        }
                    }
                    None => break,
                }
            }
            _ = shutdown_rx.recv() => {
                break;
            }
        }
    }

    for h in handles {
        h.abort();
    }
    eprintln!("[Defense] Stopped.");
    Ok(())
}
