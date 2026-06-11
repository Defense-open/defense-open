//! Daemon durum nesnesi — tüm modüller bu yapıyı paylaşır.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use tokio::sync::RwLock;

use crate::ipc_types::{DaemonStatus, ProtectionMode};

/// `DaemonState`, daemon boyunca tek bir `Arc<DaemonState>` olarak tutulur.
/// Tüm async task'lar bu nesneyi klonlayarak paylaşır.
#[derive(Debug)]
pub struct DaemonState {
    /// Daemon'ın başladığı zaman (değişmez).
    pub started_at: DateTime<Utc>,

    /// Şimdiye kadar taranan toplam dosya sayısı (atomik, kilitsiz).
    total_scans: AtomicU64,

    /// Şimdiye kadar üretilen toplam uyarı sayısı (atomik, kilitsiz).
    total_alerts: AtomicU64,

    /// İzlenen klasörlerin listesi (nadiren değişir, RwLock yeterli).
    pub watched_dirs: RwLock<Vec<String>>,

    /// Aktif koruma modu.
    pub protection_mode: RwLock<ProtectionMode>,
}

impl DaemonState {
    /// Yeni bir daemon durumu oluşturur.
    pub fn new(watched_dirs: Vec<String>) -> Arc<Self> {
        Arc::new(Self {
            started_at: Utc::now(),
            total_scans: AtomicU64::new(0),
            total_alerts: AtomicU64::new(0),
            watched_dirs: RwLock::new(watched_dirs),
            protection_mode: RwLock::new(ProtectionMode::RulesOnly),
        })
    }

    /// Bir tarama tamamlandığında çağrılır.
    pub fn record_scan(&self, produced_alert: bool) {
        self.total_scans.fetch_add(1, Ordering::Relaxed);
        if produced_alert {
            self.total_alerts.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Toplam tarama sayısını döndürür.
    pub fn total_scans(&self) -> u64 {
        self.total_scans.load(Ordering::Relaxed)
    }

    /// Toplam uyarı sayısını döndürür.
    pub fn total_alerts(&self) -> u64 {
        self.total_alerts.load(Ordering::Relaxed)
    }

    /// IPC üzerinden gönderilecek durum özetini oluşturur.
    pub async fn to_status(&self) -> DaemonStatus {
        let dirs = self.watched_dirs.read().await;
        let mode = self.protection_mode.read().await;
        DaemonStatus {
            running: true,
            started_at: self.started_at,
            total_scans: self.total_scans(),
            total_alerts: self.total_alerts(),
            watched_dirs: dirs.len(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            protection_mode: mode.clone(),
        }
    }
}
