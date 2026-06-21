use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use notify::{EventKind as NotifyKind, RecursiveMode, Watcher};
use tokio::sync::mpsc as tokio_mpsc;

use crate::collector::{Collector, EventSender};
use crate::event::{EventKind, FsEventType, SecurityEvent};

pub struct FileSystemCollector {
    pub watch_paths: Vec<PathBuf>,
}

impl Default for FileSystemCollector {
    fn default() -> Self {
        Self {
            watch_paths: default_watch_paths(),
        }
    }
}

fn default_watch_paths() -> Vec<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        vec![
            PathBuf::from(r"C:\Users"),
            PathBuf::from(r"C:\Windows\Temp"),
            PathBuf::from(r"C:\Temp"),
        ]
    }
    #[cfg(target_os = "linux")]
    {
        vec![
            PathBuf::from("/tmp"),
            PathBuf::from("/home"),
            PathBuf::from("/etc"),
        ]
    }
    #[cfg(target_os = "macos")]
    {
        vec![
            PathBuf::from("/tmp"),
            PathBuf::from("/Users"),
            PathBuf::from("/private/tmp"),
        ]
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        vec![PathBuf::from("/tmp")]
    }
}

#[async_trait]
impl Collector for FileSystemCollector {
    fn name(&self) -> &'static str {
        "filesystem"
    }

    async fn run(&self, tx: EventSender) -> anyhow::Result<()> {
        let (notify_tx, mut notify_rx) = tokio_mpsc::channel(256);
        let counter = Arc::new(AtomicU64::new(0));

        let mut watcher =
            notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
                if let Ok(event) = res {
                    let _ = notify_tx.blocking_send(event);
                }
            })?;

        for path in &self.watch_paths {
            if path.exists() {
                watcher.watch(path, RecursiveMode::Recursive)?;
            }
        }

        while let Some(event) = notify_rx.recv().await {
            let fs_type = match event.kind {
                NotifyKind::Create(_) => FsEventType::Created,
                NotifyKind::Modify(_) => FsEventType::Modified,
                NotifyKind::Remove(_) => FsEventType::Deleted,
                NotifyKind::Access(_) => continue,
                _ => continue,
            };

            for path in event.paths {
                let id = counter.fetch_add(1, Ordering::Relaxed);
                let kind = EventKind::FileSystem {
                    path: path.display().to_string(),
                    event_type: fs_type.clone(),
                    entropy_estimate: None,
                };
                if tx.send(SecurityEvent::new(id, kind)).await.is_err() {
                    return Ok(());
                }
            }
        }

        // Keep watcher alive
        drop(watcher);
        tokio::time::sleep(Duration::MAX).await;
        Ok(())
    }
}
