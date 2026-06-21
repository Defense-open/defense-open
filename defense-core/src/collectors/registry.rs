use std::time::Duration;

use async_trait::async_trait;

use crate::collector::{Collector, EventSender};
use crate::event::{EventKind, RegistryOp, SecurityEvent};

/// Windows Registry collector — monitors high-value persistence keys.
/// No-op on non-Windows platforms.
pub struct RegistryCollector {
    pub poll_interval: Duration,
}

impl Default for RegistryCollector {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(10),
        }
    }
}

#[async_trait]
impl Collector for RegistryCollector {
    fn name(&self) -> &'static str {
        "registry"
    }

    async fn run(&self, tx: EventSender) -> anyhow::Result<()> {
        #[cfg(target_os = "windows")]
        {
            run_windows(self.poll_interval, tx).await
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = tx;
            // Registry not applicable on this platform — sleep forever
            tokio::time::sleep(Duration::MAX).await;
            Ok(())
        }
    }
}

#[cfg(target_os = "windows")]
async fn run_windows(poll_interval: Duration, tx: EventSender) -> anyhow::Result<()> {
    use std::collections::HashMap;
    use winreg::enums::*;
    use winreg::RegKey;

    let watch_keys: &[(&str, &str)] = &[
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM"),
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
        (
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "HKLM",
        ),
        (r"SYSTEM\CurrentControlSet\Services", "HKLM"),
    ];

    let mut snapshots: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut event_id: u64 = 0;

    loop {
        for (subkey, hive) in watch_keys {
            let root = match *hive {
                "HKLM" => RegKey::predef(HKEY_LOCAL_MACHINE),
                "HKCU" => RegKey::predef(HKEY_CURRENT_USER),
                _ => continue,
            };
            let Ok(key) = root.open_subkey(subkey) else {
                continue;
            };

            let full_path = format!("{}\\{}", hive, subkey);
            let current: HashMap<String, String> = key
                .enum_values()
                .filter_map(|r| r.ok())
                .map(|(name, val)| (name, val.to_string()))
                .collect();

            let prev = snapshots.entry(full_path.clone()).or_default();

            for (name, value) in &current {
                let op = if prev.contains_key(name) {
                    if prev[name] != *value {
                        RegistryOp::Set
                    } else {
                        continue;
                    }
                } else {
                    RegistryOp::Create
                };

                let kind = EventKind::Registry {
                    key: full_path.clone(),
                    value_name: name.clone(),
                    operation: op,
                };
                if tx.send(SecurityEvent::new(event_id, kind)).await.is_err() {
                    return Ok(());
                }
                event_id += 1;
            }

            // Detect deletions
            for name in prev.keys() {
                if !current.contains_key(name) {
                    let kind = EventKind::Registry {
                        key: full_path.clone(),
                        value_name: name.clone(),
                        operation: RegistryOp::Delete,
                    };
                    if tx.send(SecurityEvent::new(event_id, kind)).await.is_err() {
                        return Ok(());
                    }
                    event_id += 1;
                }
            }

            *prev = current;
        }

        tokio::time::sleep(poll_interval).await;
    }
}
