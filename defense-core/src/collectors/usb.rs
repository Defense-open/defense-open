use std::collections::HashSet;
use std::time::Duration;

use async_trait::async_trait;
use sysinfo::Disks;

use crate::collector::{Collector, EventSender};
use crate::event::{EventKind, SecurityEvent};

pub struct UsbCollector {
    pub poll_interval: Duration,
}

impl Default for UsbCollector {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(3),
        }
    }
}

#[async_trait]
impl Collector for UsbCollector {
    fn name(&self) -> &'static str {
        "usb"
    }

    async fn run(&self, tx: EventSender) -> anyhow::Result<()> {
        let mut seen: HashSet<String> = HashSet::new();
        let mut event_id: u64 = 0;
        let mut disks = Disks::new_with_refreshed_list();

        loop {
            disks.refresh(true);

            for disk in disks.list() {
                let name = disk.name().to_string_lossy().to_string();
                if seen.contains(&name) {
                    continue;
                }

                // Removable disks are likely USB
                if disk.is_removable() {
                    seen.insert(name.clone());
                    let kind = EventKind::Usb {
                        device_id: name,
                        device_class: disk.kind().to_string(),
                    };
                    if tx.send(SecurityEvent::new(event_id, kind)).await.is_err() {
                        return Ok(());
                    }
                    event_id += 1;
                }
            }

            tokio::time::sleep(self.poll_interval).await;
        }
    }
}
