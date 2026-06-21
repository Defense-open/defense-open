use std::collections::HashSet;
use std::time::Duration;

use async_trait::async_trait;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System};

use crate::collector::{Collector, EventSender};
use crate::event::{EventKind, SecurityEvent};

pub struct ProcessCollector {
    pub poll_interval: Duration,
}

impl Default for ProcessCollector {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(2),
        }
    }
}

#[async_trait]
impl Collector for ProcessCollector {
    fn name(&self) -> &'static str {
        "process"
    }

    async fn run(&self, tx: EventSender) -> anyhow::Result<()> {
        let mut sys = System::new_with_specifics(
            RefreshKind::nothing().with_processes(ProcessRefreshKind::everything()),
        );
        let mut seen: HashSet<u32> = HashSet::new();
        let mut event_id: u64 = 0;

        loop {
            sys.refresh_processes(ProcessesToUpdate::All, true);

            for (pid, proc) in sys.processes() {
                let pid_u32 = pid.as_u32();
                if seen.contains(&pid_u32) {
                    continue;
                }
                seen.insert(pid_u32);

                let image = proc
                    .exe()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default();

                let command_line = proc
                    .cmd()
                    .iter()
                    .map(|s| s.to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join(" ");

                let parent_pid = proc.parent().map(|p| p.as_u32()).unwrap_or(0);

                let parent_image = proc
                    .parent()
                    .and_then(|ppid| sys.process(ppid))
                    .and_then(|p| p.exe())
                    .map(|p| p.display().to_string())
                    .unwrap_or_default();

                let kind = EventKind::Process {
                    pid: pid_u32,
                    parent_pid,
                    image,
                    parent_image,
                    command_line,
                };
                if tx.send(SecurityEvent::new(event_id, kind)).await.is_err() {
                    return Ok(());
                }
                event_id += 1;
            }

            tokio::time::sleep(self.poll_interval).await;
        }
    }
}
