use crate::event::SecurityEvent;
use tokio::sync::mpsc;

pub type EventSender = mpsc::Sender<SecurityEvent>;

#[async_trait::async_trait]
pub trait Collector: Send + Sync {
    fn name(&self) -> &'static str;
    async fn run(&self, tx: EventSender) -> anyhow::Result<()>;
}

pub struct EventBus {
    tx: EventSender,
    rx: mpsc::Receiver<SecurityEvent>,
}

impl EventBus {
    pub fn new(buffer: usize) -> Self {
        let (tx, rx) = mpsc::channel(buffer);
        Self { tx, rx }
    }

    pub fn sender(&self) -> EventSender {
        self.tx.clone()
    }

    pub async fn recv(&mut self) -> Option<SecurityEvent> {
        self.rx.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{EventKind, SecurityEvent};

    struct MockCollector;

    #[async_trait::async_trait]
    impl Collector for MockCollector {
        fn name(&self) -> &'static str {
            "mock"
        }

        async fn run(&self, tx: EventSender) -> anyhow::Result<()> {
            for i in 0u64..3 {
                let event = SecurityEvent::new(
                    i,
                    EventKind::Usb {
                        device_id: format!("USB{i}"),
                        device_class: "MassStorage".to_string(),
                    },
                );
                tx.send(event).await?;
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn event_bus_receives_all_collector_events() {
        let mut bus = EventBus::new(16);
        let tx = bus.sender();

        let collector = MockCollector;
        tokio::spawn(async move {
            collector.run(tx).await.unwrap();
        });

        let mut received = Vec::new();
        while let Ok(event) =
            tokio::time::timeout(std::time::Duration::from_millis(100), bus.recv()).await
        {
            match event {
                Some(e) => received.push(e.id),
                None => break,
            }
        }

        assert_eq!(received, vec![0, 1, 2]);
    }
}
