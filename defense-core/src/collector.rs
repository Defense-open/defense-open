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
