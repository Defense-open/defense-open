use crate::{event::SecurityEvent, rule_engine::RuleMatch};

pub trait EventSink: Send + Sync {
    fn handle(&self, event: &SecurityEvent, matches: &[RuleMatch]);
}
