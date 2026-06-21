use crate::event::SecurityEvent;

#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub rule_id: String,
    pub rule_name: String,
    pub score: u32,
    pub category: String,
    pub mitre: Option<String>,
    pub recommended_action: String,
}

pub trait RuleEngine: Send + Sync {
    fn evaluate(&self, event: &SecurityEvent) -> Vec<RuleMatch>;
}
