use crate::event::{EventKind, SecurityEvent};
use crate::rule_engine::{RuleEngine, RuleMatch};
use crate::rules::schema::{ConditionOp, RuleDef};

pub struct TomlRuleEngine {
    rules: Vec<RuleDef>,
}

impl TomlRuleEngine {
    pub fn new(rules: Vec<RuleDef>) -> Self {
        Self { rules }
    }
}

impl RuleEngine for TomlRuleEngine {
    fn evaluate(&self, event: &SecurityEvent) -> Vec<RuleMatch> {
        self.rules
            .iter()
            .filter_map(|rule| {
                if rule_matches(rule, event) {
                    Some(RuleMatch {
                        rule_id: rule.id.clone(),
                        rule_name: rule.name.clone(),
                        score: rule.score,
                        category: rule.category.clone(),
                        mitre: rule.mitre.clone(),
                        recommended_action: rule.recommended_action.clone(),
                    })
                } else {
                    None
                }
            })
            .collect()
    }
}

fn rule_matches(rule: &RuleDef, event: &SecurityEvent) -> bool {
    if rule.conditions.is_empty() {
        return false;
    }
    let fields = extract_fields(event);
    let or_mode = rule.match_mode == "any";

    let mut matched = 0usize;
    for cond in &rule.conditions {
        let field_val = fields
            .iter()
            .find(|(k, _)| *k == cond.field.as_str())
            .map(|(_, v)| v.as_str())
            .unwrap_or("");

        let ok = eval_condition(&cond.op, field_val, &cond.value);
        if ok {
            matched += 1;
            if or_mode {
                return true;
            }
        } else if !or_mode {
            return false;
        }
    }

    if or_mode {
        false
    } else {
        matched == rule.conditions.len()
    }
}

fn eval_condition(op: &ConditionOp, field: &str, value: &str) -> bool {
    let field_lower = field.to_lowercase();
    let value_lower = value.to_lowercase();
    match op {
        ConditionOp::Contains => field_lower.contains(value_lower.as_str()),
        ConditionOp::NotContains => !field_lower.contains(value_lower.as_str()),
        ConditionOp::Equals => field_lower == value_lower,
        ConditionOp::NotEquals => field_lower != value_lower,
        ConditionOp::StartsWith => field_lower.starts_with(value_lower.as_str()),
        ConditionOp::EndsWith => field_lower.ends_with(value_lower.as_str()),
        ConditionOp::Gt => {
            let f: f64 = field.parse().unwrap_or(0.0);
            let v: f64 = value.parse().unwrap_or(0.0);
            f > v
        }
        ConditionOp::Lt => {
            let f: f64 = field.parse().unwrap_or(0.0);
            let v: f64 = value.parse().unwrap_or(0.0);
            f < v
        }
        ConditionOp::Eq => {
            let f: f64 = field.parse().unwrap_or(0.0);
            let v: f64 = value.parse().unwrap_or(0.0);
            (f - v).abs() < f64::EPSILON
        }
    }
}

/// Flatten SecurityEvent fields into (key, value) pairs for condition matching.
fn extract_fields(event: &SecurityEvent) -> Vec<(&'static str, String)> {
    match &event.kind {
        EventKind::Process {
            pid,
            parent_pid,
            image,
            parent_image,
            command_line,
        } => vec![
            ("process.pid", pid.to_string()),
            ("process.parent_pid", parent_pid.to_string()),
            ("process.image", image.clone()),
            ("process.parent_image", parent_image.clone()),
            ("process.command_line", command_line.clone()),
        ],
        EventKind::FileSystem {
            path,
            event_type,
            entropy_estimate,
        } => vec![
            ("fs.path", path.clone()),
            ("fs.event_type", format!("{event_type:?}").to_lowercase()),
            (
                "fs.entropy",
                entropy_estimate.map(|e| e.to_string()).unwrap_or_default(),
            ),
        ],
        EventKind::Network {
            pid,
            dst_ip,
            dst_port,
            protocol,
            bytes_sent,
            bytes_recv,
        } => vec![
            ("network.pid", pid.to_string()),
            ("network.dst_ip", dst_ip.clone()),
            ("network.dst_port", dst_port.to_string()),
            ("network.protocol", protocol.clone()),
            ("network.bytes_sent", bytes_sent.to_string()),
            ("network.bytes_recv", bytes_recv.to_string()),
        ],
        EventKind::Registry {
            key,
            value_name,
            operation,
        } => vec![
            ("registry.key", key.clone()),
            ("registry.value_name", value_name.clone()),
            (
                "registry.operation",
                format!("{operation:?}").to_lowercase(),
            ),
        ],
        EventKind::Usb {
            device_id,
            device_class,
        } => vec![
            ("usb.device_id", device_id.clone()),
            ("usb.device_class", device_class.clone()),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{EventKind, SecurityEvent};
    use crate::rules::schema::{Condition, ConditionOp, RuleDef};

    fn make_rule(id: &str, field: &str, op: ConditionOp, value: &str, score: u32) -> RuleDef {
        RuleDef {
            id: id.to_string(),
            name: id.to_string(),
            score,
            category: "test".to_string(),
            mitre: None,
            recommended_action: "alert".to_string(),
            conditions: vec![Condition {
                field: field.to_string(),
                op,
                value: value.to_string(),
            }],
            match_mode: "all".to_string(),
        }
    }

    #[test]
    fn matches_powershell_encoded_command() {
        let engine = TomlRuleEngine::new(vec![make_rule(
            "PROC-001",
            "process.command_line",
            ConditionOp::Contains,
            "-EncodedCommand",
            80,
        )]);
        let event = SecurityEvent::new(
            0,
            EventKind::Process {
                pid: 1234,
                parent_pid: 1,
                image: "powershell.exe".to_string(),
                parent_image: String::new(),
                command_line: "powershell.exe -EncodedCommand SQBFAFgA".to_string(),
            },
        );
        let matches = engine.evaluate(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_id, "PROC-001");
        assert_eq!(matches[0].score, 80);
    }

    #[test]
    fn no_match_on_benign_process() {
        let engine = TomlRuleEngine::new(vec![make_rule(
            "PROC-001",
            "process.command_line",
            ConditionOp::Contains,
            "-EncodedCommand",
            80,
        )]);
        let event = SecurityEvent::new(
            0,
            EventKind::Process {
                pid: 1,
                parent_pid: 0,
                image: "explorer.exe".to_string(),
                parent_image: String::new(),
                command_line: "explorer.exe".to_string(),
            },
        );
        assert!(engine.evaluate(&event).is_empty());
    }

    #[test]
    fn or_mode_matches_any_condition() {
        let rule = RuleDef {
            id: "NET-001".to_string(),
            name: "Suspicious Port".to_string(),
            score: 60,
            category: "network".to_string(),
            mitre: None,
            recommended_action: "alert".to_string(),
            conditions: vec![
                Condition {
                    field: "network.dst_port".to_string(),
                    op: ConditionOp::Eq,
                    value: "4444".to_string(),
                },
                Condition {
                    field: "network.dst_port".to_string(),
                    op: ConditionOp::Eq,
                    value: "1337".to_string(),
                },
            ],
            match_mode: "any".to_string(),
        };
        let engine = TomlRuleEngine::new(vec![rule]);
        let event = SecurityEvent::new(
            0,
            EventKind::Network {
                pid: 0,
                dst_ip: "1.2.3.4".to_string(),
                dst_port: 4444,
                protocol: "tcp".to_string(),
                bytes_sent: 0,
                bytes_recv: 0,
            },
        );
        let matches = engine.evaluate(&event);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn suspicious_script_extension_matches() {
        let engine = TomlRuleEngine::new(vec![make_rule(
            "FS-001",
            "fs.path",
            ConditionOp::EndsWith,
            ".ps1",
            50,
        )]);
        let event = SecurityEvent::new(
            0,
            EventKind::FileSystem {
                path: r"C:\Users\victim\AppData\Roaming\evil.ps1".to_string(),
                event_type: crate::event::FsEventType::Created,
                entropy_estimate: None,
            },
        );
        let matches = engine.evaluate(&event);
        assert_eq!(matches.len(), 1);
    }
}
