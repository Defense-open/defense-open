use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct RuleFile {
    #[serde(default)]
    pub rules: Vec<RuleDef>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuleDef {
    pub id: String,
    pub name: String,
    pub score: u32,
    pub category: String,
    #[serde(default)]
    pub mitre: Option<String>,
    pub recommended_action: String,
    #[serde(default)]
    pub conditions: Vec<Condition>,
    /// "all" (default) = AND logic, "any" = OR logic
    #[serde(default = "default_match_mode")]
    pub match_mode: String,
}

fn default_match_mode() -> String {
    "all".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct Condition {
    /// Field path: "process.image", "process.command_line",
    /// "fs.path", "fs.event_type",
    /// "network.dst_port", "network.dst_ip", "network.protocol",
    /// "registry.key", "registry.value_name", "registry.operation",
    /// "usb.device_id", "usb.device_class"
    pub field: String,
    pub op: ConditionOp,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConditionOp {
    Contains,
    NotContains,
    Equals,
    NotEquals,
    StartsWith,
    EndsWith,
    /// Numeric: greater than
    Gt,
    /// Numeric: less than
    Lt,
    /// Numeric: equals
    Eq,
}
