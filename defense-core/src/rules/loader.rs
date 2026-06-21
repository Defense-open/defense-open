use std::path::Path;

use anyhow::Context;

use crate::rules::engine::TomlRuleEngine;
use crate::rules::schema::{RuleDef, RuleFile};

pub fn load_from_dir(dir: impl AsRef<Path>) -> anyhow::Result<TomlRuleEngine> {
    let dir = dir.as_ref();
    let mut rules: Vec<RuleDef> = Vec::new();

    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("rules dizini açılamadı: {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("kural dosyası okunamadı: {}", path.display()))?;
        let file: RuleFile = toml::from_str(&content)
            .with_context(|| format!("kural dosyası parse hatası: {}", path.display()))?;
        rules.extend(file.rules);
    }

    Ok(TomlRuleEngine::new(rules))
}

pub fn load_from_str(toml_content: &str) -> anyhow::Result<TomlRuleEngine> {
    let file: RuleFile = toml::from_str(toml_content)?;
    Ok(TomlRuleEngine::new(file.rules))
}
