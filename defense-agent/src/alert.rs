use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::Result;
use chrono::Utc;
use serde::Serialize;

use defense_core::event::{EventKind, SecurityEvent};
use defense_core::rule_engine::RuleMatch;

#[derive(Serialize)]
pub struct Alert<'a> {
    pub timestamp: String,
    pub event_id: u64,
    pub rule_id: &'a str,
    pub rule_name: &'a str,
    pub score: u32,
    pub category: &'a str,
    pub mitre: Option<&'a str>,
    pub recommended_action: &'a str,
    pub event: EventSummary<'a>,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventSummary<'a> {
    Process {
        pid: u32,
        image: &'a str,
        command_line: &'a str,
    },
    FileSystem {
        path: &'a str,
        event_type: String,
    },
    Network {
        dst_ip: &'a str,
        dst_port: u16,
        protocol: &'a str,
        bytes_sent: u64,
    },
    Registry {
        key: &'a str,
        value_name: &'a str,
        operation: String,
    },
    Usb {
        device_id: &'a str,
        device_class: &'a str,
    },
}

enum Output {
    Stdout,
    File(Mutex<BufWriter<File>>),
}

pub struct AlertSink {
    output: Output,
}

impl AlertSink {
    pub fn new(path: Option<PathBuf>) -> Result<Self> {
        let output = match path {
            Some(p) => {
                let file = OpenOptions::new().create(true).append(true).open(p)?;
                Output::File(Mutex::new(BufWriter::new(file)))
            }
            None => Output::Stdout,
        };
        Ok(Self { output })
    }

    pub fn emit(&self, event: &SecurityEvent, matches: &[RuleMatch]) -> Result<()> {
        let ts = Utc::now().to_rfc3339();

        for m in matches {
            let alert = Alert {
                timestamp: ts.clone(),
                event_id: event.id,
                rule_id: &m.rule_id,
                rule_name: &m.rule_name,
                score: m.score,
                category: &m.category,
                mitre: m.mitre.as_deref(),
                recommended_action: &m.recommended_action,
                event: event_summary(event),
            };
            let line = serde_json::to_string(&alert)?;
            self.write_line(&line)?;
        }
        Ok(())
    }

    fn write_line(&self, line: &str) -> Result<()> {
        match &self.output {
            Output::Stdout => {
                let stdout = io::stdout();
                let mut lock = stdout.lock();
                writeln!(lock, "{line}")?;
            }
            Output::File(mutex) => {
                let mut w = mutex.lock().unwrap();
                writeln!(w, "{line}")?;
                w.flush()?;
            }
        }
        Ok(())
    }
}

fn event_summary(event: &SecurityEvent) -> EventSummary<'_> {
    match &event.kind {
        EventKind::Process {
            pid,
            image,
            command_line,
            ..
        } => EventSummary::Process {
            pid: *pid,
            image,
            command_line,
        },
        EventKind::FileSystem {
            path, event_type, ..
        } => EventSummary::FileSystem {
            path,
            event_type: format!("{event_type:?}"),
        },
        EventKind::Network {
            dst_ip,
            dst_port,
            protocol,
            bytes_sent,
            ..
        } => EventSummary::Network {
            dst_ip,
            dst_port: *dst_port,
            protocol,
            bytes_sent: *bytes_sent,
        },
        EventKind::Registry {
            key,
            value_name,
            operation,
        } => EventSummary::Registry {
            key,
            value_name,
            operation: format!("{operation:?}"),
        },
        EventKind::Usb {
            device_id,
            device_class,
        } => EventSummary::Usb {
            device_id,
            device_class,
        },
    }
}
