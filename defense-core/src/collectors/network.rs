use std::collections::HashSet;
use std::time::Duration;

use async_trait::async_trait;
use sysinfo::Networks;

use crate::collector::{Collector, EventSender};
use crate::event::{EventKind, SecurityEvent};

pub struct NetworkCollector {
    pub poll_interval: Duration,
}

impl Default for NetworkCollector {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(5),
        }
    }
}

#[async_trait]
impl Collector for NetworkCollector {
    fn name(&self) -> &'static str {
        "network"
    }

    async fn run(&self, tx: EventSender) -> anyhow::Result<()> {
        let mut event_id: u64 = 0;
        let mut networks = Networks::new_with_refreshed_list();
        // Track (interface, bytes_sent, bytes_recv) to detect new traffic
        let mut seen_interfaces: HashSet<String> = HashSet::new();

        loop {
            networks.refresh(true);

            for (name, data) in &networks {
                if seen_interfaces.contains(name) {
                    continue;
                }
                seen_interfaces.insert(name.clone());

                // Emit a synthetic network event per new interface seen
                let kind = EventKind::Network {
                    pid: 0,
                    dst_ip: String::new(),
                    dst_port: 0,
                    protocol: "unknown".to_string(),
                    bytes_sent: data.total_transmitted(),
                    bytes_recv: data.total_received(),
                };
                if tx.send(SecurityEvent::new(event_id, kind)).await.is_err() {
                    return Ok(());
                }
                event_id += 1;
            }

            // Emit connection-level events by parsing system network state
            for event in active_connections(event_id) {
                event_id += 1;
                if tx.send(event).await.is_err() {
                    return Ok(());
                }
            }

            tokio::time::sleep(self.poll_interval).await;
        }
    }
}

fn active_connections(base_id: u64) -> Vec<SecurityEvent> {
    #[cfg(target_os = "linux")]
    {
        let mut events = Vec::new();
        let mut id = base_id;
        if let Ok(content) = std::fs::read_to_string("/proc/net/tcp") {
            for line in content.lines().skip(1) {
                if let Some(event) = parse_proc_net_tcp_line(line, id) {
                    events.push(event);
                    id += 1;
                }
            }
        }
        return events;
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = base_id;
        Vec::new()
    }
}

#[cfg(target_os = "linux")]
fn parse_proc_net_tcp_line(line: &str, id: u64) -> Option<SecurityEvent> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 4 {
        return None;
    }
    // state 01 = ESTABLISHED
    if fields[3] != "01" {
        return None;
    }
    let remote_hex = fields[2];
    let (ip, port) = parse_hex_addr(remote_hex)?;
    if ip == "00000000" {
        return None;
    }
    let dst_ip = hex_to_ipv4(ip)?;
    let dst_port = u16::from_str_radix(port, 16).ok()?;

    Some(SecurityEvent::new(
        id,
        EventKind::Network {
            pid: 0,
            dst_ip,
            dst_port,
            protocol: "tcp".to_string(),
            bytes_sent: 0,
            bytes_recv: 0,
        },
    ))
}

#[cfg(target_os = "linux")]
fn parse_hex_addr(s: &str) -> Option<(&str, &str)> {
    let colon = s.find(':')?;
    Some((&s[..colon], &s[colon + 1..]))
}

#[cfg(target_os = "linux")]
fn hex_to_ipv4(hex: &str) -> Option<String> {
    if hex.len() != 8 {
        return None;
    }
    let n = u32::from_str_radix(hex, 16).ok()?;
    let b = n.to_le_bytes();
    Some(format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]))
}
