use std::time::SystemTime;

#[derive(Debug, Clone)]
pub enum EventKind {
    Process {
        pid: u32,
        parent_pid: u32,
        image: String,
        parent_image: String,
        command_line: String,
    },
    FileSystem {
        path: String,
        event_type: FsEventType,
        entropy_estimate: Option<f32>,
    },
    Network {
        pid: u32,
        dst_ip: String,
        dst_port: u16,
        protocol: String,
        bytes_sent: u64,
        bytes_recv: u64,
    },
    Registry {
        key: String,
        value_name: String,
        operation: RegistryOp,
    },
    Usb {
        device_id: String,
        device_class: String,
    },
}

#[derive(Debug, Clone)]
pub enum FsEventType {
    Created,
    Modified,
    Deleted,
    Renamed,
}

#[derive(Debug, Clone)]
pub enum RegistryOp {
    Set,
    Delete,
    Create,
}

#[derive(Debug, Clone)]
pub struct SecurityEvent {
    pub id: u64,
    pub timestamp: SystemTime,
    pub kind: EventKind,
}

impl SecurityEvent {
    pub fn new(id: u64, kind: EventKind) -> Self {
        Self {
            id,
            timestamp: SystemTime::now(),
            kind,
        }
    }
}
