use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::{Arc, OnceLock, RwLock};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatMessage {
    NewBadIp { ip: String, reason: String },
    NewBadHash { hash: String, reason: String },
}

#[derive(Debug, Default)]
pub struct ThreatDatabase {
    pub bad_ips: RwLock<HashSet<String>>,
    pub bad_hashes: RwLock<HashSet<String>>,
}

impl ThreatDatabase {
    /// Küresel P2P Tehdit İstihbarat Veritabanının Singleton objesi
    pub fn global() -> &'static Arc<ThreatDatabase> {
        static THREAT_DB: OnceLock<Arc<ThreatDatabase>> = OnceLock::new();
        THREAT_DB.get_or_init(|| {
            let db = ThreatDatabase::default();
            // Varsayılan / Başlangıç Karalistesi (Daha sonra ağdan beslenecek)
            if let Ok(mut ips) = db.bad_ips.write() {
                ips.insert("185.15.247.140".to_string());
                ips.insert("93.184.216.34".to_string());
            }
            Arc::new(db)
        })
    }

    pub fn add_ip(&self, ip: String) {
        if let Ok(mut ips) = self.bad_ips.write() {
            ips.insert(ip);
        }
    }

    pub fn is_bad_ip(&self, ip: &str) -> bool {
        if let Ok(ips) = self.bad_ips.read() {
            ips.contains(ip)
        } else {
            false
        }
    }
}
