use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Level::Info => write!(f, "INFO "),
            Level::Medium => write!(f, "MEDIUM"),
            Level::High => write!(f, "HIGH "),
            Level::Critical => write!(f, "CRIT "),
        }
    }
}

pub fn format_log_line(level: Level, category: &str, message: &str) -> String {
    let ts = iso8601_now();
    let message = mask_sensitive(message);
    format!("[{ts}] [{level}] [{category:<10}] {message}")
}

fn iso8601_now() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    format!("{secs}")
}

fn mask_sensitive(s: &str) -> String {
    let re_unix = regex::Regex::new(r"/home/[^/]+/").unwrap();
    let re_win = regex::Regex::new(r"(?i)C:\\Users\\[^\\]+\\").unwrap();
    let s = re_unix.replace_all(s, "/home/[USER]/");
    let s = re_win.replace_all(&s, r"C:\Users\[USER]\");
    s.into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_windows_user_path() {
        let line = mask_sensitive(r"C:\Users\JohnDoe\AppData\evil.exe");
        assert!(line.contains("[USER]"));
        assert!(!line.contains("JohnDoe"));
    }

    #[test]
    fn masks_unix_user_path() {
        let line = mask_sensitive("/home/johndoe/downloads/evil.sh");
        assert!(line.contains("[USER]"));
        assert!(!line.contains("johndoe"));
    }
}
