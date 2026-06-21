use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use flate2::write::GzEncoder;
use flate2::Compression;

const MAX_BYTES: u64 = 10 * 1024 * 1024; // 10 MB

pub struct RotatingLog {
    dir: PathBuf,
    current: PathBuf,
    file: File,
}

impl RotatingLog {
    pub fn open(dir: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        let current = dir.join(today_filename());
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&current)?;
        Ok(Self { dir, current, file })
    }

    pub fn write_line(&mut self, line: &str) -> anyhow::Result<()> {
        self.rotate_if_needed()?;
        writeln!(self.file, "{line}")?;
        Ok(())
    }

    fn rotate_if_needed(&mut self) -> anyhow::Result<()> {
        let size = self.file.metadata()?.len();
        let new_name = today_filename();
        let new_path = self.dir.join(&new_name);

        if size >= MAX_BYTES || new_path != self.current {
            compress_and_remove(&self.current)?;
            self.current = new_path;
            self.file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.current)?;
        }
        Ok(())
    }
}

fn today_filename() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // YYYY-MM-DD from Unix timestamp (no chrono dep yet)
    let days = secs / 86400;
    let (y, m, d) = days_to_ymd(days);
    format!("log_{y:04}-{m:02}-{d:02}.txt")
}

fn compress_and_remove(path: &Path) -> anyhow::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let gz_path = path.with_extension("txt.gz");
    let input = File::open(path)?;
    let mut reader = BufReader::new(input);
    let output = File::create(&gz_path)?;
    let mut encoder = GzEncoder::new(output, Compression::best());
    std::io::copy(&mut reader, &mut encoder)?;
    encoder.finish()?;
    fs::remove_file(path)?;
    Ok(())
}

// Minimal Gregorian calendar from day count (no external dep)
fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    // Days since 1970-01-01
    let mut year = 1970u64;
    loop {
        let dy = if is_leap(year) { 366 } else { 365 };
        if days < dy {
            break;
        }
        days -= dy;
        year += 1;
    }
    let months = if is_leap(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 1u64;
    for dm in months {
        if days < dm {
            break;
        }
        days -= dm;
        month += 1;
    }
    (year, month, days + 1)
}

fn is_leap(y: u64) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn write_and_file_exists() {
        let dir = tempdir().unwrap();
        let mut log = RotatingLog::open(dir.path()).unwrap();
        log.write_line("hello defense").unwrap();
        assert!(log.current.exists());
        let content = fs::read_to_string(&log.current).unwrap();
        assert!(content.contains("hello defense"));
    }

    #[test]
    fn rotation_compresses_when_size_exceeded() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join(today_filename());
        let big_content = "x".repeat((MAX_BYTES + 1) as usize);
        fs::write(&log_path, &big_content).unwrap();

        let mut log = RotatingLog::open(dir.path()).unwrap();
        log.write_line("trigger").unwrap();

        // After rotation: gz archive exists, new empty log file re-created
        let gz_path = log_path.with_extension("txt.gz");
        assert!(gz_path.exists(), "gz file should exist after rotation");
        // The new log file is recreated at the same path for continued writing
        assert!(log_path.exists(), "new log file should be open for writing");
        assert!(
            fs::metadata(&log_path).unwrap().len() < MAX_BYTES,
            "new log file should be small (just the trigger line)"
        );
    }

    #[test]
    fn days_to_ymd_epoch() {
        assert_eq!(days_to_ymd(0), (1970, 1, 1));
    }

    #[test]
    fn days_to_ymd_known_date() {
        // 2026-06-21 = 20625 days since 1970-01-01
        let (y, m, d) = days_to_ymd(20625);
        assert_eq!((y, m, d), (2026, 6, 21));
    }
}
