//! SplitWG binary entry point.
//!
//! Sets up file logging and hands control to the tray event loop.

use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;

use splitwg::{config, gui, i18n};

/// Minimal file logger that writes `splitwg: <level>: <msg>\n` lines to
/// `<ConfigDir>/splitwg.log` and to stderr.
struct FileLogger {
    file: Mutex<Option<std::fs::File>>,
}

impl log::Log for FileLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Info
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let line = format!(
            "{} splitwg: {}: {}\n",
            timestamp_utc(),
            record.level().to_string().to_lowercase(),
            record.args(),
        );
        if let Ok(mut guard) = self.file.lock() {
            if let Some(f) = guard.as_mut() {
                let _ = f.write_all(line.as_bytes());
            }
        }
        let _ = std::io::stderr().write_all(line.as_bytes());
    }

    fn flush(&self) {
        if let Ok(mut guard) = self.file.lock() {
            if let Some(f) = guard.as_mut() {
                let _ = f.flush();
            }
        }
    }
}

/// Timestamp formatted as `YYYY/MM/DD HH:MM:SS` (UTC).
fn timestamp_utc() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (y, mo, d, h, mi, s) = utc_breakdown(secs);
    format!("{:04}/{:02}/{:02} {:02}:{:02}:{:02}", y, mo, d, h, mi, s)
}

fn utc_breakdown(mut t: u64) -> (i32, u32, u32, u32, u32, u32) {
    let second = (t % 60) as u32;
    t /= 60;
    let minute = (t % 60) as u32;
    t /= 60;
    let hour = (t % 24) as u32;
    t /= 24;
    let mut days = t as i64;

    let mut year: i32 = 1970;
    loop {
        let yd: i64 = if is_leap(year) { 366 } else { 365 };
        if days >= yd {
            days -= yd;
            year += 1;
        } else {
            break;
        }
    }
    let months = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month: u32 = 1;
    for (i, m) in months.iter().enumerate() {
        let mut dm = *m;
        if i == 1 && is_leap(year) {
            dm = 29;
        }
        if days >= dm {
            days -= dm;
            month += 1;
        } else {
            break;
        }
    }
    (year, month, (days + 1) as u32, hour, minute, second)
}

fn is_leap(y: i32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}

fn init_file_logging() {
    let file = config::ensure_config_dir().ok().and_then(|_| {
        let path = config::config_dir().join("splitwg.log");
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .ok()
    });
    let logger = Box::leak(Box::new(FileLogger {
        file: Mutex::new(file),
    }));
    let _ = log::set_logger(logger);
    log::set_max_level(log::LevelFilter::Info);
}

fn main() {
    init_file_logging();
    log::info!("main: splitwg starting");
    i18n::init();
    if let Err(e) = gui::run() {
        log::error!("main: gui exited with error: {}", e);
        std::process::exit(1);
    }
    log::info!("main: exited cleanly");
}
