//! SplitWG binary entry point.
//!
//! Sets up file logging and hands control to the tray event loop.

use std::fs::OpenOptions;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::sync::Mutex;

use splitwg::{config, gui, i18n};

/// Minimal file logger that writes `splitwg: <level>: <msg>` lines to
/// `<ConfigDir>/splitwg.log`. Stderr mirroring is partial by default
/// (WARN+ only, plus everything when `SPLITWG_LOG_STDERR=full`): mirroring
/// every info line duplicated every write syscall and pushed the log to
/// 67 MB in 11 days when combined with a chatty source.
struct FileLogger {
    file: Mutex<Option<std::fs::File>>,
}

impl log::Log for FileLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        let target = metadata.target();
        if target.starts_with("wgpu") || target.starts_with("naga") {
            return metadata.level() <= log::Level::Warn;
        }
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
        // Mirror to stderr: always for WARN/ERROR (visible in terminal
        // runs), for everything only when explicitly requested.
        static MIRROR: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        let mirror_all = *MIRROR.get_or_init(|| {
            std::env::var("SPLITWG_LOG_STDERR")
                .map(|v| v.eq_ignore_ascii_case("full"))
                .unwrap_or(false)
        });
        if mirror_all || record.level() >= log::Level::Warn {
            let _ = std::io::stderr().write_all(line.as_bytes());
        }
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
        // Startup rotation: the log is append-only and never rotated at
        // runtime, so an earlier runaway (a warning logged hundreds of times
        // per second) grew it to 67 MB. Cap it here: everything over 10 MiB
        // is moved to `splitwg.log.1` (replacing the previous one). The Logs
        // tab follower seeks by offset and rewinds when the file shrinks, so
        // a truncated/rotated file is picked up on its next 1 s tick.
        if let Ok(meta) = std::fs::metadata(&path) {
            if meta.len() > 10 * 1024 * 1024 {
                let old = config::config_dir().join("splitwg.log.1");
                let _ = std::fs::remove_file(&old);
                let _ = std::fs::rename(&path, &old);
            }
        }
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        opts.mode(0o600);
        opts.open(path).ok()
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
