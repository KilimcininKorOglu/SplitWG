//! `splitwg.log` tail follower — background thread reads new bytes into a
//! bounded `VecDeque`, the Logs tab renders the buffer.
//!
//! Simpler than `tail -f` because the file is only ever appended to by our
//! own `FileLogger` and never rotated on macOS. We seek from the last
//! offset on each tick (1 s polling) and push complete lines into the
//! shared buffer.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::config;

const BUFFER_CAPACITY: usize = 500;

pub struct LogTail {
    pub buffer: Arc<Mutex<VecDeque<String>>>,
}

impl Default for LogTail {
    fn default() -> Self {
        Self::new()
    }
}

impl LogTail {
    pub fn new() -> Self {
        let buffer: Arc<Mutex<VecDeque<String>>> =
            Arc::new(Mutex::new(VecDeque::with_capacity(BUFFER_CAPACITY)));
        let buf_clone = buffer.clone();

        thread::spawn(move || {
            let path: PathBuf = config::config_dir().join("splitwg.log");
            let mut last_pos: u64 = 0;
            loop {
                if let Ok(mut f) = File::open(&path) {
                    let len = f
                        .metadata()
                        .map(|m| m.len())
                        .unwrap_or(0);
                    if len < last_pos {
                        // File was truncated or replaced — rewind.
                        last_pos = 0;
                    }
                    if len > last_pos {
                        let _ = f.seek(SeekFrom::Start(last_pos));
                        let mut reader = BufReader::new(&mut f);
                        loop {
                            let mut line = String::new();
                            match reader.read_line(&mut line) {
                                Ok(0) => break,
                                Ok(n) => {
                                    last_pos += n as u64;
                                    let trimmed = line.trim_end().to_string();
                                    if trimmed.is_empty() {
                                        continue;
                                    }
                                    if let Ok(mut buf) = buf_clone.lock() {
                                        if buf.len() >= BUFFER_CAPACITY {
                                            buf.pop_front();
                                        }
                                        buf.push_back(trimmed);
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                    }
                }
                thread::sleep(Duration::from_secs(1));
            }
        });

        LogTail { buffer }
    }

    /// Returns a snapshot of the current buffer, optionally filtered to
    /// lines mentioning `needle` (case-insensitive).
    pub fn snapshot(&self, needle: Option<&str>) -> Vec<String> {
        let Ok(buf) = self.buffer.lock() else {
            return Vec::new();
        };
        match needle {
            None => buf.iter().cloned().collect(),
            Some(n) => {
                let n_lc = n.to_ascii_lowercase();
                buf.iter()
                    .filter(|l| l.to_ascii_lowercase().contains(&n_lc))
                    .cloned()
                    .collect()
            }
        }
    }
}
