//! Tiny sparkline widget painted directly with `egui::Painter`.
//!
//! Used by the Status tab to show the last 60 seconds of RX/TX throughput
//! for the selected tunnel. Values are normalised against a sliding-window
//! max so a one-off burst does not permanently flatten the graph.

use std::collections::VecDeque;
use std::time::Instant;

/// Max number of samples retained per direction (one sample per second →
/// one minute of history).
pub const CAPACITY: usize = 60;

/// Rolling history of per-second RX/TX deltas for a single tunnel.
#[derive(Debug)]
pub struct TransferHistory {
    pub rx_samples: VecDeque<f32>,
    pub tx_samples: VecDeque<f32>,
    pub last_rx: u64,
    pub last_tx: u64,
    pub last_ts: Instant,
}

impl TransferHistory {
    pub fn new(rx: u64, tx: u64) -> Self {
        TransferHistory {
            rx_samples: VecDeque::with_capacity(CAPACITY),
            tx_samples: VecDeque::with_capacity(CAPACITY),
            last_rx: rx,
            last_tx: tx,
            last_ts: Instant::now(),
        }
    }

    /// Pushes a new snapshot and returns the per-second rates (bytes/sec).
    /// When `dt` is zero the existing rates are preserved to avoid divide-
    /// by-zero spikes on duplicate reads.
    pub fn record(&mut self, rx: u64, tx: u64) -> (f32, f32) {
        let now = Instant::now();
        let dt = now.duration_since(self.last_ts).as_secs_f32().max(0.001);
        let rx_rate = (rx.saturating_sub(self.last_rx)) as f32 / dt;
        let tx_rate = (tx.saturating_sub(self.last_tx)) as f32 / dt;

        if self.rx_samples.len() == CAPACITY {
            self.rx_samples.pop_front();
        }
        if self.tx_samples.len() == CAPACITY {
            self.tx_samples.pop_front();
        }
        self.rx_samples.push_back(rx_rate);
        self.tx_samples.push_back(tx_rate);

        self.last_rx = rx;
        self.last_tx = tx;
        self.last_ts = now;
        (rx_rate, tx_rate)
    }

    /// Latest rate without mutating state. Returns `(rx, tx)` in bytes/sec.
    pub fn latest(&self) -> (f32, f32) {
        (
            self.rx_samples.back().copied().unwrap_or(0.0),
            self.tx_samples.back().copied().unwrap_or(0.0),
        )
    }
}

/// Rolling RTT history for a single tunnel. Samples are milliseconds; a
/// timeout pushes `0.0` so the sparkline shows a floor dip rather than a
/// gap. `last_ms` keeps the most recent *successful* measurement so the
/// UI can surface a meaningful number during a transient timeout burst.
#[derive(Debug)]
pub struct RttHistory {
    pub samples: VecDeque<f32>,
    pub last_ms: Option<u32>,
    pub last_was_timeout: bool,
    pub last_ts: Instant,
}

impl Default for RttHistory {
    fn default() -> Self {
        Self::new()
    }
}

impl RttHistory {
    pub fn new() -> Self {
        RttHistory {
            samples: VecDeque::with_capacity(CAPACITY),
            last_ms: None,
            last_was_timeout: false,
            last_ts: Instant::now(),
        }
    }

    /// Pushes a new ping result. `None` = timeout (`0.0` sample,
    /// `last_was_timeout = true`, `last_ms` preserved). `Some(ms)` = success
    /// (`ms` sample, `last_was_timeout = false`, `last_ms` updated).
    pub fn record(&mut self, result: Option<u32>) {
        if self.samples.len() == CAPACITY {
            self.samples.pop_front();
        }
        match result {
            Some(ms) => {
                self.samples.push_back(ms as f32);
                self.last_ms = Some(ms);
                self.last_was_timeout = false;
            }
            None => {
                self.samples.push_back(0.0);
                self.last_was_timeout = true;
            }
        }
        self.last_ts = Instant::now();
    }

    /// Latest *successful* RTT. Returns `None` until the first success.
    pub fn latest(&self) -> Option<u32> {
        self.last_ms
    }
}

/// One-shot sparkline widget. `values` is rendered left-to-right, scaled to
/// fit `size`. Empty input renders a faint baseline.
pub struct Sparkline<'a> {
    pub values: &'a VecDeque<f32>,
    pub size: egui::Vec2,
    pub color: egui::Color32,
}

impl<'a> Sparkline<'a> {
    pub fn show(self, ui: &mut egui::Ui) -> egui::Response {
        let (response, painter) =
            ui.allocate_painter(self.size, egui::Sense::hover());
        let rect = response.rect;

        // Subtle baseline so the widget has a visible extent even when idle.
        let baseline = ui.visuals().weak_text_color().gamma_multiply(0.35);
        painter.line_segment(
            [rect.left_bottom(), rect.right_bottom()],
            egui::Stroke::new(1.0, baseline),
        );

        if self.values.is_empty() {
            return response;
        }

        // Sliding-window max keeps the graph responsive to current activity.
        // Floor at 1.0 so zero-traffic windows don't blow up the normaliser.
        let max = self
            .values
            .iter()
            .copied()
            .fold(0.0f32, f32::max)
            .max(1.0);

        let n = self.values.len();
        let x_step = if n > 1 {
            rect.width() / (CAPACITY.saturating_sub(1)).max(1) as f32
        } else {
            0.0
        };
        let x_offset = rect.right() - x_step * (n.saturating_sub(1)) as f32;

        let mut prev: Option<egui::Pos2> = None;
        for (i, v) in self.values.iter().enumerate() {
            let x = x_offset + x_step * i as f32;
            let y = rect.bottom() - (v / max) * rect.height();
            let pos = egui::pos2(x, y);
            if let Some(p) = prev {
                painter.line_segment(
                    [p, pos],
                    egui::Stroke::new(1.2, self.color),
                );
            }
            prev = Some(pos);
        }

        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_computes_rates_and_caps_capacity() {
        let mut h = TransferHistory::new(0, 0);
        for i in 1..=65u64 {
            h.record(i * 1000, i * 500);
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(h.rx_samples.len(), CAPACITY);
        assert_eq!(h.tx_samples.len(), CAPACITY);
        assert!(h.latest().0 > 0.0);
    }

    #[test]
    fn record_handles_counter_reset() {
        let mut h = TransferHistory::new(10_000, 5_000);
        let (rx, _) = h.record(5_000, 2_000);
        // Counter went backwards — saturating_sub yields zero, no panic.
        assert_eq!(rx, 0.0);
    }

    #[test]
    fn rtt_record_caps_capacity() {
        let mut h = RttHistory::new();
        for _ in 0..(CAPACITY + 5) {
            h.record(Some(10));
        }
        assert_eq!(h.samples.len(), CAPACITY);
        assert_eq!(h.latest(), Some(10));
    }

    #[test]
    fn rtt_timeout_preserves_last_ms() {
        let mut h = RttHistory::new();
        h.record(Some(42));
        h.record(None);
        assert_eq!(h.samples.back().copied(), Some(0.0));
        assert!(h.last_was_timeout);
        // `last_ms` survives a timeout so the UI can keep showing the
        // previous numeric reading alongside the "timeout" label.
        assert_eq!(h.latest(), Some(42));
    }

    #[test]
    fn rtt_success_clears_timeout_flag() {
        let mut h = RttHistory::new();
        h.record(None);
        h.record(Some(20));
        assert!(!h.last_was_timeout);
        assert_eq!(h.latest(), Some(20));
        assert_eq!(h.samples.back().copied(), Some(20.0));
    }
}
