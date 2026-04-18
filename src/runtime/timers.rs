//! 250 ms ticker that drives boringtun's internal timers (handshake retry,
//! persistent keepalive, rekey, session expiry).

use std::sync::Arc;
use std::time::Duration;

use boringtun::noise::{Tunn, TunnResult};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::interval;

const TIMER_TICK: Duration = Duration::from_millis(250);
const TIMER_DST_LEN: usize = 2048;

pub fn spawn_timer_loop(tunn: Arc<Mutex<Tunn>>, udp: Arc<UdpSocket>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = interval(TIMER_TICK);
        let mut dst = vec![0u8; TIMER_DST_LEN];
        loop {
            ticker.tick().await;
            let to_send = {
                let mut t = tunn.lock().await;
                match t.update_timers(&mut dst) {
                    TunnResult::WriteToNetwork(pkt) => Some(pkt.to_vec()),
                    TunnResult::Err(e) => {
                        eprintln!("splitwg-helper: update_timers: {e:?}");
                        None
                    }
                    _ => None,
                }
            };
            if let Some(bytes) = to_send {
                if let Err(e) = udp.send(&bytes).await {
                    eprintln!("splitwg-helper: udp send (timer): {e}");
                }
            }
        }
    })
}
