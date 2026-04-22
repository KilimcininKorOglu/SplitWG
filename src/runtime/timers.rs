//! 250 ms ticker that drives gotatun's internal timers (handshake retry,
//! persistent keepalive, rekey, session expiry).

use std::sync::Arc;
use std::time::Duration;

use gotatun::noise::Tunn;
use gotatun::packet::Packet;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::interval;

use super::transport::WgTransport;

const TIMER_TICK: Duration = Duration::from_millis(250);

pub fn spawn_timer_loop(tunn: Arc<Mutex<Tunn>>, transport: Arc<dyn WgTransport>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = interval(TIMER_TICK);
        loop {
            ticker.tick().await;
            let to_send = {
                let mut t = tunn.lock().await;
                match t.update_timers() {
                    Ok(Some(wg)) => {
                        let pkt: Packet = Packet::from(wg);
                        Some(pkt.to_vec())
                    }
                    Ok(None) => None,
                    Err(e) => {
                        eprintln!("splitwg-helper: update_timers: {e:?}");
                        None
                    }
                }
            };
            if let Some(bytes) = to_send {
                if let Err(e) = transport.send(&bytes).await {
                    eprintln!("splitwg-helper: transport send (timer): {e}");
                }
            }
        }
    })
}
