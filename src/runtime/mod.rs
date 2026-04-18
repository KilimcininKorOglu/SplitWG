//! Userspace WireGuard tunnel runtime — boringtun crypto state machine fed
//! by a macOS utun device (via tun2) and a UDP socket to the peer endpoint.
//!
//! All I/O is driven by three tokio tasks:
//!
//! 1. tun → udp : encapsulate plaintext IP packets from the utun.
//! 2. udp → tun : decapsulate ciphertext datagrams; flush queued packets
//!    whenever a WriteToNetwork is returned.
//! 3. timers    : 250 ms ticker that drives boringtun's rekey/keepalive.
//!
//! Shutdown is broadcast via a `watch::Receiver<bool>` — when set to true the
//! loops abort and the `AsyncDevice` / `UdpSocket` drop (utun closes).

use std::net::SocketAddr;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use ipnet::IpNet;
use tokio::net::UdpSocket;
use tokio::sync::{watch, Mutex};

use crate::ipc::{self, TunnelMode, UpParams};

/// Per-hook timeout. `PreUp` is fatal on timeout (bringup aborts); `PostUp`,
/// `PreDown`, `PostDown` are log-only. Not configurable — kept short enough
/// that a hang cannot indefinitely wedge a tunnel's lifecycle.
const HOOK_TIMEOUT: Duration = Duration::from_secs(30);

pub mod dns;
pub mod pf;
pub mod routing;
pub mod timers;

const MAX_PACKET: usize = 65_536;

/// Live tunnel state owned by the helper for a single `.conf`.
///
/// Ordering matters on drop: the background tasks abort first (tun + udp
/// dropped), then `dns` and `routes` remove their side-effects. Struct fields
/// drop in declaration order, so `routes` / `dns` live after `device` here.
pub struct Tunnel {
    pub iface: String,
    device: Arc<tun2::AsyncDevice>,
    udp: Arc<UdpSocket>,
    tunn: Arc<Mutex<Tunn>>,
    mtu: u16,
    /// Kill-switch pf anchor. Declared before `dns` and `routes` so the
    /// drop order flushes the anchor (unblocking non-tunnel traffic) before
    /// DNS gets restored and routes come down. `None` when the user has
    /// the kill switch disabled in Settings.
    #[allow(dead_code)]
    pf: Option<pf::PfAnchor>,
    // `dns` and `routes` only exist for their `Drop` side-effects; the
    // allow suppresses the dead-field lint.
    #[allow(dead_code)]
    dns: dns::Dns,
    #[allow(dead_code)]
    routes: routing::Routes,
    /// Hook commands stored for teardown — wg-quick writes PreDown/PostDown in
    /// the `.conf`; the helper needs them after `Shutdown` arrives.
    pre_down: Vec<String>,
    post_down: Vec<String>,
}

impl Tunnel {
    pub async fn bringup(params: &UpParams) -> Result<Self> {
        let static_secret = load_static_secret(&params.interface_key)?;
        let peer_public = load_peer_public(&params.peer_key)?;
        let psk = match &params.psk {
            Some(s) => Some(ipc::decode_key(s).map_err(|e| anyhow!("psk: {e}"))?),
            None => None,
        };

        // PreUp hooks — fired before the utun exists. wg-quick documents that
        // `%i` is *undefined* during PreUp; we follow suit by substituting an
        // empty string. A non-zero exit aborts bringup: the user explicitly
        // asked for this hook to gate connection.
        for cmd in &params.pre_up {
            run_hook("", cmd, HookPhase::PreUp).await?;
        }

        // tun2 auto-picks an available utunN name.
        let mut cfg = tun2::Configuration::default();
        cfg.mtu(params.mtu).up();
        let device = tun2::create_as_async(&cfg).context("create utun device")?;
        use tun2::AbstractDevice;
        let iface = device.tun_name().context("read utun name")?;

        // Apply every address via ifconfig — tun2's config only sets one.
        for cidr in &params.addresses {
            let net: IpNet = cidr
                .parse()
                .map_err(|e| anyhow!("address `{cidr}`: {e}"))?;
            apply_address(&iface, &net).with_context(|| format!("ifconfig {iface} {cidr}"))?;
        }

        // UDP socket for the peer endpoint.
        let bind_addr: SocketAddr = match params.endpoint {
            SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
            SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
        };
        let udp = UdpSocket::bind(bind_addr)
            .await
            .with_context(|| format!("bind UDP ({bind_addr})"))?;
        udp.connect(params.endpoint)
            .await
            .with_context(|| format!("connect UDP ({})", params.endpoint))?;

        // Gateway: prefer host-supplied value; fall back to `route get` so we
        // can still install endpoint bypass / exclude routes from the helper.
        let gateway = match params.gateway {
            Some(g) => Some(g),
            None => routing::lookup_gateway(params.endpoint.ip())
                .ok()
                .flatten(),
        };

        let mut routes = routing::Routes::new(&iface);

        // 1. Endpoint bypass first — without this, 0.0.0.0/0 AllowedIPs would
        //    recurse WireGuard UDP through the utun we just created.
        if let Some(gw) = gateway {
            if let Err(e) = routes.apply_endpoint_bypass(params.endpoint.ip(), gw) {
                eprintln!("splitwg-helper: endpoint bypass (non-fatal): {e}");
            }
        } else {
            eprintln!("splitwg-helper: no gateway known, skipping endpoint bypass");
        }

        // 2. AllowedIPs → utun routes (with 0.0.0.0/0 split-default).
        let allowed_nets: Vec<IpNet> = params
            .allowed_ips
            .iter()
            .filter_map(|s| s.parse::<IpNet>().ok())
            .collect();
        if let Err(e) = routes.apply_tunnel(&allowed_nets) {
            bail!("apply tunnel routes: {e}");
        }

        // 3. Exclude-mode bypass: listed CIDRs leave via the gateway.
        if matches!(params.mode, TunnelMode::Exclude) && !params.exclude_entries.is_empty() {
            if let Some(gw) = gateway {
                let exclude_nets: Vec<IpNet> = params
                    .exclude_entries
                    .iter()
                    .filter_map(|s| s.parse::<IpNet>().ok())
                    .collect();
                if let Err(e) = routes.apply_exclude(&exclude_nets, gw) {
                    eprintln!("splitwg-helper: exclude routes (non-fatal): {e}");
                }
            } else {
                eprintln!(
                    "splitwg-helper: exclude mode requested but no gateway — routes skipped"
                );
            }
        }

        // 4. DNS.
        let dns = dns::Dns::apply(&iface, &params.dns)
            .with_context(|| format!("apply DNS on {iface}"))?;

        // 4b. Kill-switch pf anchor. Best-effort: a failure here should not
        // abort an otherwise-healthy tunnel — the user still sees the
        // attempt in the log and can investigate. When disabled globally,
        // `kill_switch = false` short-circuits the subprocess call.
        let pf = if params.kill_switch {
            match pf::PfAnchor::load(&iface) {
                Ok(a) => Some(a),
                Err(e) => {
                    eprintln!(
                        "splitwg-helper: kill-switch load failed (non-fatal): {e:#}"
                    );
                    None
                }
            }
        } else {
            None
        };

        // PostUp hooks — fired after the tunnel is ready. Failure is log-only
        // so a broken hook cannot poison a live tunnel that is already up.
        for cmd in &params.post_up {
            if let Err(e) = run_hook(&iface, cmd, HookPhase::PostUp).await {
                log::warn!("splitwg-helper: PostUp failed (non-fatal): {e:#}");
            }
        }

        let tunn = Tunn::new(static_secret, peer_public, psk, params.keepalive, 0, None);

        Ok(Self {
            iface,
            device: Arc::new(device),
            udp: Arc::new(udp),
            tunn: Arc::new(Mutex::new(tunn)),
            mtu: params.mtu,
            pf,
            dns,
            routes,
            pre_down: params.pre_down.clone(),
            post_down: params.post_down.clone(),
        })
    }

    /// Orderly teardown: PreDown hooks fire → Drop-based routing/DNS cleanup
    /// happens (as `self` goes out of scope) → PostDown hooks fire.
    ///
    /// Hook failures during teardown are log-only so a broken hook cannot
    /// prevent the utun/routes from being released.
    pub async fn shutdown(self) {
        let iface = self.iface.clone();
        let pre_down = self.pre_down.clone();
        let post_down = self.post_down.clone();

        for cmd in &pre_down {
            if let Err(e) = run_hook(&iface, cmd, HookPhase::PreDown).await {
                log::warn!("splitwg-helper: PreDown failed (non-fatal): {e:#}");
            }
        }

        // Drop `self` → Routes::drop + Dns::drop run here, restoring the
        // system's pre-tunnel state before PostDown sees it.
        drop(self);

        for cmd in &post_down {
            if let Err(e) = run_hook(&iface, cmd, HookPhase::PostDown).await {
                log::warn!("splitwg-helper: PostDown failed (non-fatal): {e:#}");
            }
        }
    }

    /// Run the three background tasks until `shutdown_rx` fires. Returns once
    /// all tasks are aborted — the caller may then drop `self` to tear down
    /// the utun device.
    pub async fn run(&self, mut shutdown_rx: watch::Receiver<bool>) -> Result<()> {
        let mtu = self.mtu as usize;

        let tun_to_udp = {
            let device = self.device.clone();
            let udp = self.udp.clone();
            let tunn = self.tunn.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; mtu + 64];
                let mut dst = vec![0u8; mtu + 128];
                loop {
                    let n = match device.recv(&mut buf).await {
                        Ok(n) => n,
                        Err(e) => {
                            eprintln!("splitwg-helper: tun recv: {e}");
                            return;
                        }
                    };
                    let to_send = {
                        let mut t = tunn.lock().await;
                        match t.encapsulate(&buf[..n], &mut dst) {
                            TunnResult::WriteToNetwork(pkt) => Some(pkt.to_vec()),
                            TunnResult::Err(e) => {
                                eprintln!("splitwg-helper: encapsulate: {e:?}");
                                None
                            }
                            _ => None,
                        }
                    };
                    if let Some(b) = to_send {
                        if let Err(e) = udp.send(&b).await {
                            eprintln!("splitwg-helper: udp send (tun→udp): {e}");
                        }
                    }
                }
            })
        };

        let udp_to_tun = {
            let device = self.device.clone();
            let udp = self.udp.clone();
            let tunn = self.tunn.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; MAX_PACKET];
                let mut dst = vec![0u8; MAX_PACKET];
                loop {
                    let n = match udp.recv(&mut buf).await {
                        Ok(n) => n,
                        Err(e) => {
                            eprintln!("splitwg-helper: udp recv: {e}");
                            return;
                        }
                    };
                    let mut datagram: &[u8] = &buf[..n];
                    loop {
                        let action = {
                            let mut t = tunn.lock().await;
                            match t.decapsulate(None, datagram, &mut dst) {
                                TunnResult::Done => Action::Stop,
                                TunnResult::Err(e) => {
                                    eprintln!("splitwg-helper: decapsulate: {e:?}");
                                    Action::Stop
                                }
                                TunnResult::WriteToNetwork(pkt) => Action::Net(pkt.to_vec()),
                                TunnResult::WriteToTunnelV4(pkt, _)
                                | TunnResult::WriteToTunnelV6(pkt, _) => Action::Tun(pkt.to_vec()),
                            }
                        };
                        match action {
                            Action::Stop => break,
                            Action::Net(b) => {
                                if let Err(e) = udp.send(&b).await {
                                    eprintln!("splitwg-helper: udp send (udp→udp): {e}");
                                }
                                // Drain queued packets — boringtun contract
                                // says repeat with empty datagram until Done.
                                datagram = &[];
                            }
                            Action::Tun(b) => {
                                if let Err(e) = device.send(&b).await {
                                    eprintln!("splitwg-helper: tun send: {e}");
                                }
                                break;
                            }
                        }
                    }
                }
            })
        };

        let timer = timers::spawn_timer_loop(self.tunn.clone(), self.udp.clone());

        let _ = shutdown_rx.changed().await;
        tun_to_udp.abort();
        udp_to_tun.abort();
        timer.abort();
        Ok(())
    }

    /// Convenience for the helper: run the tunnel until shutdown, then invoke
    /// `shutdown()` for ordered PreDown/teardown/PostDown. Consumes `self` so
    /// the helper doesn't have to juggle ownership with `Arc::try_unwrap`.
    pub async fn run_and_teardown(self, rx: watch::Receiver<bool>) -> Result<()> {
        self.run(rx).await?;
        self.shutdown().await;
        Ok(())
    }

    /// Snapshot of the last-seen handshake age and tx/rx counters.
    pub async fn stats(&self) -> (Option<std::time::Duration>, usize, usize) {
        let t = self.tunn.lock().await;
        let (hs, tx, rx, _, _) = t.stats();
        (hs, tx, rx)
    }
}

enum Action {
    Stop,
    Net(Vec<u8>),
    Tun(Vec<u8>),
}

fn load_static_secret(b64: &str) -> Result<StaticSecret> {
    let bytes = ipc::decode_key(b64).map_err(|e| anyhow!("interface_key: {e}"))?;
    Ok(StaticSecret::from(bytes))
}

fn load_peer_public(b64: &str) -> Result<PublicKey> {
    let bytes = ipc::decode_key(b64).map_err(|e| anyhow!("peer_key: {e}"))?;
    Ok(PublicKey::from(bytes))
}

/// Identifies which hook is executing — kept around for log lines and the
/// error messages surfaced back to the tray.
#[derive(Debug, Clone, Copy)]
enum HookPhase {
    PreUp,
    PostUp,
    PreDown,
    PostDown,
}

impl HookPhase {
    fn as_str(self) -> &'static str {
        match self {
            HookPhase::PreUp => "PreUp",
            HookPhase::PostUp => "PostUp",
            HookPhase::PreDown => "PreDown",
            HookPhase::PostDown => "PostDown",
        }
    }
}

/// Substitutes `%i` with the interface name (wg-quick-compatible placeholder).
/// No other placeholders are supported. `%i` during `PreUp` is intentionally
/// empty to match wg-quick's documented behaviour.
fn substitute_iface(iface: &str, cmd: &str) -> String {
    cmd.replace("%i", iface)
}

/// Executes a single hook command under `sh -c` with a hard 30-second timeout.
///
/// Stdin/stdout/stderr are inherited so the child writes straight into the
/// helper's stdout/stderr streams — which the host already relays into
/// `~/.config/splitwg/splitwg.log`. A non-zero exit or timeout yields an error;
/// callers decide whether that aborts the tunnel lifecycle (PreUp) or is
/// purely advisory (PostUp / PreDown / PostDown).
async fn run_hook(iface: &str, cmd: &str, phase: HookPhase) -> Result<()> {
    let expanded = substitute_iface(iface, cmd);
    log::info!(
        "splitwg-helper: {}: running `{expanded}`",
        phase.as_str()
    );

    // `kill_on_drop(true)` ensures that if the timeout branch fires the child
    // is reaped rather than orphaned as a zombie root process.
    let mut child = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(&expanded)
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("{}: spawn `{expanded}`", phase.as_str()))?;

    let status = match tokio::time::timeout(HOOK_TIMEOUT, child.wait()).await {
        Ok(r) => r.with_context(|| format!("{}: wait `{expanded}`", phase.as_str()))?,
        Err(_) => {
            // Try best-effort kill; `kill_on_drop` covers the case where `kill`
            // itself errors (e.g. child already exiting).
            let _ = child.kill().await;
            bail!(
                "{} timed out after {:?}: `{expanded}`",
                phase.as_str(),
                HOOK_TIMEOUT
            );
        }
    };

    if !status.success() {
        bail!(
            "{} exited non-zero ({status}): `{expanded}`",
            phase.as_str()
        );
    }
    Ok(())
}

fn apply_address(iface: &str, net: &IpNet) -> Result<()> {
    let status = match net {
        IpNet::V4(v4) => Command::new("ifconfig")
            .args([
                iface,
                "inet",
                &format!("{}/{}", v4.addr(), v4.prefix_len()),
                &v4.addr().to_string(),
                "alias",
            ])
            .status(),
        IpNet::V6(v6) => Command::new("ifconfig")
            .args([
                iface,
                "inet6",
                "add",
                &format!("{}/{}", v6.addr(), v6.prefix_len()),
            ])
            .status(),
    }
    .context("spawn ifconfig")?;
    if !status.success() {
        bail!("ifconfig exited with {status}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitute_iface_replaces_percent_i() {
        assert_eq!(
            substitute_iface("utun4", "logger 'vpn %i up'"),
            "logger 'vpn utun4 up'"
        );
    }

    #[test]
    fn substitute_iface_replaces_all_occurrences() {
        assert_eq!(
            substitute_iface("utun3", "echo %i %i %i"),
            "echo utun3 utun3 utun3"
        );
    }

    #[test]
    fn substitute_iface_empty_for_preup() {
        // wg-quick documents `%i` as undefined during PreUp; we substitute "".
        assert_eq!(substitute_iface("", "logger '%i pre'"), "logger ' pre'");
    }

    #[test]
    fn substitute_iface_leaves_other_percents() {
        // Only `%i` is recognised; `%t`, `%c`, `%%` pass through verbatim.
        assert_eq!(
            substitute_iface("utun4", "echo %t %c %% done"),
            "echo %t %c %% done"
        );
    }

    #[tokio::test]
    async fn run_hook_success_returns_ok() {
        run_hook("utun0", "true", HookPhase::PostUp)
            .await
            .expect("true exits 0");
    }

    #[tokio::test]
    async fn run_hook_nonzero_exit_errors() {
        let err = run_hook("utun0", "false", HookPhase::PreUp)
            .await
            .expect_err("false must fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("PreUp exited non-zero"),
            "unexpected error: {msg}"
        );
    }

    #[tokio::test]
    async fn run_hook_substitutes_iface_in_command() {
        // Writes the iface name into a unique temp file; we read it back.
        let tmp = std::env::temp_dir().join(format!(
            "splitwg-hook-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&tmp);
        let cmd = format!("printf %i > {}", tmp.display());
        run_hook("utun42", &cmd, HookPhase::PostUp)
            .await
            .expect("hook ok");
        let got = std::fs::read_to_string(&tmp).expect("temp file written");
        let _ = std::fs::remove_file(&tmp);
        assert_eq!(got, "utun42");
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn run_hook_times_out_and_errors() {
        // `sleep 120` vastly exceeds HOOK_TIMEOUT; with paused time the 30s
        // deadline advances instantly and no real sleep is observed.
        let fut = run_hook("utun0", "sleep 120", HookPhase::PreUp);
        let err = fut.await.expect_err("must time out");
        let msg = format!("{err}");
        assert!(msg.contains("timed out"), "unexpected error: {msg}");
    }
}
