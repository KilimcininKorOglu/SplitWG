//! Userspace WireGuard tunnel runtime — gotatun crypto state machine fed
//! by a macOS utun device (via tun2) and a UDP socket to the peer endpoint.
//!
//! All I/O is driven by three tokio tasks:
//!
//! 1. tun → udp : encapsulate plaintext IP packets from the utun.
//! 2. udp → tun : decapsulate ciphertext datagrams; flush queued packets
//!    whenever a WriteToNetwork is returned.
//! 3. timers    : 250 ms ticker that drives gotatun's rekey/keepalive.
//!
//! Shutdown is broadcast via a `watch::Receiver<bool>` — when set to true the
//! loops abort and the `AsyncDevice` / `UdpSocket` drop (utun closes).

use std::net::SocketAddr;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use gotatun::noise::index_table::IndexTable;
use gotatun::noise::rate_limiter::RateLimiter;
use gotatun::noise::{Tunn, TunnResult};
use gotatun::packet::Packet;
use gotatun::x25519::{PublicKey, StaticSecret};
use ipnet::IpNet;
use tokio::net::UdpSocket;
use tokio::sync::{watch, Mutex};

use crate::ipc::{self, TunnelMode, UpParams};

/// Per-hook timeout. `PreUp` is fatal on timeout (bringup aborts); `PostUp`,
/// `PreDown`, `PostDown` are log-only. Not configurable — kept short enough
/// that a hang cannot indefinitely wedge a tunnel's lifecycle.
const HOOK_TIMEOUT: Duration = Duration::from_secs(30);

#[cfg(target_os = "macos")]
#[path = "dns_darwin.rs"]
pub mod dns;
#[cfg(target_os = "windows")]
#[path = "dns_windows.rs"]
pub mod dns;

#[cfg(target_os = "macos")]
pub mod pf;
#[cfg(target_os = "windows")]
pub mod wfp;

#[cfg(target_os = "macos")]
#[path = "routing_darwin.rs"]
pub mod routing;
#[cfg(target_os = "windows")]
#[path = "routing_windows.rs"]
pub mod routing;

pub mod timers;

const MAX_PACKET: usize = 65_536;

#[cfg(target_os = "windows")]
fn tunnel_name_to_guid(name: &str) -> u128 {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(format!("splitwg-tunnel-{name}").as_bytes());
    u128::from_le_bytes(hash[..16].try_into().unwrap())
}

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
    #[cfg(target_os = "macos")]
    #[allow(dead_code)]
    pf: Option<pf::PfAnchor>,
    #[cfg(target_os = "windows")]
    #[allow(dead_code)]
    wfp: Option<wfp::WfpAnchor>,
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
        eprintln!("splitwg-helper: bringup: start (endpoint={})", params.endpoint);

        let static_secret = load_static_secret(&params.interface_key)?;
        let peer_public = load_peer_public(&params.peer_key)?;
        let psk = match &params.psk {
            Some(s) => {
                eprintln!("splitwg-helper: bringup: preshared key present");
                Some(ipc::decode_key(s).map_err(|e| anyhow!("psk: {e}"))?)
            }
            None => {
                eprintln!("splitwg-helper: bringup: no preshared key");
                None
            }
        };

        for cmd in &params.pre_up {
            run_hook("", cmd, HookPhase::PreUp).await?;
        }

        eprintln!("splitwg-helper: bringup: creating tun device (mtu={})", params.mtu);
        let mut cfg = tun2::Configuration::default();
        cfg.mtu(params.mtu).up();
        #[cfg(target_os = "windows")]
        cfg.platform_config(|p| {
            p.device_guid(tunnel_name_to_guid(&params.tunnel));
        });
        let device = tun2::create_as_async(&cfg).context("create tun device")?;
        use tun2::AbstractDevice;
        let iface = device.tun_name().context("read utun name")?;
        eprintln!("splitwg-helper: bringup: utun created: {iface}");

        for cidr in &params.addresses {
            eprintln!("splitwg-helper: bringup: assigning address {cidr} to {iface}");
            let net: IpNet = cidr
                .parse()
                .map_err(|e| anyhow!("address `{cidr}`: {e}"))?;
            apply_address(&iface, &net).with_context(|| format!("ifconfig {iface} {cidr}"))?;
        }

        let bind_addr: SocketAddr = match params.endpoint {
            SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
            SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
        };
        eprintln!("splitwg-helper: bringup: binding UDP socket ({})", bind_addr);
        let udp = UdpSocket::bind(bind_addr)
            .await
            .with_context(|| format!("bind UDP ({bind_addr})"))?;
        udp.connect(params.endpoint)
            .await
            .with_context(|| format!("connect UDP ({})", params.endpoint))?;
        eprintln!("splitwg-helper: bringup: UDP connected to {}", params.endpoint);

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

        eprintln!("splitwg-helper: bringup: applying {} tunnel route(s)", params.allowed_ips.len());
        let allowed_nets: Vec<IpNet> = params
            .allowed_ips
            .iter()
            .filter_map(|s| s.parse::<IpNet>().ok())
            .collect();
        if let Err(e) = routes.apply_tunnel(&allowed_nets) {
            bail!("apply tunnel routes: {e}");
        }
        eprintln!("splitwg-helper: bringup: tunnel routes applied");

        if matches!(params.mode, TunnelMode::Exclude) && !params.exclude_entries.is_empty() {
            eprintln!("splitwg-helper: bringup: applying {} exclude route(s)", params.exclude_entries.len());
            if let Some(gw) = gateway {
                let exclude_nets: Vec<IpNet> = params
                    .exclude_entries
                    .iter()
                    .filter_map(|s| s.parse::<IpNet>().ok())
                    .collect();
                if let Err(e) = routes.apply_exclude(&exclude_nets, gw) {
                    eprintln!("splitwg-helper: bringup: exclude routes (non-fatal): {e}");
                } else {
                    eprintln!("splitwg-helper: bringup: exclude routes applied via gateway {gw}");
                }
            } else {
                eprintln!(
                    "splitwg-helper: bringup: exclude mode requested but no gateway — routes skipped"
                );
            }
        }

        eprintln!("splitwg-helper: bringup: applying DNS {:?} on {iface}", params.dns);
        let dns = dns::Dns::apply(&iface, &params.dns)
            .with_context(|| format!("apply DNS on {iface}"))?;
        eprintln!("splitwg-helper: bringup: DNS applied");

        // 4b. Kill-switch pf anchor. Best-effort: a failure here should not
        // abort an otherwise-healthy tunnel — the user still sees the
        // attempt in the log and can investigate. When disabled globally,
        // `kill_switch = false` short-circuits the subprocess call.
        #[cfg(target_os = "macos")]
        let pf = if params.kill_switch {
            eprintln!("splitwg-helper: bringup: loading kill-switch pf anchor for {iface}");
            match pf::PfAnchor::load(&iface) {
                Ok(a) => {
                    eprintln!("splitwg-helper: bringup: kill-switch pf anchor loaded");
                    Some(a)
                }
                Err(e) => {
                    eprintln!(
                        "splitwg-helper: bringup: kill-switch load failed (non-fatal): {e:#}"
                    );
                    None
                }
            }
        } else {
            None
        };
        #[cfg(target_os = "windows")]
        let wfp = if params.kill_switch {
            eprintln!("splitwg-svc: bringup: loading kill-switch WFP rules for {iface}");
            match wfp::WfpAnchor::load(&iface) {
                Ok(a) => Some(a),
                Err(e) => {
                    eprintln!("splitwg-svc: bringup: WFP load failed (non-fatal): {e:#}");
                    None
                }
            }
        } else {
            None
        };

        // PostUp hooks — fired after the tunnel is ready. Failure is log-only
        // so a broken hook cannot poison a live tunnel that is already up.
        eprintln!("splitwg-helper: bringup: running {} PostUp hook(s)", params.post_up.len());
        for cmd in &params.post_up {
            if let Err(e) = run_hook(&iface, cmd, HookPhase::PostUp).await {
                eprintln!("splitwg-helper: bringup: PostUp failed (non-fatal): {e:#}");
            }
        }

        eprintln!(
            "splitwg-helper: bringup: creating gotatun Tunn (keepalive={:?})",
            params.keepalive
        );
        let our_public = PublicKey::from(&static_secret);
        let index_table = IndexTable::from_os_rng();
        let rate_limiter = Arc::new(RateLimiter::new(&our_public, 100));
        let tunn = Tunn::new(static_secret, peer_public, psk, params.keepalive, index_table, rate_limiter);
        eprintln!("splitwg-helper: bringup: tunnel ready on {iface}");

        Ok(Self {
            iface,
            device: Arc::new(device),
            udp: Arc::new(udp),
            tunn: Arc::new(Mutex::new(tunn)),
            mtu: params.mtu,
            #[cfg(target_os = "macos")]
            pf,
            #[cfg(target_os = "windows")]
            wfp,
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
    ///
    /// Takes `self` by value so all Arc-wrapped resources drop when this
    /// function returns.  Callers that hold the tunnel in an `Arc` should
    /// `Arc::try_unwrap` first or use `shutdown_arc`.
    pub async fn shutdown(self) {
        let iface = self.iface.clone();
        let pre_down = self.pre_down.clone();
        let post_down = self.post_down.clone();

        eprintln!("splitwg-helper: shutdown: starting teardown on {iface}");

        eprintln!("splitwg-helper: shutdown: running {} PreDown hook(s)", pre_down.len());
        for cmd in &pre_down {
            if let Err(e) = run_hook(&iface, cmd, HookPhase::PreDown).await {
                eprintln!("splitwg-helper: shutdown: PreDown failed (non-fatal): {e:#}");
            }
        }

        eprintln!("splitwg-helper: shutdown: dropping tunnel (pf flush, DNS revert, route cleanup, device close)");
        drop(self);
        eprintln!("splitwg-helper: shutdown: tunnel resources released");

        eprintln!("splitwg-helper: shutdown: running {} PostDown hook(s)", post_down.len());
        for cmd in &post_down {
            if let Err(e) = run_hook(&iface, cmd, HookPhase::PostDown).await {
                eprintln!("splitwg-helper: shutdown: PostDown failed (non-fatal): {e:#}");
            }
        }
        eprintln!("splitwg-helper: shutdown: teardown complete on {iface}");
    }

    /// `Arc`-friendly teardown: unwraps or waits for sole ownership, then
    /// delegates to `shutdown(self)`.  If other `Arc` references still exist
    /// (shouldn't happen — the stats emitter must be cancelled first) the
    /// method retries a few times before logging a warning and leaking.
    pub async fn shutdown_arc(mut this: Arc<Self>) {
        for _ in 0..20 {
            match Arc::try_unwrap(this) {
                Ok(inner) => {
                    inner.shutdown().await;
                    return;
                }
                Err(arc) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    this = arc;
                }
            }
        }
        eprintln!("splitwg-helper: shutdown_arc: could not obtain sole ownership, leaking tunnel");
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
                        let packet = Packet::copy_from(&buf[..n]);
                        t.handle_outgoing_packet(packet, None)
                            .map(|wg| {
                                let pkt: Packet = Packet::from(wg);
                                pkt.to_vec()
                            })
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
                loop {
                    let n = match udp.recv(&mut buf).await {
                        Ok(n) => n,
                        Err(e) => {
                            eprintln!("splitwg-helper: udp recv: {e}");
                            return;
                        }
                    };
                    let raw = Packet::copy_from(&buf[..n]);
                    let wg = match raw.try_into_wg() {
                        Ok(wg) => wg,
                        Err(e) => {
                            eprintln!("splitwg-helper: parse wg packet: {e}");
                            continue;
                        }
                    };
                    let (net_reply, tun_data) = {
                        let mut t = tunn.lock().await;
                        match t.handle_incoming_packet(wg) {
                            TunnResult::Done => (None, None),
                            TunnResult::Err(e) => {
                                eprintln!("splitwg-helper: decapsulate: {e:?}");
                                (None, None)
                            }
                            TunnResult::WriteToNetwork(reply) => {
                                let pkt: Packet = Packet::from(reply);
                                (Some(pkt.to_vec()), None)
                            }
                            TunnResult::WriteToTunnel(pkt) => {
                                (None, Some(pkt.to_vec()))
                            }
                        }
                    };
                    if let Some(b) = net_reply {
                        if let Err(e) = udp.send(&b).await {
                            eprintln!("splitwg-helper: udp send (udp→udp): {e}");
                        }
                    }
                    if let Some(b) = tun_data {
                        if b.is_empty() {
                            continue;
                        }
                        if let Err(e) = device.send(&b).await {
                            eprintln!("splitwg-helper: tun send ({} bytes): {e}", b.len());
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
        eprintln!("splitwg-helper: tunnel: data plane running on {}", self.iface);
        self.run(rx).await?;
        eprintln!("splitwg-helper: tunnel: data plane stopped, beginning shutdown");
        self.shutdown().await;
        Ok(())
    }

    /// Snapshot of the last-seen handshake age and tx/rx counters.
    pub async fn stats(&self) -> (Option<std::time::Duration>, usize, usize) {
        let t = self.tunn.lock().await;
        let (hs, tx, rx, _loss, _rtt) = t.stats();
        (hs, tx, rx)
    }
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
    eprintln!(
        "splitwg-helper: hook: {}: running `{expanded}`",
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
                &v4.addr().to_string(),
                &v4.addr().to_string(),
                "netmask",
                &v4.netmask().to_string(),
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
