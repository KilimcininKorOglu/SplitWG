//! Homebrew installs wireguard-tools to `/usr/local/bin` on Intel and
//! `/opt/homebrew/bin` on Apple Silicon (symlinked to `/usr/local/bin` by
//! default).

pub const WG_BIN: &str = "/usr/local/bin/wg";
pub const WG_QUICK_BIN: &str = "/usr/local/bin/wg-quick";
