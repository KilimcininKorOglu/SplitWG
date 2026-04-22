//! "Launch at login" toggle backed by XDG autostart .desktop file.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginItemState {
    NotRegistered,
    Enabled,
    RequiresApproval,
    NotFound,
}

fn autostart_path() -> std::path::PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from(".config"))
        .join("autostart")
        .join("splitwg.desktop")
}

pub fn status() -> LoginItemState {
    if autostart_path().exists() {
        LoginItemState::Enabled
    } else {
        LoginItemState::NotRegistered
    }
}

pub fn register() -> Result<(), String> {
    log::info!("splitwg: login_item: registering (XDG autostart)");
    let path = autostart_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create autostart dir: {e}"))?;
    }
    std::fs::write(
        &path,
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=SplitWG\n\
         Exec=/usr/bin/splitwg --minimized\n\
         Icon=network-vpn\n\
         X-GNOME-Autostart-enabled=true\n\
         StartupNotify=false\n",
    )
    .map_err(|e| format!("write desktop file: {e}"))?;
    Ok(())
}

pub fn unregister() -> Result<(), String> {
    log::info!("splitwg: login_item: unregistering (XDG autostart)");
    let path = autostart_path();
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| format!("remove desktop file: {e}"))?;
    }
    Ok(())
}
