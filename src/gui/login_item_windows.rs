//! "Launch at login" toggle backed by Windows Registry Run key.
//!
//! Writes to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
//! which does not require elevation.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginItemState {
    NotRegistered,
    Enabled,
    RequiresApproval,
    NotFound,
}

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const VALUE_NAME: &str = "SplitWG";

pub fn status() -> LoginItemState {
    #[cfg(target_os = "windows")]
    {
        use winreg::enums::*;
        use winreg::RegKey;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        match hkcu.open_subkey(RUN_KEY) {
            Ok(run) => match run.get_value::<String, _>(VALUE_NAME) {
                Ok(_) => LoginItemState::Enabled,
                Err(_) => LoginItemState::NotRegistered,
            },
            Err(_) => LoginItemState::NotRegistered,
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        LoginItemState::NotRegistered
    }
}

pub fn register() -> Result<(), String> {
    log::info!("splitwg: login_item: registering (Windows Registry)");
    #[cfg(target_os = "windows")]
    {
        use winreg::enums::*;
        use winreg::RegKey;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let run = hkcu
            .open_subkey_with_flags(RUN_KEY, KEY_SET_VALUE)
            .map_err(|e| format!("failed to open Run key: {e}"))?;
        let exe = std::env::current_exe().map_err(|e| format!("failed to get exe path: {e}"))?;
        run.set_value(VALUE_NAME, &exe.to_string_lossy().to_string())
            .map_err(|e| format!("failed to set registry value: {e}"))?;
    }
    Ok(())
}

pub fn unregister() -> Result<(), String> {
    log::info!("splitwg: login_item: unregistering (Windows Registry)");
    #[cfg(target_os = "windows")]
    {
        use winreg::enums::*;
        use winreg::RegKey;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        if let Ok(run) = hkcu.open_subkey_with_flags(RUN_KEY, KEY_SET_VALUE) {
            let _ = run.delete_value(VALUE_NAME);
        }
    }
    Ok(())
}
