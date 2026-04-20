//! URL scheme registration for `x-splitwg://` on Windows.
//!
//! Registers a protocol handler in the Windows Registry under
//! `HKCU\Software\Classes\x-splitwg`. This allows the browser to launch
//! SplitWG when clicking `x-splitwg://...` links.

const PROTOCOL_KEY: &str = r"Software\Classes\x-splitwg";

pub fn is_registered() -> bool {
    #[cfg(target_os = "windows")]
    {
        use winreg::enums::*;
        use winreg::RegKey;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        hkcu.open_subkey(PROTOCOL_KEY).is_ok()
    }
    #[cfg(not(target_os = "windows"))]
    false
}

pub fn register() -> Result<(), String> {
    log::info!("splitwg: url_scheme: registering x-splitwg:// handler");
    #[cfg(target_os = "windows")]
    {
        use winreg::enums::*;
        use winreg::RegKey;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let (key, _) = hkcu
            .create_subkey(PROTOCOL_KEY)
            .map_err(|e| format!("failed to create protocol key: {e}"))?;
        key.set_value("", &"URL:SplitWG Protocol")
            .map_err(|e| format!("failed to set default value: {e}"))?;
        key.set_value("URL Protocol", &"")
            .map_err(|e| format!("failed to set URL Protocol: {e}"))?;

        let (cmd_key, _) = hkcu
            .create_subkey(&format!(r"{PROTOCOL_KEY}\shell\open\command"))
            .map_err(|e| format!("failed to create command key: {e}"))?;

        let exe = std::env::current_exe()
            .map_err(|e| format!("failed to get exe path: {e}"))?;
        let cmd = format!("\"{}\" \"%1\"", exe.display());
        cmd_key
            .set_value("", &cmd)
            .map_err(|e| format!("failed to set command: {e}"))?;
    }
    Ok(())
}

pub fn unregister() -> Result<(), String> {
    log::info!("splitwg: url_scheme: unregistering x-splitwg:// handler");
    #[cfg(target_os = "windows")]
    {
        use winreg::enums::*;
        use winreg::RegKey;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let _ = hkcu.delete_subkey_all(PROTOCOL_KEY);
    }
    Ok(())
}
