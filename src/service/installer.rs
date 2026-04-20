//! Windows Service install/uninstall utilities.
//!
//! Used by the GUI's Preferences panel to register or remove the
//! `splitwg` service. Installation requires UAC elevation.

#[cfg(target_os = "windows")]
use std::ffi::OsString;

/// Returns true if the splitwg service is registered.
#[cfg(target_os = "windows")]
pub fn is_installed() -> bool {
    use windows_service::service_manager::*;

    let manager = match ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT,
    ) {
        Ok(m) => m,
        Err(_) => return false,
    };
    manager
        .open_service("splitwg", ServiceAccess::QUERY_STATUS)
        .is_ok()
}

/// Installs the splitwg service. Requires admin privileges.
#[cfg(target_os = "windows")]
pub fn install() -> Result<(), String> {
    use windows_service::service::*;
    use windows_service::service_manager::*;

    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(|e| format!("failed to open service manager: {e}"))?;

    let service_binary = std::env::current_exe()
        .map_err(|e| format!("failed to get exe path: {e}"))?
        .parent()
        .unwrap()
        .join("splitwg-svc.exe");

    let service_info = ServiceInfo {
        name: OsString::from("splitwg"),
        display_name: OsString::from("SplitWG Tunnel Service"),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: service_binary,
        launch_arguments: vec![],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };

    manager
        .create_service(&service_info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .map_err(|e| format!("failed to create service: {e}"))?;

    Ok(())
}

/// Uninstalls the splitwg service.
#[cfg(target_os = "windows")]
pub fn uninstall() -> Result<(), String> {
    use windows_service::service_manager::*;
    use windows_service::service::*;

    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT,
    )
    .map_err(|e| format!("failed to open service manager: {e}"))?;

    let service = manager
        .open_service("splitwg", ServiceAccess::STOP | ServiceAccess::DELETE)
        .map_err(|e| format!("failed to open service: {e}"))?;

    let _ = service.stop();
    service
        .delete()
        .map_err(|e| format!("failed to delete service: {e}"))?;

    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn is_installed() -> bool {
    false
}

#[cfg(not(target_os = "windows"))]
pub fn install() -> Result<(), String> {
    Err("service installation is only available on Windows".to_string())
}

#[cfg(not(target_os = "windows"))]
pub fn uninstall() -> Result<(), String> {
    Err("service uninstallation is only available on Windows".to_string())
}
