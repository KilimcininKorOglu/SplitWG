//! Windows Hello biometric authentication via UserConsentVerifier.
//!
//! Uses the `windows` crate WinRT bindings. Falls back to `NotAvailable`
//! when Windows Hello is not enrolled or the device lacks biometric hardware.

use super::touchid::AuthResult;

pub fn authenticate(reason: &str) -> AuthResult {
    match try_authenticate(reason) {
        Ok(result) => result,
        Err(e) => {
            log::warn!("splitwg: auth: Windows Hello failed: {e}");
            AuthResult::NotAvailable
        }
    }
}

#[cfg(target_os = "windows")]
fn try_authenticate(reason: &str) -> Result<AuthResult, String> {
    use std::sync::mpsc;

    let reason = reason.to_string();
    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        let result = win_hello_sync(&reason);
        let _ = tx.send(result);
    });

    rx.recv()
        .map_err(|e| format!("auth thread panicked: {e}"))?
}

#[cfg(target_os = "windows")]
fn win_hello_sync(reason: &str) -> Result<AuthResult, String> {
    use windows::Security::Credentials::UI::*;

    let availability = UserConsentVerifier::CheckAvailabilityAsync()
        .map_err(|e| format!("CheckAvailability: {e}"))?
        .get()
        .map_err(|e| format!("CheckAvailability.get: {e}"))?;

    if availability != UserConsentVerifierAvailability::Available {
        return Ok(AuthResult::NotAvailable);
    }

    let hstring: windows::core::HSTRING = reason.into();
    let result = UserConsentVerifier::RequestVerificationAsync(&hstring)
        .map_err(|e| format!("RequestVerification: {e}"))?
        .get()
        .map_err(|e| format!("RequestVerification.get: {e}"))?;

    match result {
        UserConsentVerificationResult::Verified => Ok(AuthResult::Success),
        UserConsentVerificationResult::Canceled => Ok(AuthResult::Denied),
        _ => Ok(AuthResult::Denied),
    }
}

#[cfg(not(target_os = "windows"))]
fn try_authenticate(_reason: &str) -> Result<AuthResult, String> {
    Ok(AuthResult::NotAvailable)
}
