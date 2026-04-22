//! Linux authentication stub — no biometric equivalent to Touch ID / Windows Hello.
//! Returns NotAvailable so the connect path skips auth without blocking.

use super::touchid::AuthResult;

pub fn authenticate(_reason: &str) -> AuthResult {
    AuthResult::NotAvailable
}
