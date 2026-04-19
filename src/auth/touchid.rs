//! Public Touch ID API — platform-dispatched via re-export in `auth/mod.rs`.

/// Result of a biometric authentication attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthResult {
    /// Biometric check succeeded.
    Success,
    /// User denied or cancelled the prompt.
    Denied,
    /// Touch ID hardware is absent, not enrolled, or locked out.
    NotAvailable,
}

impl AuthResult {
    pub fn is_success(self) -> bool {
        matches!(self, AuthResult::Success)
    }
}
