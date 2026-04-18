//! Touch ID biometric authentication.
//!
//! Uses the `objc2-local-authentication` bindings to call `LAContext`'s
//! `canEvaluatePolicy:error:` and `evaluatePolicy:localizedReason:reply:`
//! directly. The `reply` block is delivered on an internal GCD queue; we block
//! the caller on a one-shot channel (same idea as the classic
//! `dispatch_semaphore` wait/signal pattern).

use std::sync::mpsc;

use block2::RcBlock;
use objc2::rc::Retained;
use objc2::runtime::Bool;
use objc2::AnyThread;
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAPolicy};

use super::touchid::AuthResult;

/// Shows the Touch ID dialog with `reason` as the prompt.
pub fn authenticate(reason: &str) -> AuthResult {
    let ctx: Retained<LAContext> = unsafe { LAContext::init(LAContext::alloc()) };
    let policy = LAPolicy::DeviceOwnerAuthenticationWithBiometrics;

    // Pre-flight: can we evaluate this policy at all?
    if unsafe { ctx.canEvaluatePolicy_error(policy) }.is_err() {
        return AuthResult::NotAvailable;
    }

    let reason_ns = NSString::from_str(reason);
    let (tx, rx) = mpsc::channel::<bool>();

    let tx_block = tx.clone();
    let block = RcBlock::new(move |success: Bool, _error: *mut NSError| {
        let _ = tx_block.send(success.as_bool());
    });

    unsafe {
        ctx.evaluatePolicy_localizedReason_reply(policy, &reason_ns, &block);
    }

    // Drop the extra sender so `recv` errors on unexpected channel close.
    drop(tx);

    match rx.recv() {
        Ok(true) => AuthResult::Success,
        Ok(false) => AuthResult::Denied,
        Err(_) => AuthResult::Denied,
    }
}
