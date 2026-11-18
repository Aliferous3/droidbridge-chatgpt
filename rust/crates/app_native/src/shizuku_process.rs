//! The typed Shizuku process primitive internal surfaces share.
//!
//! Fixed-argv primitives (visual input today) run through the `shizuku.shell`
//! user-service operations `ShizukuProcessStart`/`ShizukuProcessCancel`. This helper
//! keeps the executing thread able to deliver the typed cancel while the primitive
//! carries the payload's own deadline, so cleanup is always proven by the identity
//! that owns the process. It is not a public tool surface: callers pass already-built
//! fixed-operation payloads, never caller-supplied shell text.

use contract::ErrorCode;
use domain::DomainError;
use runtime::{AdmittedExecution, LocalExecutionClaim};

/// Runs the Shizuku process primitive for this execution while this thread stays able
/// to deliver the typed cancel the APK surface owns for that identity. The primitive
/// carries the operation's own deadline, so a cancelled run settles through the same
/// proof and this port never has to guess at cleanup.
#[cfg(target_os = "android")]
pub(crate) fn run_shizuku_guarded(
    execution: &AdmittedExecution,
    claim: &LocalExecutionClaim,
    payload: &[u8],
    descriptor: Option<(&str, std::os::fd::RawFd)>,
) -> Result<runtime::AndroidPrimitiveResult, DomainError> {
    use std::time::Duration;

    let owned_execution = execution.clone();
    let owned_payload = payload.to_vec();
    let owned_descriptor = descriptor.map(|(role, fd)| (role.to_owned(), fd));
    let worker = std::thread::spawn(move || match owned_descriptor {
        Some((role, fd)) => crate::dispatch_android_execution_for_with_descriptor(
            "shizuku.shell",
            "ShizukuProcessStart",
            &owned_payload,
            &owned_execution,
            Some((&role, fd)),
        ),
        None => crate::dispatch_android_execution_for(
            "shizuku.shell",
            "ShizukuProcessStart",
            &owned_payload,
            &owned_execution,
        ),
    });
    let mut cancelled = false;
    while !worker.is_finished() {
        if !cancelled && claim.checkpoint().is_err() {
            cancelled = true;
            let _ = cancel_process(execution);
        }
        std::thread::sleep(Duration::from_millis(SHIZUKU_CANCEL_POLL_MS));
    }
    worker.join().unwrap_or_else(|_| {
        Err(DomainError::new(
            ErrorCode::InternalError,
            "the Shizuku process primitive did not report a settlement",
        ))
    })
}

#[cfg(not(target_os = "android"))]
pub(crate) fn run_shizuku_guarded(
    _execution: &AdmittedExecution,
    _claim: &LocalExecutionClaim,
    _payload: &[u8],
    _descriptor: Option<(&str, i32)>,
) -> Result<runtime::AndroidPrimitiveResult, DomainError> {
    Err(DomainError::new(
        ErrorCode::CapabilityUnavailable,
        "Shizuku guarded primitives require Android",
    ))
}

/// Requests cancellation of the one Shizuku process this execution started through the
/// same typed primitive, so the identity that owns the process is always the one that
/// cancels it.
#[cfg(target_os = "android")]
fn cancel_process(
    execution: &AdmittedExecution,
) -> Result<runtime::AndroidPrimitiveResult, DomainError> {
    let payload = serde_json::to_vec(&serde_json::json!({
        "execution_id": execution.execution_id.as_str(),
    }))
    .map_err(|_| {
        DomainError::new(
            ErrorCode::InternalError,
            "process cancel payload encoding failed",
        )
    })?;
    crate::dispatch_android_execution_for(
        "shizuku.shell",
        "ShizukuProcessCancel",
        &payload,
        execution,
    )
}

#[cfg(target_os = "android")]
const SHIZUKU_CANCEL_POLL_MS: u64 = 25;
