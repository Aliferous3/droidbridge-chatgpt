//! The shared host-process settlement wire (S-AUTH-CMD-001's primitive half).
//!
//! Fixed-argv process primitives on both host surfaces report through these types:
//! the APK surface's visual primitives and the Magisk surface's package, content and
//! visual primitives. The `command` mother tool is not part of this build; nothing
//! here accepts caller-supplied shell text.

use contract::{ErrorCode, RunAs};
use domain::DomainError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandProcessCause {
    Exited,
    Timeout,
    Cancelled,
    OwnerLost,
}

/// The bounded retained result of one guarded process: the stream bytes are
/// the retained prefix, and the truncation facts report that more output was drained
/// and discarded.
#[derive(Clone, Debug, PartialEq)]
pub struct CommandProcessOutcome {
    pub cause: CommandProcessCause,
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr: Vec<u8>,
    pub stderr_truncated: bool,
}

/// One already-admitted fixed-argv process handed to the host primitive that owns
/// its identity. `run_as` is the already-admitted identity rather than a preference.
#[derive(Clone, Debug, PartialEq)]
pub struct CommandProcessRequest {
    pub run_as: RunAs,
    pub program: String,
    pub arguments: Vec<String>,
    pub cwd: Option<String>,
    pub stdin: Option<Vec<u8>>,
    pub timeout_ms: u64,
    pub max_output_bytes: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CommandProcessSettlement {
    pub outcome: CommandProcessOutcome,
    pub cleanup_verified: bool,
}

/// The Android process primitive's settlement for one guarded process. One wire shape
/// carries it from whichever identity ran the process, so the surfaces that own the
/// primitives read the same fields through the same decoder and cannot diverge on
/// terminal meaning.
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct AndroidCommandSettlement {
    cause: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exit_code: Option<i32>,
    #[serde(default)]
    stdout_base64: String,
    #[serde(default)]
    stdout_truncated: bool,
    #[serde(default)]
    stderr_base64: String,
    #[serde(default)]
    stderr_truncated: bool,
    /// A Shizuku settlement reports cleanup separately, and reports an unverified
    /// cleanup as a typed failure instead of a settlement, so its payload omits this.
    #[serde(
        default = "verified_cleanup",
        skip_serializing_if = "is_verified_cleanup"
    )]
    cleanup_verified: bool,
}

const fn verified_cleanup() -> bool {
    true
}

const fn is_verified_cleanup(verified: &bool) -> bool {
    *verified
}

impl AndroidCommandSettlement {
    pub fn decode(payload: &[u8]) -> Result<CommandProcessSettlement, DomainError> {
        let settlement: Self = serde_json::from_slice(payload)
            .map_err(|_| invalid_settlement("command settlement is invalid"))?;
        let cause = match settlement.cause.as_str() {
            "exited" => CommandProcessCause::Exited,
            "cancelled" => CommandProcessCause::Cancelled,
            "timeout" => CommandProcessCause::Timeout,
            "owner_lost" => CommandProcessCause::OwnerLost,
            _ => return Err(invalid_settlement("command settlement cause is invalid")),
        };
        let stdout = decode_stream(&settlement.stdout_base64, "command stdout is invalid")?;
        let stderr = decode_stream(&settlement.stderr_base64, "command stderr is invalid")?;
        Ok(CommandProcessSettlement {
            outcome: CommandProcessOutcome {
                cause,
                exit_code: (cause == CommandProcessCause::Exited)
                    .then_some(settlement.exit_code)
                    .flatten(),
                stdout,
                stdout_truncated: settlement.stdout_truncated,
                stderr,
                stderr_truncated: settlement.stderr_truncated,
            },
            cleanup_verified: settlement.cleanup_verified,
        })
    }

    pub fn encode(settlement: &CommandProcessSettlement) -> Result<Vec<u8>, DomainError> {
        let cause = match settlement.outcome.cause {
            CommandProcessCause::Exited => "exited",
            CommandProcessCause::Timeout => "timeout",
            CommandProcessCause::Cancelled => "cancelled",
            CommandProcessCause::OwnerLost => "owner_lost",
        };
        use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
        serde_json::to_vec(&Self {
            cause: cause.to_owned(),
            exit_code: settlement.outcome.exit_code,
            stdout_base64: BASE64.encode(&settlement.outcome.stdout),
            stdout_truncated: settlement.outcome.stdout_truncated,
            stderr_base64: BASE64.encode(&settlement.outcome.stderr),
            stderr_truncated: settlement.outcome.stderr_truncated,
            cleanup_verified: settlement.cleanup_verified,
        })
        .map_err(|_| {
            DomainError::new(
                ErrorCode::InternalError,
                "command settlement encoding failed",
            )
        })
    }
}

fn decode_stream(encoded: &str, reason: &'static str) -> Result<Vec<u8>, DomainError> {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    BASE64
        .decode(encoded)
        .map_err(|_| invalid_settlement(reason))
}

const fn invalid_settlement(reason: &'static str) -> DomainError {
    DomainError::new(ErrorCode::IoError, reason)
}

/// Decodes one process settlement a primitive reported. A payload that does not
/// decode is not evidence about the process at all, so it is an unverified cleanup and
/// never a pre-start rejection a surface could mistake for a clean run.
pub fn decode_android_command_settlement(
    payload: &[u8],
) -> Result<CommandProcessSettlement, crate::ExecutionFailure> {
    AndroidCommandSettlement::decode(payload).map_err(|error| crate::ExecutionFailure {
        error,
        cleanup_verified: false,
    })
}
