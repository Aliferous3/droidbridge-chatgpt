//! The App-UID execution guard scope.
//!
//! One guarded process owns exactly one proof whose identity is the Runtime instance
//! that admitted it. The APK Runtime host writes those proofs under one scope, so a
//! guarded command has a single proof-ownership path (S-AUTH-CMD-001, S-EXEC-001).

use contract::{ErrorCode, UuidV4};
use domain::DomainError;
use serde::Serialize;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock, atomic::AtomicBool},
};

/// The addressed owner of every guard proof this process writes.
///
/// `base`, `boot_id`, `runtime_epoch`, and `runtime_instance_id` are only read from the
/// `unix` proof-writing path, which does not compile on a non-Unix host.
#[derive(Clone)]
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) struct GuardScope {
    base: PathBuf,
    boot_id: UuidV4,
    runtime_epoch: UuidV4,
    runtime_instance_id: UuidV4,
    quarantined: Arc<AtomicBool>,
}

/// The settlement of one guard proof, as the App surface reports it to its caller.
#[derive(Serialize)]
pub(crate) struct GuardSettlement {
    pub(crate) cleanup_verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) shell_exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cause: Option<&'static str>,
}

static GUARD_SCOPE: OnceLock<Mutex<Option<GuardScope>>> = OnceLock::new();

fn scope_slot() -> &'static Mutex<Option<GuardScope>> {
    GUARD_SCOPE.get_or_init(|| Mutex::new(None))
}

/// Publishes the scope this process is the guard owner under, so a proof always names
/// the Runtime instance that admitted it.
pub(crate) fn publish_scope(scope: GuardScope) -> Result<(), DomainError> {
    *scope_slot()
        .lock()
        .map_err(|_| DomainError::new(ErrorCode::InternalError, "guard scope lock failed"))? =
        Some(scope);
    Ok(())
}

pub(crate) fn scope() -> Result<GuardScope, DomainError> {
    scope_slot()
        .lock()
        .map_err(|_| DomainError::new(ErrorCode::InternalError, "guard scope lock failed"))?
        .clone()
        .ok_or_else(|| {
            DomainError::new(
                ErrorCode::CapabilityUnavailable,
                "execution guard scope is unavailable",
            )
        })
}

pub(crate) fn is_quarantined() -> bool {
    scope_slot()
        .lock()
        .ok()
        .and_then(|slot| slot.as_ref().map(GuardScope::quarantined))
        .unwrap_or(false)
}

impl GuardScope {
    pub(crate) fn new(
        base: PathBuf,
        runtime_epoch: UuidV4,
        runtime_instance_id: UuidV4,
    ) -> Result<Self, DomainError> {
        ignore_sigpipe();
        Ok(Self {
            base,
            boot_id: crate::read_boot_id()?,
            runtime_epoch,
            runtime_instance_id,
            quarantined: Arc::new(AtomicBool::new(false)),
        })
    }

    pub(crate) fn quarantined(&self) -> bool {
        self.quarantined.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub(crate) fn quarantine(&self) {
        self.quarantined
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/// A guarded command's input is a pipe this process writes, so a command that closes its
/// input early must not deliver a fatal signal to the Runtime process.
#[cfg(unix)]
fn ignore_sigpipe() {
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
}

#[cfg(not(unix))]
fn ignore_sigpipe() {}

#[cfg(unix)]
mod unix {
    use super::{GuardScope, GuardSettlement};
    use crate::{ProcFacts, guard_proof_capacity_available, sync_directory};
    use contract::{ErrorCode, UuidV4};
    use domain::DomainError;
    use persistence::{
        GuardIdentity, GuardProofDirectory, GuardProofReader, GuardRecovery, classify_guard_proof,
        encode_guard_frame,
    };
    use std::{
        fs,
        io::Write,
        os::unix::fs::OpenOptionsExt,
        path::PathBuf,
        thread,
        time::{Duration, Instant},
    };

    const REAP_POLL_MS: u64 = 20;

    impl GuardScope {
        fn directory(&self) -> PathBuf {
            self.base
                .join("execution-guards")
                .join(self.boot_id.as_str())
        }

        fn identity(&self, execution_id: &UuidV4) -> GuardIdentity {
            GuardIdentity {
                runtime_epoch: self.runtime_epoch.clone(),
                runtime_instance_id: self.runtime_instance_id.clone(),
                execution_id: execution_id.clone(),
                boot_id: self.boot_id.clone(),
            }
        }

        /// Writes the identity frame and returns the proof the guard must inherit. The
        /// header is the whole proof until the guard records a start, which is what
        /// makes an aborted proof distinguishable from an unsettled one.
        pub(crate) fn prepare(&self, execution_id: &UuidV4) -> Result<fs::File, DomainError> {
            if self.quarantined() || !guard_proof_capacity_available(&self.base) {
                return Err(DomainError::new(
                    ErrorCode::ResourceLimit,
                    "execution guard proof admission rejected",
                ));
            }
            let directory = self.directory();
            fs::create_dir_all(&directory)
                .map_err(os("cannot create execution guard directory"))?;
            sync_directory(&directory)?;
            let identity = self.identity(execution_id);
            let header = encode_guard_frame(&identity)?;
            let proof_path = directory.join(format!("{}.proof", identity.execution_id.as_str()));
            let mut proof = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&proof_path)
                .map_err(os("cannot create execution guard proof"))?;
            if let Err(error) = proof.write_all(&header).and_then(|_| proof.sync_all()) {
                drop(proof);
                let _ = fs::remove_file(proof_path);
                let _ = sync_directory(&directory);
                return Err(DomainError::os(
                    ErrorCode::IoError,
                    "guard proof header write failed",
                    &error,
                ));
            }
            Ok(proof)
        }

        pub(crate) fn settle(&self, execution_id: &UuidV4) -> Result<GuardSettlement, DomainError> {
            let identity = self.identity(execution_id);
            let deadline = Instant::now() + Duration::from_millis(5_000);
            let recovery = loop {
                let bytes = GuardProofDirectory::new(&self.base)
                    .read_proof(&self.boot_id, execution_id)?
                    .unwrap_or_default();
                let recovery = classify_guard_proof(
                    self.boot_id.as_str(),
                    &self.boot_id,
                    &identity,
                    &bytes,
                    &ProcFacts,
                )?;
                if matches!(recovery, GuardRecovery::Clean { .. }) || Instant::now() >= deadline {
                    break recovery;
                }
                thread::sleep(Duration::from_millis(REAP_POLL_MS));
            };
            let result = match recovery {
                GuardRecovery::Clean { clean: Some(clean) } => GuardSettlement {
                    cleanup_verified: true,
                    shell_exit_code: clean.shell_exit_code,
                    cause: Some(guard_cause_token(clean.cause)),
                },
                GuardRecovery::Clean { clean: None }
                | GuardRecovery::Live { .. }
                | GuardRecovery::Unverified => GuardSettlement {
                    cleanup_verified: false,
                    shell_exit_code: None,
                    cause: None,
                },
            };
            if result.cleanup_verified {
                let directory = self.directory();
                fs::remove_file(directory.join(format!("{}.proof", execution_id.as_str())))
                    .map_err(os("cannot remove clean execution guard proof"))?;
                sync_directory(&directory)?;
            } else {
                self.quarantine();
            }
            Ok(result)
        }

        /// Retires a proof whose guard never recorded a start. Only exact header bytes
        /// prove that, so a guard that already started is never retired here.
        pub(crate) fn abort(&self, execution_id: &UuidV4) -> Result<bool, DomainError> {
            let identity = self.identity(execution_id);
            let directory = self.directory();
            let path = directory.join(format!("{}.proof", execution_id.as_str()));
            let bytes = fs::read(&path).map_err(os("cannot read execution guard proof"))?;
            if bytes != encode_guard_frame(&identity)? {
                return Ok(false);
            }
            fs::remove_file(path).map_err(os("cannot retire execution guard proof"))?;
            sync_directory(&directory)?;
            Ok(true)
        }
    }

    const fn guard_cause_token(cause: persistence::GuardCleanCause) -> &'static str {
        match cause {
            persistence::GuardCleanCause::Exited => "exited",
            persistence::GuardCleanCause::Cancelled => "cancelled",
            persistence::GuardCleanCause::Timeout => "timeout",
            persistence::GuardCleanCause::OwnerLost => "owner_lost",
        }
    }

    fn os(reason: &'static str) -> impl Fn(std::io::Error) -> DomainError {
        move |error| DomainError::os(ErrorCode::IoError, reason, &error)
    }

    pub(crate) fn settle_proof(execution_id: &UuidV4) -> Result<GuardSettlement, DomainError> {
        super::scope()?.settle(execution_id)
    }

    pub(crate) fn abort_proof(execution_id: &UuidV4) -> Result<bool, DomainError> {
        super::scope()?.abort(execution_id)
    }

    pub(crate) fn prepare_proof(execution_id: &UuidV4) -> Result<fs::File, DomainError> {
        super::scope()?.prepare(execution_id)
    }
}

#[cfg(unix)]
pub(crate) use unix::{abort_proof, prepare_proof, settle_proof};

// The guard is a Unix process primitive; a process without it cannot prove clean
// shutdown, so every entry point reports the capability instead of degrading.
#[cfg(not(unix))]
mod fallback {
    use super::GuardSettlement;
    use contract::{ErrorCode, UuidV4};
    use domain::DomainError;

    fn unavailable() -> DomainError {
        DomainError::new(
            ErrorCode::CapabilityUnavailable,
            "execution guard requires Unix",
        )
    }

    #[allow(dead_code)] // only reachable via the #[cfg(unix)] JNI entry point.
    pub(crate) fn prepare_proof(_execution_id: &UuidV4) -> Result<std::fs::File, DomainError> {
        Err(unavailable())
    }

    pub(crate) fn settle_proof(_execution_id: &UuidV4) -> Result<GuardSettlement, DomainError> {
        Ok(GuardSettlement {
            cleanup_verified: false,
            shell_exit_code: None,
            cause: None,
        })
    }

    pub(crate) fn abort_proof(_execution_id: &UuidV4) -> Result<bool, DomainError> {
        Ok(false)
    }
}

#[cfg(not(unix))]
#[allow(unused_imports)] // prepare_proof is only called from the #[cfg(unix)] JNI entry point.
pub(crate) use fallback::{abort_proof, prepare_proof, settle_proof};
