use crate::{
    AdmittedExecution, CapabilitySnapshot, ExecutionCancelOutcome, ExecutionFailure,
    ExecutionPayload, ExecutionPort, FilesystemCandidate, FilesystemPreflightPort, PortFuture,
};
use contract::{ErrorCode, FilesystemCall, UuidV4};
use domain::{AdmittedExecutor, DomainError, ExecutorRequest, NetworkRoute, resolve_executor};

pub(crate) fn resolve_execution(
    capability: &CapabilitySnapshot,
    request: ExecutorRequest,
) -> Result<AdmittedExecutor, DomainError> {
    let mut facts = capability.resolver_facts;
    if matches!(
        request,
        ExecutorRequest::Filesystem { .. }
            | ExecutorRequest::Network(NetworkRoute::InspectOrDiagnose)
    ) {
        facts.app_native = capability.context.app_execution_surface;
        facts.generations.app_native = capability.fence.host_generation;
    }
    resolve_executor(
        capability.context.host,
        capability.fence.clone(),
        facts,
        request,
    )
}

/// The one installed execution surface of a Runtime host. Each host installs exactly
/// one delegate per payload family it owns, so a payload has one handling path.
#[derive(Clone)]
pub struct CompositeExecutionSurface<
    F,
    N = UnavailableExecutionDelegate,
    V = UnavailableExecutionDelegate,
    D = UnavailableExecutionDelegate,
> {
    filesystem: F,
    network: N,
    visual: V,
    android: D,
}

/// The delegate of a payload family a host does not own. It has no handling path to
/// install, so every request for that family is a typed unavailability.
#[derive(Clone, Copy, Debug)]
pub struct UnavailableExecutionDelegate;

impl ExecutionPort for UnavailableExecutionDelegate {
    fn claim_and_start<'a>(
        &'a self,
        _execution: AdmittedExecution,
    ) -> PortFuture<'a, Result<crate::ExecutionCompletion, ExecutionFailure>> {
        Box::pin(async move {
            Err(ExecutionFailure {
                error: DomainError::new(
                    ErrorCode::Unsupported,
                    "execution payload has no installed feature delegate",
                ),
                cleanup_verified: true,
            })
        })
    }

    fn cancel<'a>(
        &'a self,
        _execution_id: &'a UuidV4,
    ) -> PortFuture<'a, Result<ExecutionCancelOutcome, DomainError>> {
        Box::pin(async move { Ok(ExecutionCancelOutcome::CompletionWon) })
    }
}

impl<F>
    CompositeExecutionSurface<
        F,
        UnavailableExecutionDelegate,
        UnavailableExecutionDelegate,
        UnavailableExecutionDelegate,
    >
{
    pub const fn new(filesystem: F) -> Self {
        Self {
            filesystem,
            network: UnavailableExecutionDelegate,
            visual: UnavailableExecutionDelegate,
            android: UnavailableExecutionDelegate,
        }
    }
}

impl<F, N, V, D> CompositeExecutionSurface<F, N, V, D> {
    pub fn with_network<N2>(self, network: N2) -> CompositeExecutionSurface<F, N2, V, D> {
        CompositeExecutionSurface {
            filesystem: self.filesystem,
            network,
            visual: self.visual,
            android: self.android,
        }
    }

    pub fn with_visual<V2>(self, visual: V2) -> CompositeExecutionSurface<F, N, V2, D> {
        CompositeExecutionSurface {
            filesystem: self.filesystem,
            network: self.network,
            visual,
            android: self.android,
        }
    }

    pub fn with_android<D2>(self, android: D2) -> CompositeExecutionSurface<F, N, V, D2> {
        CompositeExecutionSurface {
            filesystem: self.filesystem,
            network: self.network,
            visual: self.visual,
            android,
        }
    }
}

impl<F: FilesystemPreflightPort, N, V, D> FilesystemPreflightPort
    for CompositeExecutionSurface<F, N, V, D>
{
    fn preflight(
        &self,
        candidate: FilesystemCandidate,
        call: &FilesystemCall,
    ) -> Result<domain::Preflight, DomainError> {
        self.filesystem.preflight(candidate, call)
    }
}

impl<F: ExecutionPort, N: ExecutionPort, V: ExecutionPort, D: ExecutionPort> ExecutionPort
    for CompositeExecutionSurface<F, N, V, D>
{
    fn claim_and_start<'a>(
        &'a self,
        execution: AdmittedExecution,
    ) -> PortFuture<'a, Result<crate::ExecutionCompletion, ExecutionFailure>> {
        match &execution.payload {
            ExecutionPayload::FilesystemCall(_) => self.filesystem.claim_and_start(execution),
            ExecutionPayload::NetworkCall(_) => self.network.claim_and_start(execution),
            ExecutionPayload::VisualCall(_) => self.visual.claim_and_start(execution),
            ExecutionPayload::AndroidCall(_) => self.android.claim_and_start(execution),
            _ => Box::pin(async move {
                Err(ExecutionFailure {
                    error: DomainError::new(
                        ErrorCode::Unsupported,
                        "execution payload has no installed feature delegate",
                    ),
                    cleanup_verified: true,
                })
            }),
        }
    }

    fn cancel<'a>(
        &'a self,
        execution_id: &'a UuidV4,
    ) -> PortFuture<'a, Result<ExecutionCancelOutcome, DomainError>> {
        Box::pin(async move {
            let filesystem = self.filesystem.cancel(execution_id).await?;
            if !matches!(filesystem, ExecutionCancelOutcome::CompletionWon) {
                return Ok(filesystem);
            }
            let network = self.network.cancel(execution_id).await?;
            if !matches!(network, ExecutionCancelOutcome::CompletionWon) {
                return Ok(network);
            }
            let visual = self.visual.cancel(execution_id).await?;
            if !matches!(visual, ExecutionCancelOutcome::CompletionWon) {
                return Ok(visual);
            }
            let android = self.android.cancel(execution_id).await?;
            Ok(match android {
                ExecutionCancelOutcome::CompletionWon => filesystem,
                outcome => outcome,
            })
        })
    }
}

pub(crate) fn new_uuid() -> Result<UuidV4, DomainError> {
    UuidV4::parse(uuid::Uuid::new_v4().to_string())
        .map_err(|_| DomainError::new(ErrorCode::InternalError, "UUID generation failed"))
}

pub(crate) fn execution_fence(execution: &AdmittedExecution) -> domain::AdmissionFence {
    domain::AdmissionFence {
        runtime_epoch: execution.executor.fence.runtime_epoch.clone(),
        host_generation: execution.executor.fence.host_generation,
        runtime_instance_id: execution.executor.fence.runtime_instance_id.clone(),
    }
}

pub(crate) fn execution_failure(
    code: ErrorCode,
    message: &'static str,
    cleanup_verified: bool,
) -> ExecutionFailure {
    ExecutionFailure {
        error: DomainError::new(code, message),
        cleanup_verified,
    }
}
