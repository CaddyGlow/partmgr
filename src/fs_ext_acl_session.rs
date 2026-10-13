//! Private storage-owning classic ACL lifecycle. No public write admission.
use super::{
    acl_plan, acl_recovery, invalid,
    jbd::acl::{self, LifecycleLimits, Outcome},
};
use crate::{
    fs_core::{Budget, Cancellation, Error, ErrorKind, NativeName, Resources},
    platform::{
        io,
        sync::atomic::{AtomicU64, Ordering},
    },
    storage::Storage,
};
static NEXT: AtomicU64 = AtomicU64::new(1);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum State {
    Ready,
    NeedsRecovery,
}
pub(super) struct Session<S: Storage> {
    storage: S,
    scope: u128,
    generation: u64,
    state: State,
    limits: LifecycleLimits,
    memory: Budget,
}
impl<S: Storage> Session<S> {
    /// Cold opening grants no readiness. Explicit recovery must prove a clean
    /// inactive profile or this exact typed original/canonical transaction scope.
    pub fn open_for_recovery(
        storage: S,
        limits: LifecycleLimits,
        r: &Resources,
    ) -> io::Result<Self> {
        r.cancellation.check().map_err(io::Error::other)?;
        let len = storage.len()?;
        r.cancellation.check().map_err(io::Error::other)?;
        if len > limits.proof.source_bytes as u64 {
            return Err(invalid("acl session source ceiling"));
        }
        let serial = NEXT
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| invalid("acl session identity exhausted"))?;
        Ok(Self {
            storage,
            scope: (28u128 << 64) | u128::from(serial),
            generation: 1,
            state: State::NeedsRecovery,
            limits,
            memory: r.memory.clone(),
        })
    }
    fn resources(&self, cancellation: &Cancellation) -> Resources {
        Resources {
            memory: self.memory.clone(),
            cancellation: cancellation.clone(),
        }
    }
    pub fn state(&self) -> State {
        self.state
    }
    pub fn recover(&mut self, cancellation: &Cancellation) -> io::Result<Outcome> {
        let r = self.resources(cancellation);
        r.cancellation.check().map_err(io::Error::other)?;
        let next = self
            .generation
            .checked_add(1)
            .ok_or_else(|| invalid("acl session generation exhausted"))?;
        self.state = State::NeedsRecovery;
        let result = acl::recover(
            &mut self.storage,
            self.scope,
            self.generation,
            self.limits,
            &r,
        )?;
        r.cancellation.check().map_err(io::Error::other)?;
        self.generation = next;
        self.state = State::Ready;
        Ok(result)
    }
    pub fn plan(
        &self,
        path: &[NativeName],
        operation: acl_plan::Operation<'_>,
        ctime: u32,
        cancellation: &Cancellation,
    ) -> io::Result<acl_plan::Plan> {
        if self.state != State::Ready {
            return Err(invalid("acl session requires explicit recovery"));
        }
        let r = self.resources(cancellation);
        acl_plan::plan(
            &self.storage,
            self.scope,
            self.generation,
            path,
            operation,
            ctime,
            self.limits.proof.planning,
            &r,
        )
    }
    /// Intent is independently matched to the sealed plan before any preparation.
    /// On publication/recovery error readiness remains fenced until explicit recover.
    pub fn commit(
        &mut self,
        plan: acl_plan::Plan,
        path: &[NativeName],
        operation: acl_plan::Operation<'_>,
        ctime: u32,
        cancellation: &Cancellation,
    ) -> io::Result<Outcome> {
        if self.state != State::Ready {
            return Err(invalid("acl session requires explicit recovery"));
        }
        let r = self.resources(cancellation);
        r.cancellation.check().map_err(io::Error::other)?;
        if plan.binding() != (self.scope, self.generation) {
            return Err(io::Error::other(Error::new(
                ErrorKind::StalePlan,
                "acl session foreign or stale plan",
            )));
        }
        let observed_intent =
            acl_plan::intent_digest(path, operation, ctime, self.limits.proof.intent_bytes, &r)?;
        if plan.intent() != &observed_intent {
            return Err(io::Error::other(Error::new(
                ErrorKind::StalePlan,
                "acl session supplied intent differs from sealed plan",
            )));
        }
        let next = self
            .generation
            .checked_add(1)
            .ok_or_else(|| invalid("acl session generation exhausted"))?;
        let capsule = if plan.changed {
            Some(acl_recovery::seal(
                &plan,
                path,
                operation,
                ctime,
                self.limits.proof,
                &r,
            )?)
        } else {
            None
        };
        self.state = State::NeedsRecovery;
        let result = acl::commit(
            &mut self.storage,
            (self.scope, self.generation),
            &plan,
            capsule.as_ref(),
            self.limits,
            &r,
        )?;
        r.cancellation.check().map_err(io::Error::other)?;
        if plan.changed {
            self.generation = next;
        }
        self.state = State::Ready;
        Ok(result)
    }
    pub fn into_storage(self) -> S {
        self.storage
    }
}
