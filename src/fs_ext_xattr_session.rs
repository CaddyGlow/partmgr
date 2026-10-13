//! Private storage-owning classic user-xattr lifecycle. No public write admission.
use super::{
    invalid,
    jbd::xattr::{self, LifecycleLimits, Outcome},
    xattr_plan, xattr_recovery, xattr_write,
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
            return Err(invalid("xattr session source ceiling"));
        }
        let serial = NEXT
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| invalid("xattr session identity exhausted"))?;
        Ok(Self {
            storage,
            scope: (27u128 << 64) | u128::from(serial),
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
            .ok_or_else(|| invalid("xattr session generation exhausted"))?;
        self.state = State::NeedsRecovery;
        let result = xattr::recover(
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
        key: &[u8],
        mutation: xattr_write::Mutation<'_>,
        cancellation: &Cancellation,
    ) -> io::Result<xattr_plan::Plan> {
        if self.state != State::Ready {
            return Err(invalid("xattr session requires explicit recovery"));
        }
        let r = self.resources(cancellation);
        xattr_plan::plan(
            &self.storage,
            self.scope,
            self.generation,
            path,
            key,
            mutation,
            self.limits.proof.planning,
            &r,
        )
    }
    /// Intent is independently matched to the sealed plan before any preparation.
    /// On publication/recovery error readiness remains fenced until explicit recover.
    pub fn commit(
        &mut self,
        plan: xattr_plan::Plan,
        path: &[NativeName],
        key: &[u8],
        mutation: xattr_write::Mutation<'_>,
        cancellation: &Cancellation,
    ) -> io::Result<Outcome> {
        if self.state != State::Ready {
            return Err(invalid("xattr session requires explicit recovery"));
        }
        let r = self.resources(cancellation);
        r.cancellation.check().map_err(io::Error::other)?;
        if plan.binding() != (self.scope, self.generation) {
            return Err(io::Error::other(Error::new(
                ErrorKind::StalePlan,
                "xattr session foreign or stale plan",
            )));
        }
        let observed_intent =
            xattr_plan::intent_digest(path, key, mutation, self.limits.proof.intent_bytes, &r)?;
        if plan.intent() != &observed_intent {
            return Err(io::Error::other(Error::new(
                ErrorKind::StalePlan,
                "xattr session supplied intent differs from sealed plan",
            )));
        }
        let next = self
            .generation
            .checked_add(1)
            .ok_or_else(|| invalid("xattr session generation exhausted"))?;
        let capsule = if plan.changed {
            Some(xattr_recovery::seal(
                &plan,
                path,
                key,
                mutation,
                self.limits.proof,
                &r,
            )?)
        } else {
            None
        };
        self.state = State::NeedsRecovery;
        let result = xattr::commit(
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
