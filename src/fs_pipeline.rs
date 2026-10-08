//! Explicit per-layer outcomes for media pipelines with separate commits.
//!
//! Reports record caller-observed evidence. They do not perform operations,
//! infer durability from a successful write, or establish an atomic transaction
//! across container, partition, filesystem, copy and boot layers.
use std::fmt;

/// Version of the report contract and its textual representation.
pub const REPORT_VERSION: u32 = 1;

/// Independently validated or committed part of a media pipeline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Layer {
    /// Source discovery, inventory and validation.
    Source,
    /// Logical disk container management or independent conversion.
    Container,
    /// Partition table planning, commit and inspection.
    Partition,
    /// Filesystem authoring, mutation, barriers and allocation validation.
    Filesystem,
    /// Content and preservation-policy verification.
    Copy,
    /// Boot installation or independent boot verification.
    Boot,
    /// Artifact publication and publication-directory persistence.
    Publication,
}
impl Layer {
    /// All layers, in stable report order rather than operation order.
    pub const ALL: [Self; 7] = [
        Self::Source,
        Self::Container,
        Self::Partition,
        Self::Filesystem,
        Self::Copy,
        Self::Boot,
        Self::Publication,
    ];
    fn index(self) -> usize {
        match self {
            Self::Source => 0,
            Self::Container => 1,
            Self::Partition => 2,
            Self::Filesystem => 3,
            Self::Copy => 4,
            Self::Boot => 5,
            Self::Publication => 6,
        }
    }
    /// Stable name used by textual reports.
    pub fn name(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Container => "container",
            Self::Partition => "partition",
            Self::Filesystem => "filesystem",
            Self::Copy => "copy",
            Self::Boot => "boot",
            Self::Publication => "publication",
        }
    }
}
/// Assurance actually observed for the completed layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Completion {
    /// Declared validation completed; no mutation or durability inference.
    Validated,
    /// Mutation was accepted; its durability is not confirmed.
    Applied,
    /// Required barriers and declared verification completed.
    Durable,
    /// Final artifact became visible; directory durability is not confirmed.
    Published,
}
/// State that must survive reporting an unsuccessful layer operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureState {
    /// No target mutation was accepted.
    Unchanged,
    /// Only an unpublished staging artifact may have changed.
    UnpublishedStaging,
    /// The artifact was published; directory durability is uncertain.
    PublishedDurabilityUncertain,
    /// A live filesystem requires its explicit recovery protocol.
    FilesystemRecoveryRequired,
    /// Mutation or barrier completion cannot be established.
    Uncertain,
}
/// Explicit next action, without suggesting rollback across independent layers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Recovery {
    /// No mutation recovery is required.
    None,
    /// Discard the unpublished staging artifact and restart planning.
    DiscardStaging,
    /// Recover the named filesystem using its retained protocol evidence.
    Filesystem {
        /// Protocol, saved anchor or recovery identity needed by the caller.
        evidence: String,
    },
    /// Inspect the published artifact and explicitly finish directory persistence.
    InspectPublishedArtifact,
    /// Stop mutation and inspect the affected layers before choosing recovery.
    InspectAffectedLayers,
}
/// Outcome for one independently owned layer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// No operation or validation was attempted.
    NotAttempted,
    /// This pipeline explicitly excludes the layer.
    NotApplicable {
        /// Why the layer is inapplicable.
        reason: String,
    },
    /// The caller observed the declared assurance.
    Completed {
        /// Exact assurance; successful writes alone are not durable completion.
        assurance: Completion,
        /// Profile, verification and preservation scope.
        detail: String,
    },
    /// Failure leaves the declared state and recovery obligation.
    Failed {
        /// State of already accepted operations.
        state: FailureState,
        /// Original failure description; callers retain the original typed error.
        reason: String,
        /// Explicit recovery action for this layer.
        recovery: Recovery,
    },
}
/// Fixed-size per-layer report; completion of one layer never updates another.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PipelineReport {
    outcomes: [Outcome; 7],
}
impl Default for PipelineReport {
    fn default() -> Self {
        Self {
            outcomes: std::array::from_fn(|_| Outcome::NotAttempted),
        }
    }
}
impl PipelineReport {
    /// Start a report with every layer explicitly unattempted.
    pub fn new() -> Self {
        Self::default()
    }
    /// Read the caller-recorded outcome for a layer.
    pub fn outcome(&self, layer: Layer) -> &Outcome {
        &self.outcomes[layer.index()]
    }
    /// Replace one layer's outcome after observing the corresponding operation.
    ///
    /// Callers supply honest scope and evidence. This records no implicit
    /// rollback, boot validation, external-writer exclusion or atomicity claim.
    pub fn record(&mut self, layer: Layer, outcome: Outcome) {
        self.outcomes[layer.index()] = outcome;
    }
    /// Record an observed result and return it without changing its error type.
    ///
    /// The caller declares success assurance and the state/recovery obligation
    /// on failure. This never derives persistence from `Ok` or rolls back a
    /// previously completed layer. The original typed error stays in the result.
    pub fn observe<T, E: fmt::Display>(
        &mut self,
        layer: Layer,
        detail: &str,
        success: Completion,
        failure: FailureState,
        recovery: Recovery,
        result: Result<T, E>,
    ) -> Result<T, E> {
        self.record(
            layer,
            match &result {
                Ok(_) => Outcome::Completed {
                    assurance: success,
                    detail: detail.into(),
                },
                Err(error) => Outcome::Failed {
                    state: failure,
                    reason: error.to_string(),
                    recovery,
                },
            },
        );
        result
    }
}
impl fmt::Display for PipelineReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "pipeline_report_version={REPORT_VERSION}")?;
        for layer in Layer::ALL {
            // Debug escaping keeps native names/error text on a single record.
            writeln!(
                f,
                "pipeline_layer={} outcome={:?}",
                layer.name(),
                self.outcome(layer)
            )?;
        }
        Ok(())
    }
}
