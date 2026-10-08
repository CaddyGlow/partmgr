//! Copy orchestration diagnostics and explicit no-clobber publication.
use partmgr::fs_pipeline::{Completion, FailureState, Layer, Outcome, PipelineReport, Recovery};
use std::{
    io,
    path::{Path, PathBuf},
};

pub struct CopyPipeline {
    pub report: PipelineReport,
    active: Option<(Layer, FailureState, Recovery)>,
}
impl CopyPipeline {
    pub fn new() -> Self {
        Self {
            report: PipelineReport::new(),
            active: None,
        }
    }
    pub fn raw(&mut self, partitioned: bool) {
        self.report.record(
            Layer::Container,
            Outcome::NotApplicable {
                reason: "raw staging; no virtual-container conversion".into(),
            },
        );
        if !partitioned {
            self.report.record(
                Layer::Partition,
                Outcome::NotApplicable {
                    reason: "standalone filesystem output".into(),
                },
            );
        }
    }
    pub fn begin(&mut self, layer: Layer, state: FailureState, recovery: Recovery) {
        self.active = Some((layer, state, recovery));
    }
    pub fn complete(&mut self, layer: Layer, assurance: Completion, detail: &str) {
        assert_eq!(self.active.as_ref().map(|v| v.0), Some(layer));
        self.report.record(
            layer,
            Outcome::Completed {
                assurance,
                detail: detail.into(),
            },
        );
        self.active = None;
    }
    pub fn finish(&mut self, error: Option<&dyn std::error::Error>) {
        if let Some(error) = error {
            if let Some((layer, state, recovery)) = self.active.take() {
                self.report.record(
                    layer,
                    Outcome::Failed {
                        state,
                        reason: error.to_string(),
                        recovery,
                    },
                );
            }
            eprint!("{}", self.report);
        } else {
            print!("{}", self.report);
        }
    }
}

#[derive(Debug)]
struct PublicationDirectoryFailure {
    artifact: PathBuf,
    cause: io::Error,
}
impl std::fmt::Display for PublicationDirectoryFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "image published at {}; publication-directory durability uncertain: {}",
            self.artifact.display(),
            self.cause
        )
    }
}
impl std::error::Error for PublicationDirectoryFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}
pub fn publish(
    staged: tempfile::NamedTempFile,
    destination: &Path,
    parent: &Path,
    report: &mut PipelineReport,
) -> Result<(), Box<dyn std::error::Error>> {
    report.observe(
        Layer::Publication,
        "no-clobber artifact publication; directory barrier pending",
        Completion::Published,
        FailureState::Uncertain,
        Recovery::InspectAffectedLayers,
        staged.persist_noclobber(destination),
    )?;
    let barrier = std::fs::File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|cause| {
            io::Error::new(
                cause.kind(),
                PublicationDirectoryFailure {
                    artifact: destination.into(),
                    cause,
                },
            )
        });
    report.observe(
        Layer::Publication,
        "published artifact and publication-directory barrier confirmed",
        Completion::Durable,
        FailureState::PublishedDurabilityUncertain,
        Recovery::InspectPublishedArtifact,
        barrier,
    )?;
    Ok(())
}
