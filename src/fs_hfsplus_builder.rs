//! Fresh unpublished HFS+/HFSX construction. Existing-volume editing is separate.
use crate::{
    fs_copy::{CopyLimits, CopyNamePolicy, MetadataOutcome},
    fs_core::{Error, Reservation, Resources, Result, TreeSource},
    fs_hfsplus::{authoring_node::builder_inventory, bad, budget},
    storage::Storage,
};
use std::{io, sync::Arc};

/// Native catalog comparison profile.
#[derive(Clone, Copy, Debug)]
pub enum HfsPlusBuildCase {
    /// HFS+ ASCII case-folding. Non-ASCII comparison keys are rejected.
    AsciiFold,
    /// HFSX binary comparison of native UTF-16 code units.
    BinaryUtf16,
}
/// Explicit metadata treatment; neither policy promises full preservation.
#[derive(Clone, Copy, Debug)]
pub enum HfsPlusBuildMetadata {
    /// Replace metadata with deterministic ownership, permission and date defaults.
    ContentOnlyDefaults,
    /// Check native HFS catalog records and preserve ownership, permissions and
    /// all five dates. Remaining catalog fields and attributes are reported lost.
    NativeHfsCatalogFields,
}
/// Exact geometry, volume name and common-tree inventory ceilings.
pub struct HfsPlusBuildOptions {
    /// Power-of-two native allocation block size, 512 through 32768 bytes.
    pub allocation_block_bytes: u32,
    /// Native allocation block count, at least eight; layout must fit.
    pub blocks: u32,
    /// Explicit HFS+ or HFSX comparison semantics.
    pub case: HfsPlusBuildCase,
    /// Native volume label: 1 through 127 UTF-16 units, without NUL or slash.
    pub volume_name: Vec<u16>,
    /// Bounded source pagination and object inventory.
    pub limits: CopyLimits,
    /// Explicit source name conversion.
    pub names: CopyNamePolicy,
    /// Explicit metadata preservation or replacement policy.
    pub metadata: HfsPlusBuildMetadata,
}
/// Bound stable input inventory with deferred data/resource forks.
pub struct HfsPlusBuildPlan {
    inventory: builder_inventory::Plan,
    options: HfsPlusBuildOptions,
    _name_lease: Reservation,
}
impl HfsPlusBuildPlan {
    /// Inspect and bind source objects before destination mutation. Hardlink
    /// aliases, special objects and unsupported streams are rejected.
    pub fn prepare(
        source: Arc<dyn TreeSource>,
        options: HfsPlusBuildOptions,
        r: &Resources,
    ) -> Result<Self> {
        r.cancellation.check()?;
        if !(512..=32768).contains(&options.allocation_block_bytes)
            || !options.allocation_block_bytes.is_power_of_two()
            || options.blocks < 8
            || options.volume_name.is_empty()
            || options.volume_name.len() > 127
            || options.volume_name.iter().any(|u| *u == 0 || *u == 47)
        {
            return Err(bad("HFS+ build geometry or volume name"));
        }
        let name_bytes = (options.volume_name.capacity() as u64)
            .checked_mul(2)
            .ok_or_else(|| budget("HFS+ retained volume name capacity"))?;
        let lease = r.memory.reserve(name_bytes)?;
        let policy = match options.metadata {
            HfsPlusBuildMetadata::ContentOnlyDefaults => {
                builder_inventory::MetadataPolicy::ContentOnlyDefaults
            }
            HfsPlusBuildMetadata::NativeHfsCatalogFields => {
                builder_inventory::MetadataPolicy::NativeHfsCatalogFields
            }
        };
        let inventory = builder_inventory::Plan::new(
            source,
            options.limits,
            options.names,
            policy,
            matches!(options.case, HfsPlusBuildCase::BinaryUtf16),
            r,
        )?;
        Ok(Self {
            inventory,
            options,
            _name_lease: lease,
        })
    }
    /// Exact target byte length.
    pub fn image_bytes(&self) -> u64 {
        u64::from(self.options.allocation_block_bytes) * u64::from(self.options.blocks)
    }
    /// Per-object metadata decisions available before emission.
    pub fn metadata_outcomes(&self) -> &[MetadataOutcome] {
        self.inventory.outcomes()
    }
    /// Write an exclusively owned, unpublished destination of exactly the planned
    /// length. Supports short writes and checks cancellation between writes.
    /// This method does not flush or publish. On failure, discard the staged image.
    /// The destination must not alias any source storage.
    /// It must never be used to edit an existing filesystem.
    pub fn emit(&self, target: &mut dyn Storage, r: &Resources) -> Result<u64> {
        r.cancellation.check()?;
        if target
            .len()
            .map_err(|e| Error::io("HFS+ staging length", e))?
            != self.image_bytes()
        {
            return Err(bad("HFS+ staging length mismatch"));
        }
        self.inventory.emit(
            self.options.allocation_block_bytes,
            self.options.blocks,
            &self.options.volume_name,
            r,
            &mut |mut at, mut bytes| {
                while !bytes.is_empty() {
                    r.cancellation.check()?;
                    let n = target
                        .write_at(at, bytes)
                        .map_err(|e| Error::io("HFS+ staging write", e))?;
                    if n == 0 || n > bytes.len() {
                        return Err(Error::io(
                            "HFS+ staging short write",
                            io::Error::new(io::ErrorKind::WriteZero, "invalid write count"),
                        ));
                    }
                    at += n as u64;
                    bytes = &bytes[n..];
                }
                Ok(())
            },
        )
    }
}
