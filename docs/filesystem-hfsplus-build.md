# Fresh HFS+/HFSX image construction

`fs_hfsplus_builder::HfsPlusBuildPlan` prepares a stable common-tree source and
streams a fresh filesystem into an exclusively owned, unpublished `Storage`.
The destination must have exactly `plan.image_bytes()` bytes and must not alias
source storage. Emission overwrites the complete destination. Any failed staging
output must be discarded.

```rust
use partmgr::{
    fs_copy::{CopyLimits, CopyNamePolicy},
    fs_core::{Resources, Result, TreeSource},
    fs_hfsplus_builder::*,
    storage::Storage,
};
use std::sync::Arc;

fn stage(
    source: Arc<dyn TreeSource>,
    target: &mut dyn Storage,
    resources: &Resources,
) -> Result<u64> {
    let plan = HfsPlusBuildPlan::prepare(source, HfsPlusBuildOptions {
        allocation_block_bytes: 4096,
        blocks: 256,
        case: HfsPlusBuildCase::BinaryUtf16,
        volume_name: "Fresh".encode_utf16().collect(),
        limits: CopyLimits { objects: 128, pages: 256, page_entries: 16 },
        names: CopyNamePolicy::StrictUtf8,
        metadata: HfsPlusBuildMetadata::ContentOnlyDefaults,
    }, resources)?;
    // Review plan.metadata_outcomes() before writing.
    plan.emit(target, resources)
}
```

`AsciiFold` produces the bounded ASCII case-fold HFS+ profile; `BinaryUtf16`
produces HFSX with native UTF-16 comparison. Data and resource forks are deferred,
short reads/writes are supported, and metadata/allocation buffers are budgeted.
Hardlink aliases, special objects and other streams reject during inventory.

`ContentOnlyDefaults` explicitly replaces metadata with deterministic defaults.
`NativeHfsCatalogFields` requires checked retained HFS catalog metadata and
preserves ownership, permissions and five dates. Its reports explicitly retain
the remaining information loss; neither policy provides full metadata capture.

Emission writes headers last but does not flush or publish. Durability,
independent filesystem verification, container persistence and final publication
belong to the caller's pipeline. This API supplies no recovery or mutation
authority for an existing filesystem.

Frozen public consumer/native evidence is recorded in
`/data/cache/partmgr-hfsplus-public-builder-native-v2/root-audit.json`.
Native checker evidence uses the explicit regular-file ioctl adapter; macOS
validation remains open.
