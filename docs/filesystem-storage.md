# Filesystem storage foundation

`fs_storage::BoundedSession<S: Storage>` owns its backend and retains the
backend's lock. It exposes fixed bounded byte geometry, positional reads and
short writes, constant-scratch zeroing, and explicit flush. It does not expose
the backend, resizing, snapshot management, or discard. Bounds are checked for
the entire zero request before mutation. Errors from writes and flush retain
`UncertainMutation`, and uncertainty is sticky even after subsequent flush.
Successful flush delegates the backend's existing medium durability promise;
publication-directory durability is a separate orchestration step.

`SectorGeometry` records known logical and physical sizes separately. Unknown
values remain unknown. Neither sector size implies filesystem block size or
atomic sector writes. Callers must enforce external exclusivity and immutable
backing parents; advisory file locks do not exclude mounted access or writers
that ignore locks.

`ImmutableRegion` reuses `virtdisk::DiskView`: it retains its immutable source,
source context, partition annotation, and shared read budget. It is separate
from mutable sessions, which do not implement immutable `ReadAt`.

## R4 dependency release gate

The published `virtdisk` 0.1.0 dependency used by this crate contains immutable
read APIs only. The neighboring development repository provides `ImageWriter`,
`WriteAt`, and `InspectImage`, but these APIs are absent from the published
crate. Consequently the actual ImageWriter bridge and virtual-container
integration acceptance tests remain gated on a release containing those APIs.
No sibling-path override is used. The minimum published version is **not yet
established**. Generic session and raw regular-file tests do not establish the
ImageWriter integration gate or container performance requirements.

The following prospective integration code uses the reviewed development API;
it is unavailable with the current published dependency. Keep the wrapper
private and pass it directly into `BoundedSession`; never expose its writer.

```rust,ignore
use std::io;
use partmgr::{fs_storage::{BoundedSession, SectorGeometry}, storage::Storage};
use virtdisk::{Capability, ImageOperation, ImageWriter, InspectImage, WriteAt};

struct WriterStorage(ImageWriter);
impl Storage for WriterStorage {
    fn len(&self) -> io::Result<u64> { Ok(WriteAt::len(&self.0)) }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.0.read_exact_at(offset, out)
    }
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> io::Result<usize> {
        self.0.write_all_at(offset, bytes)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { WriteAt::flush(&self.0) }
}
fn session(writer: ImageWriter, start: u64, length: u64)
    -> io::Result<BoundedSession<impl Storage>>
{
    let facts = writer.inspection();
    for operation in [ImageOperation::Read, ImageOperation::Write, ImageOperation::Flush] {
        if facts.capabilities.get(operation) != Capability::Supported {
            return Err(io::ErrorKind::Unsupported.into());
        }
    }
    let geometry = SectorGeometry::new(
        facts.geometry.logical_sector_size,
        facts.geometry.physical_sector_size,
    )?;
    BoundedSession::new(WriterStorage(writer), start, length, geometry)
}
```

`write_all_at` success becomes a full-length `Storage::write_at` result; failures
propagate without inventing a partial count and the enclosing session records
uncertainty. Inspection and capabilities come from the handle, not the family.
When the dependency release exists, compile and test this bridge against that
published version, then exercise raw and supported container profiles,
read-after-write, bounds/overflow, partial failures and flush failures before
claiming R4 completion. Preserve the published compatibility read APIs and
separately measure performance before declaring the backend sufficient.
