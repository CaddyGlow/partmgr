# Filesystem support and dependency status

This matrix records the initial implementation inventory (2026-10-07), before
new filesystem modules are accepted. A planned profile is not operational support.
Update an operation only when its code and independent evidence meet
`FILESYSTEM_PLAN.md`; attach the evidence record. The specification/profile
inventory is in [filesystem-specifications.md](filesystem-specifications.md).

| Family/profile | Recognition/strict open | File/metadata access | New build | Existing edits/recovery | Independent/performance/native evidence |
| --- | --- | --- | --- | --- | --- |
| FAT12/16/32 and VFAT | Planned | Planned | Planned | Planned external recovery | Missing |
| exFAT revision 1 basic | Planned | Planned | Planned | Planned; TexFAT separate | Missing |
| NTFS 3.1 clean baseline | Planned | Planned | Planned staged profiles | Planned journal/system-file work | Missing |
| ext2 baseline | Planned | Planned | Planned | Planned external recovery | Missing |
| ext3/JBD2 and ext4 profiles | Planned | Planned | Planned | Planned native journal work | Missing |
| XFS v4/v5 profiles | Planned | Planned | Planned | Planned log/reference work | Missing |
| HFS | Planned | Planned | Planned | Planned external recovery | Missing |
| HFS+/HFSX | Planned | Planned | Planned | Planned journal work | Missing |
| APFS container/volumes | Planned | Planned | Planned | Planned container COW work | Missing |
| JFS | Planned | Planned | Planned | Planned log work | Missing |
| JFFS2 declared logical image | Planned | Planned | Planned offline builder | Planned flash-profile gates | Missing |
| UDF (`libmkiso`) | Existing sibling slice reader; framework adapter pending R1 | Existing sibling extraction; metadata preservation pending R3 | Existing sibling path/buffer writer; framework tree source pending R2 | No framework editor | Sibling gates must be audited per revision; framework evidence missing |
| ISO9660/Joliet/Rock Ridge (`libmkiso`) | Existing sibling `Read + Seek` reader; bounded adapter pending | Existing sibling public extent index and selected metadata | Existing sibling host-directory writers; R2/R3 pending | No framework editor | Sibling gates must be audited per namespace; framework evidence missing |

No family row grants all historical/vendor variants. Dirty/recovery-required,
encrypted, unsupported incompatible features, uninspected metadata, auxiliary
devices and resizing each need explicit outcomes. Recognition, local validation,
global ownership audit, payload decode and durable commit are separate evidence.

## Current API/dependency ledger

Read-only inspection of sibling source trees establishes APIs present locally;
it does not establish publication on crates.io. Current partmgr manifest uses
`virtdisk = "0.1.0"`, without a sibling path dependency.

| Owner/local version | Actual inspected API | Features | Required adapter/refactor and compatibility | Minimum published API version/evidence |
| --- | --- | --- | --- | --- |
| `virtdisk`, local 0.1.0 | `ReadAt: Send + Sync`, fixed `len`, positional reads; `DiskView::new(Arc<dyn ReadAt>, start, length)` | Core, no CLI required | Immutable stable-source adapter retains provenance/budgets; never implement this immutable contract on an editor handle | Existing dependency 0.1.0; new required API version none identified; publication of local extras not established |
| `virtdisk`, local 0.1.0 | `ImageWriter::{open,open_chain,read_exact_at}`, `WriteAt::{len,write_all_at,write_zeroes,flush,discard}`, `InspectImage`; writer also has resize/snapshot management | Core | R4 owned session retains writer privately, bounds all operations; map successful all-write to full `usize`; errors may leave uncertain mutation; retain advisory-lock/backing-parent and flush limits | R4 implementation must compile against locked crates.io dependency; local signature alone insufficient |
| `partmgr`, local 0.1.0 | `storage::Storage::{len,read_exact_at,write_at,flush}`, mutable short-write semantics; `WritePlan` checked staged replacement | Core | New bounded session bridge; preserve error/durability semantics. Do not reuse nonoverlapping table plans as universal filesystem journal transactions | Current owning tree; release evidence pending |
| `libmkiso` in `mkiso-rs`, local 0.1.1 | `UdfReader<'a>::open(&'a [u8], UdfLimits)`, `entries`, `extract`, size-bounded `read_entry`; UDF allocation extents private | Readers available with no default features | R1 positional retained-source input, bounded file/stream read and hole-aware extent visitation; retain slice/extraction wrappers | Unknown; local 0.1.1 is not evidence R1 published |
| `libmkiso`, local 0.1.1 | `IsoReader<R: Read + Seek>`, `index`, `into_parts`; `IsoIndex.extents: Vec<Vec<IsoExtent>>` | Readers available with no default features | Checked independent cursor over bounded immutable input; public index already supports positional payload adapter, new ISO input trait unnecessary | Current APIs local; required published version must be established by release build |
| `libmkiso`, local 0.1.1 | `UdfImage::{add_file,add_bytes,add_sparse_file,add_named_stream,add_root_stream,add_system_stream,write_with_cancel}`; ISO writer entry points take host directory | `native-writer` (default); `cli` additionally for `boot_media` | R2 library-owned stable deferred file-tree source, bounded inventories/content and staged emission; preserve host/buffer wrappers | Unknown pending R2 release |
| `libmkiso`, local 0.1.1 | `UdfEntry` kind/stream/ICB/raw name/link/size, no exposed timestamp/ownership/permission fields; `IsoEntry` raw name, selected `UnixMetadata` and link target | Reader core / writer `native-writer` | R3 per-profile read/write metadata and preservation matrices; absent differs from uninspected, inspected differs from reproducible | Unknown pending R3 release |

Framework storage/core must remain independent of partition codecs and optical
engines. The higher integration layer can depend on both filesystem contracts and
`libmkiso`; `libmkiso` must not import filesystem engines or `virtdisk`.

## Evidence gate checklist

For every advertised operation record its profile/feature allowlist, immutable or
exclusive-session preconditions, metadata classes and opaque limitations,
resource bounds, cancellation and uncertain-write outcome, recovery unit/barrier
ordering, and supported backend/publication durability. Native fixture and
failure tests must establish those particular claims. Numeric performance limits
must be selected before release per workload/backend, with cold/warm method,
hardware, tool versions, cache budget, concurrency, I/O counts/amplification,
latency, memory and durable throughput. None are established by this ledger.

Run fmt, all-target/all-feature locked clippy with warnings denied, and all-feature
locked tests in changed Rust repositories. Optical changes also retain
no-default-features tests, no-default-features+cli tests, and portable wasm check.
Independent filesystem validation, Windows capture/servicing, QEMU/OVMF boot,
power-loss durability and physical flash each remain separate gates.
