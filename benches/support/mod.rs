//! Deterministic workloads shared by the hosted std and allocation-only benchmarks.
pub mod apfs;
pub mod fat;
pub mod gpt;
pub mod ntfs;
pub mod usn;

pub struct RunMetrics {
    pub checksum: u64,
    pub backend_reads: u64,
    pub backend_bytes: u64,
}
pub struct Case {
    pub name: String,
    pub size: usize,
    pub operations: u64,
    pub run: Box<dyn FnMut() -> RunMetrics>,
}
