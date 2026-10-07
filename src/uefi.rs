//! UEFI layout policy and explicit filesystem/boot preparation boundaries.
//!
//! Device-path encoding follows UEFI 2.11 section 10, Hard Drive Media Device
//! Path. Layout validation and boot-file installation do not establish firmware
//! boot success. Firmware variables and Secure Boot remain platform operations.
//!
//! Reference: [UEFI Hard Drive Media Device Path](https://uefi.org/specs/UEFI/2.10/10_Protocols_Device_Path_Protocol.html#hard-drive-media-device-path).
//! The node uses one-based partition numbers, little-endian start/size LBAs,
//! and a GPT unique-partition GUID or an MBR disk signature.
use crate::{
    guid::{EFI_SYSTEM_PARTITION, Guid, MICROSOFT_RESERVED},
    layout::{DiskLayout, LbaRange},
};
use std::{fmt, io};
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
/// A 42-byte hard-drive media device-path node (without an end node).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HardDriveDevicePath([u8; 42]);
impl HardDriveDevicePath {
    fn node(
        number: u32,
        range: LbaRange,
        signature: [u8; 16],
        scheme: u8,
        signature_type: u8,
    ) -> Self {
        let mut b = [0; 42];
        b[..4].copy_from_slice(&[4, 1, 42, 0]);
        b[4..8].copy_from_slice(&number.to_le_bytes());
        b[8..16].copy_from_slice(&range.start().to_le_bytes());
        b[16..24].copy_from_slice(&range.sectors().to_le_bytes());
        b[24..40].copy_from_slice(&signature);
        b[40] = scheme;
        b[41] = signature_type;
        Self(b)
    }
    /// Describe a GPT partition using its unique partition GUID, not its type GUID.
    /// The one-based slot must also be within the actual GPT array dimensions;
    /// this constructor cannot check dimensions without a layout.
    pub fn gpt(number: u32, range: LbaRange, id: Guid) -> io::Result<Self> {
        if number == 0 || id.is_nil() {
            return Err(invalid(
                "GPT device path requires a nonzero slot and identity",
            ));
        }
        Ok(Self::node(number, range, id.to_gpt_bytes(), 2, 2))
    }
    /// Describe a primary MBR partition using the disk's 32-bit signature.
    /// Partition numbers are restricted to 1–4 by UEFI Table 10.54.
    pub fn mbr(number: u32, range: LbaRange, signature: u32) -> io::Result<Self> {
        if !(1..=4).contains(&number) {
            return Err(invalid("MBR device path slot must be 1 through 4"));
        }
        let mut b = [0; 16];
        b[..4].copy_from_slice(&signature.to_le_bytes());
        Ok(Self::node(number, range, b, 1, 1))
    }
    /// Return the complete node bytes.
    pub const fn encode(&self) -> [u8; 42] {
        self.0
    }
}
/// Identify EFI System Partitions while retaining their original slots and ranges.
pub fn esp_entries(layout: &DiskLayout) -> Vec<(u32, LbaRange)> {
    match layout {
        DiskLayout::Gpt(g) => g
            .entries()
            .iter()
            .filter_map(|e| {
                let b: [u8; 16] = e.raw()[..16].try_into().ok()?;
                if Guid::from_gpt_bytes(b) == EFI_SYSTEM_PARTITION {
                    e.range().map(|r| (e.slot(), r))
                } else {
                    None
                }
            })
            .collect(),
        DiskLayout::Mbr(m) => m
            .entries()
            .iter()
            .filter(|e| e.raw()[4] == 0xef)
            .map(|e| (e.slot(), e.range()))
            .collect(),
    }
}
/// Explicit platform policy; sizes and alignment come from the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EspProfile {
    minimum_bytes: u64,
    maximum_bytes: Option<u64>,
    alignment_bytes: u64,
    require_gpt: bool,
    require_microsoft_reserved: bool,
}
impl EspProfile {
    /// Build a configurable profile without choosing a universal ESP size.
    pub fn new(
        minimum_bytes: u64,
        maximum_bytes: Option<u64>,
        alignment_bytes: u64,
        require_gpt: bool,
        require_microsoft_reserved: bool,
    ) -> io::Result<Self> {
        if minimum_bytes == 0
            || alignment_bytes == 0
            || maximum_bytes.is_some_and(|m| m < minimum_bytes)
        {
            return Err(invalid("invalid ESP size or alignment policy"));
        }
        Ok(Self {
            minimum_bytes,
            maximum_bytes,
            alignment_bytes,
            require_gpt,
            require_microsoft_reserved,
        })
    }
    /// A Windows-style GPT profile with an explicit caller-selected ESP minimum.
    pub fn windows(minimum_bytes: u64, alignment_bytes: u64) -> io::Result<Self> {
        Self::new(minimum_bytes, None, alignment_bytes, true, true)
    }
    /// A Linux-style profile permitting supported MBR ESP entries.
    pub fn linux(minimum_bytes: u64, alignment_bytes: u64) -> io::Result<Self> {
        Self::new(minimum_bytes, None, alignment_bytes, false, false)
    }
    /// Validate core layout and platform policy, returning the selected ESP range.
    /// Filesystem compatibility and bootability are separate observations.
    pub fn validate(self, layout: &DiskLayout) -> io::Result<LbaRange> {
        let sector = match layout {
            DiskLayout::Gpt(g) => g.geometry().sector_size(),
            DiskLayout::Mbr(m) => {
                if self.require_gpt {
                    return Err(invalid("profile requires GPT"));
                }
                m.geometry().sector_size()
            }
        };
        if self.require_microsoft_reserved {
            let DiskLayout::Gpt(g) = layout else {
                return Err(invalid("profile requires Microsoft reserved partition"));
            };
            if !g.entries().iter().any(|e| {
                e.range().is_some()
                    && Guid::from_gpt_bytes(e.raw()[..16].try_into().unwrap_or([0; 16]))
                        == MICROSOFT_RESERVED
            }) {
                return Err(invalid("profile requires Microsoft reserved partition"));
            }
        }
        let entries = esp_entries(layout);
        if entries.len() != 1 {
            return Err(invalid("profile requires exactly one ESP"));
        }
        let range = entries[0].1;
        let bytes = range
            .sectors()
            .checked_mul(u64::from(sector))
            .ok_or_else(|| invalid("ESP size overflow"))?;
        let offset = range
            .start()
            .checked_mul(u64::from(sector))
            .ok_or_else(|| invalid("ESP offset overflow"))?;
        if bytes < self.minimum_bytes
            || self.maximum_bytes.is_some_and(|m| bytes > m)
            || !offset.is_multiple_of(self.alignment_bytes)
        {
            return Err(invalid("ESP violates size or alignment policy"));
        }
        Ok(range)
    }
}
/// Completed filesystem/boot preparation stage; none implies observed firmware boot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EspPreparation {
    /// FAT preparation has not completed.
    Unprepared,
    /// The adapter successfully prepared FAT.
    FatPrepared,
    /// FAT and boot-file installation both completed.
    BootFilesInstalled,
}
/// Filesystem and boot-tool operations supplied by a platform integration.
pub trait EspAdapter {
    /// Prepare a firmware-compatible FAT filesystem within the bounded ESP.
    fn prepare_fat(&mut self, range: LbaRange) -> io::Result<()>;
    /// Install caller-selected boot files into the prepared ESP.
    fn install_boot_files(&mut self, range: LbaRange) -> io::Result<()>;
}
/// Preparation failure with the last completed stage and underlying I/O cause.
#[derive(Debug)]
pub struct EspPreparationError {
    completed: EspPreparation,
    source: io::Error,
}
impl EspPreparationError {
    /// Last stage known to have completed; the failed stage may be partially written.
    pub const fn completed(&self) -> EspPreparation {
        self.completed
    }
}
impl fmt::Display for EspPreparationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ESP preparation failed after {:?}: {}",
            self.completed, self.source
        )
    }
}
impl std::error::Error for EspPreparationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}
/// Run FAT preparation before boot-file installation and report explicit stages.
pub fn prepare_esp(
    adapter: &mut dyn EspAdapter,
    range: LbaRange,
) -> Result<EspPreparation, EspPreparationError> {
    adapter
        .prepare_fat(range)
        .map_err(|source| EspPreparationError {
            completed: EspPreparation::Unprepared,
            source,
        })?;
    adapter
        .install_boot_files(range)
        .map_err(|source| EspPreparationError {
            completed: EspPreparation::FatPrepared,
            source,
        })?;
    Ok(EspPreparation::BootFilesInstalled)
}
/// Recognize logical ESP payloads in an explicitly inspected extended MBR.
/// The returned ordinal starts at five, following primary MBR partition slots.
/// UEFI hard-drive nodes for MBR are specified only for primary numbers 1–4;
/// recognition of a logical ESP does not promise firmware discovery support.
pub fn esp_entries_extended(layout: &crate::extended::ExtendedLayout) -> Vec<(u32, LbaRange)> {
    layout
        .logical()
        .iter()
        .enumerate()
        .filter(|(_, e)| e.kind() == 0xef)
        .map(|(i, e)| (i as u32 + 5, e.range()))
        .collect()
}
/// Create an ESP entry with explicit geometry and caller identity, without FAT
/// formatting or boot-file installation. MBR uses type 0xEF; GPT uses the ESP
/// type GUID. Platform profile validation can follow creation.
pub fn create_esp(layout: &mut DiskLayout, slot: u32, id: Guid, range: LbaRange) -> io::Result<()> {
    match layout {
        DiskLayout::Gpt(g) => g.create(slot, EFI_SYSTEM_PARTITION, id, range),
        DiskLayout::Mbr(m) => m.create(slot, 0xef, range, false),
    }
}
