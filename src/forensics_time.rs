//! Native timestamp interpretation for forensic timelines, without path inference.
//! FAT wall-clock values require an explicit UTC offset to produce a UTC sort key.

/// Lossless timestamp interpretation. Validation does not authenticate history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimestampEvidence<const N: usize> {
    /// Exact on-disk encoding, even for malformed calendar values.
    pub raw: [u8; N],
    /// Calendar/encoding validation result, separate from timezone availability.
    pub valid: bool,
    /// UTC ticks at 100 ns resolution since the Unix epoch, when interpretable.
    pub unix_ticks_100ns: Option<i128>,
    /// Native field resolution in 100 ns units. Precision never implies accuracy.
    pub precision_100ns: u64,
    /// Explicit FAT timezone assumption in seconds east of UTC; NTFS uses UTC.
    pub utc_offset_seconds: Option<i32>,
}

/// Decode exact NTFS FILETIME bits, retaining full 100 ns precision.
pub fn filetime(raw: [u8; 8]) -> TimestampEvidence<8> {
    TimestampEvidence {
        raw,
        valid: true,
        unix_ticks_100ns: Some(i128::from(u64::from_le_bytes(raw)) - 116_444_736_000_000_000),
        precision_100ns: 1,
        utc_offset_seconds: Some(0),
    }
}
fn calendar(date: u16) -> Option<(i64, u32, u32)> {
    let year = 1980 + i64::from(date >> 9);
    let month = u32::from((date >> 5) & 15);
    let day = u32::from(date & 31);
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let max = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    (day != 0 && day <= max).then_some((year, month, day))
}
// Gregorian civil date to days since 1970-01-01, with March as month zero.
fn days(year: i64, month: u32, day: u32) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let month = i64::from(month) + if month > 2 { -3 } else { 9 };
    era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + (153 * month + 2) / 5 + i64::from(day)
        - 1
        - 719468
}
fn utc_ticks(
    date: u16,
    time: Option<u16>,
    centiseconds: u8,
    offset: Option<i32>,
) -> (bool, Option<i128>) {
    let Some((year, month, day)) = calendar(date) else {
        return (false, None);
    };
    let (hours, minutes, seconds) = match time {
        Some(time) => (
            u32::from(time >> 11),
            u32::from((time >> 5) & 63),
            u32::from(time & 31) * 2,
        ),
        None => (0, 0, 0),
    };
    if hours > 23 || minutes > 59 || seconds > 59 || centiseconds > 199 {
        return (false, None);
    }
    if offset.is_some_and(|n| !(-86_400..=86_400).contains(&n)) {
        // A caller's unusable timezone assumption does not corrupt native bits.
        return (true, None);
    }
    let local = i128::from(days(year, month, day)) * 86400
        + i128::from(hours * 3600 + minutes * 60 + seconds);
    (
        true,
        offset.map(|offset| {
            (local - i128::from(offset)) * 10_000_000 + i128::from(centiseconds) * 100_000
        }),
    )
}

/// Decode a FAT modification field (`time` then `date`) at two-second precision.
/// No timezone is guessed when `utc_offset_seconds` is `None`.
pub fn fat_modified(raw: [u8; 4], utc_offset_seconds: Option<i32>) -> TimestampEvidence<4> {
    let time = u16::from_le_bytes([raw[0], raw[1]]);
    let date = u16::from_le_bytes([raw[2], raw[3]]);
    let (valid, unix_ticks_100ns) = utc_ticks(date, Some(time), 0, utc_offset_seconds);
    TimestampEvidence {
        raw,
        valid,
        unix_ticks_100ns,
        precision_100ns: 20_000_000,
        utc_offset_seconds,
    }
}
/// Decode FAT creation's subsecond byte, packed time and packed date.
/// Values 100..199 add the odd second omitted from the packed time field.
pub fn fat_created(raw: [u8; 5], utc_offset_seconds: Option<i32>) -> TimestampEvidence<5> {
    let time = u16::from_le_bytes([raw[1], raw[2]]);
    let date = u16::from_le_bytes([raw[3], raw[4]]);
    let (valid, unix_ticks_100ns) = utc_ticks(date, Some(time), raw[0], utc_offset_seconds);
    TimestampEvidence {
        raw,
        valid,
        unix_ticks_100ns,
        precision_100ns: 100_000,
        utc_offset_seconds,
    }
}
/// Decode FAT's access date. The UTC sort key is the start of the local day;
/// `precision_100ns` retains its one-day uncertainty, not a midnight event claim.
pub fn fat_accessed(raw: [u8; 2], utc_offset_seconds: Option<i32>) -> TimestampEvidence<2> {
    let (valid, unix_ticks_100ns) = utc_ticks(u16::from_le_bytes(raw), None, 0, utc_offset_seconds);
    TimestampEvidence {
        raw,
        valid,
        unix_ticks_100ns,
        precision_100ns: 864_000_000_000,
        utc_offset_seconds,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn filetime_epoch_and_single_tick_are_exact() {
        assert_eq!(
            filetime(116_444_736_000_000_001u64.to_le_bytes()).unix_ticks_100ns,
            Some(1)
        );
        assert_eq!(
            filetime(0u64.to_le_bytes()).unix_ticks_100ns,
            Some(-116_444_736_000_000_000)
        );
    }
    #[test]
    fn fat_calendar_requires_timezone_and_preserves_precision() {
        // 1980-01-01 00:00:00, independently packed literal date 0x0021.
        let raw = [0, 0, 0x21, 0];
        let unknown = fat_modified(raw, None);
        assert!(unknown.valid);
        assert_eq!(unknown.unix_ticks_100ns, None);
        assert_eq!(
            fat_modified(raw, Some(3600)).unix_ticks_100ns,
            Some(315_529_200 * 10_000_000)
        );
        assert_eq!(unknown.precision_100ns, 20_000_000);
        let bad_assumption = fat_modified(raw, Some(90_000));
        assert!(bad_assumption.valid);
        assert_eq!(bad_assumption.unix_ticks_100ns, None);
    }
    #[test]
    fn fat_invalid_dates_and_creation_odd_second_are_not_rounded() {
        // 2000-02-29 is valid, 2100-02-29 is not.
        assert!(
            fat_accessed(
                (((2000 - 1980) << 9 | 2 << 5 | 29) as u16).to_le_bytes(),
                Some(0)
            )
            .valid
        );
        assert!(
            !fat_accessed(
                (((2100 - 1980) << 9 | 2 << 5 | 29) as u16).to_le_bytes(),
                Some(0)
            )
            .valid
        );
        let value = fat_created([199, 0, 0, 0x21, 0], Some(0));
        assert_eq!(
            value.unix_ticks_100ns,
            Some(315_532_800 * 10_000_000 + 19_900_000)
        );
        assert!(!fat_created([200, 0, 0, 0x21, 0], Some(0)).valid);
        assert!(!fat_accessed([0, 0], Some(0)).valid);
    }
}
