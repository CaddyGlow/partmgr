use partmgr::fs_core::{FileRead, Resources};

/// EOF and empty reads must preserve the caller's buffer, including huge offsets.
pub fn assert_eof_contract(file: &dyn FileRead, resources: &Resources) {
    for offset in [file.len(), file.len().saturating_add(1), u64::MAX] {
        let mut buffer = [0xa5; 17];
        assert_eq!(file.read_at(offset, &mut buffer, resources).unwrap(), 0);
        assert_eq!(buffer, [0xa5; 17]);
        assert_eq!(file.read_at(offset, &mut [], resources).unwrap(), 0);
    }
    assert_eq!(file.read_at(0, &mut [], resources).unwrap(), 0);
}
