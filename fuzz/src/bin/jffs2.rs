fn main() {
    loop {
        honggfuzz::fuzz!(|data: &[u8]| {
            partmgr_fuzz::jffs2(data);
        });
    }
}
