pub(crate) fn fnv1_32(data: &[u8]) -> u32 {
    let mut hash = 0x811c9dc5u32;
    for byte in data {
        hash = hash.wrapping_mul(0x01000193);
        hash ^= u32::from(*byte);
    }
    hash
}
