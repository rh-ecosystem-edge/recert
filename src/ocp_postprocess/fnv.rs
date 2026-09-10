pub(crate) fn fnv1_32(data: &[u8]) -> u32 {
    let mut hash = 0x811c9dc5u32;
    for byte in data {
        hash = hash.wrapping_mul(0x01000193);
        hash ^= u32::from(*byte);
    }
    hash
}

pub(crate) fn fnv1_64(data: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in data {
        hash = hash.wrapping_mul(0x100000001b3);
        hash ^= u64::from(*byte);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fnv1_32_golden() {
        assert_eq!(fnv1_32(b""), 0x811c9dc5);
        assert_eq!(fnv1_32(b"a"), 0x050c5d7e);
        assert_eq!(fnv1_32(b"hello"), 0xb6fa7167);
        // Matches the "{json}\n" suffix used for operator spec-hash annotations.
        assert_eq!(fnv1_32(b"{}\n"), 0x2e5b66c9);
    }

    #[test]
    fn test_fnv1_64_golden() {
        assert_eq!(fnv1_64(b""), 0xcbf29ce484222325);
        assert_eq!(fnv1_64(b"a"), 0xaf63bd4c8601b7be);
        assert_eq!(fnv1_64(b"hello"), 0x7b495389bdbdd4c7);
        assert_eq!(fnv1_64(b"{}\n"), 0xd884b5186b651429);
    }
}
