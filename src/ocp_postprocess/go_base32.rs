const BASE32_DIGITS: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
const BASE32: u64 = 32;
const BASE32_MASK: u64 = BASE32 - 1;
const BASE32_SHIFT: u64 = 5;
const MAX_BASE32_U64_DIGITS: usize = 64 + 1;

pub(crate) fn base32_encode(mut num: u64) -> String {
    let mut output_array = [0u8; MAX_BASE32_U64_DIGITS];
    let mut output_index = output_array.len();

    while num >= BASE32 {
        output_index -= 1;
        output_array[output_index] = BASE32_DIGITS[(num & BASE32_MASK) as usize];

        num >>= BASE32_SHIFT;
    }

    output_index -= 1;
    output_array[output_index] = BASE32_DIGITS[num as usize];

    // Unwrap can't panic because the array the above loop outputs is guaranteed to be valid UTF-8,
    // we don't want this function to return a Result
    #[allow(clippy::unwrap_used)]
    String::from_utf8(output_array[output_index..].to_vec()).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    // package main
    // import (
    // 	"math/rand"
    // 	"fmt"
    // 	"strconv"
    // )
    // func main() {
    // 	for i := 0; i < 10; i++ {
    // 		fmt.Printf("assert_eq!(base32_encode(%d), %q);\n", i, strconv.FormatUint(uint64(i), 32))
    // 	}
    // 	for i := 0; i < 10; i++ {
    // 		x := rand.Uint64()
    // 		fmt.Printf("assert_eq!(base32_encode(%d), %q);\n", x, strconv.FormatUint(x, 32))
    // 	}
    // }
    fn test_base32_encode() {
        assert_eq!(base32_encode(0), "0");
        assert_eq!(base32_encode(1), "1");
        assert_eq!(base32_encode(2), "2");
        assert_eq!(base32_encode(3), "3");
        assert_eq!(base32_encode(4), "4");
        assert_eq!(base32_encode(5), "5");
        assert_eq!(base32_encode(6), "6");
        assert_eq!(base32_encode(7), "7");
        assert_eq!(base32_encode(8), "8");
        assert_eq!(base32_encode(9), "9");
        assert_eq!(base32_encode(9571486601897812948), "89l60b8v8f8uk");
        assert_eq!(base32_encode(14972217520619435323), "cvi00g906dd9r");
        assert_eq!(base32_encode(828543677970655149), "mvsk2nb5c9td");
        assert_eq!(base32_encode(10165118770545495894), "8q4e1l8l0a3qm");
        assert_eq!(base32_encode(13003616107026089108), "b8tgvug3dd14k");
        assert_eq!(base32_encode(17310030582050129450), "f0ecl38b3u1ha");
        assert_eq!(base32_encode(5246586088816823604), "4hjsu805mtj9k");
        assert_eq!(base32_encode(9506301410689701343), "87r9aogrv8lev");
        assert_eq!(base32_encode(17418413831566181087), "f3el32vak1gmv");
        assert_eq!(base32_encode(10879890617200402116), "9dv92rt4lbnm4");
    }
}
