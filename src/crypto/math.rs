use std::iter;

use crypto_bigint::Encoding;

/// Converts the given number into an array of exactly len bytes, padding with
/// zeroes if necessary.
///
/// The Java implementation handles the fact that Java BigInteger prepends a
/// sign bit, which can create an extra leading zero-byte. BigUint does not do
/// this, so we simplify the logic.
pub fn rectify<T: Encoding>(bi: &T, len: usize) -> Vec<u8> {
    let mut b = bi.to_be_bytes();
    match b.as_ref().len() {
        sz if sz == len => b.as_ref().to_vec(),
        sz if sz > len => panic!("key too big ({}) max is {}", sz, len),
        0 => {
            warn!("Warning: dh_pub is zero!");
            vec![0u8; len]
        }
        _ => {
            // Smaller than needed
            iter::repeat(0)
                .take(len - b.as_ref().len())
                .chain(b.as_ref().into_iter().cloned())
                .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::rectify;

    #[test]
    fn rectify_zero() {
        assert_eq!(&rectify(&BigUint::zero(), 1), &[0]);
        assert_eq!(&rectify(&BigUint::zero(), 8), &[0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&rectify(&BigUint::zero(), 32), &[0u8; 32]);
    }

    #[test]
    fn rectify_one() {
        assert_eq!(&rectify(&BigUint::one(), 1), &[1]);
        assert_eq!(&rectify(&BigUint::one(), 4), &[0, 0, 0, 1]);
        assert_eq!(&rectify(&BigUint::one(), 8), &[0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn rectify_value() {
        let val = [0xff, 0xab, 0xcd, 0xef];
        assert_eq!(&rectify(&BigUint::from_bytes_be(&val), 4), &val);
        assert_eq!(
            &rectify(&BigUint::from_bytes_be(&val), 5),
            &[0x00, 0xff, 0xab, 0xcd, 0xef]
        );
    }
}
