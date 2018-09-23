use num_bigint::BigUint;

/// Converts the given number into an array of exactly len bytes, padding with
/// zeroes if necessary.
///
/// The Java implementation handles the fact that Java BigInteger prepends a
/// sign bit, which can create an extra leading zero-byte. BigUint does not do
/// this, so we simplify the logic.
pub fn rectify(bi: &BigUint, len: usize) -> Vec<u8> {
    let mut b = bi.to_bytes_be();
    match b.len() {
        sz if sz == len => b,
        sz if sz > len => panic!("key too big ({}) max is {}", sz, len),
        0 => {
            warn!("Warning: dh_pub is zero!");
            vec![0u8; len]
        }
        _ => {
            // Smaller than needed
            let mut ret = vec![0u8; len];
            ret.truncate(len - b.len());
            ret.append(&mut b);
            ret
        }
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use num_traits::{One, Zero};

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
