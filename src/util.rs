//! Helper functions

use bloom_filter_rs::{BloomFilter, Murmur3};
use cookie_factory::GenError;
use core::fmt;
use std::iter::repeat;
use std::mem;

pub fn serialize<S>(serializer: S) -> Vec<u8>
where
    S: Fn((&mut [u8], usize)) -> Result<(&mut [u8], usize), GenError>,
{
    let mut buf = vec![];
    loop {
        match serializer((&mut buf, 0)).map(|tup| tup.1) {
            Ok(sz) => {
                buf.truncate(sz);
                break;
            }
            Err(e) => match e {
                GenError::BufferTooSmall(sz) => {
                    let cur_len = buf.len();
                    buf.extend(repeat(0).take(sz - cur_len));
                }
                _ => panic!("Couldn't serialize"),
            },
        }
    }
    buf
}

/// Format a byte array as a colon-delimited hex string.
///
/// Source: https://github.com/tendermint/signatory
/// License: MIT / Apache 2.0
pub(crate) fn fmt_colon_delimited_hex<B>(f: &mut fmt::Formatter, bytes: B) -> fmt::Result
where
    B: AsRef<[u8]>,
{
    let len = bytes.as_ref().len();

    for (i, byte) in bytes.as_ref().iter().enumerate() {
        write!(f, "{:02x}", byte)?;

        if i != len - 1 {
            write!(f, ":")?;
        }
    }

    Ok(())
}

/// A two-layer Bloom filter that can be decayed, meaning that it can be used continuously on
/// real-time data while maintaining a reasonable false positive rate for a fixed filter size.
///
/// It produces zero false negatives within two decay periods, and a 100% false negative rate
/// otherwise. As such, it is intended for use in places where some external timestamp or expiring
/// ID can be used for longer-range duplicate detection.
///
/// Targets a false positive rate of 10^-5.
pub struct DecayingBloomFilter {
    current: BloomFilter<Murmur3>,
    previous: BloomFilter<Murmur3>,
    max_elements: u64,
}

impl DecayingBloomFilter {
    pub fn new(max_elements: u64) -> Self {
        DecayingBloomFilter {
            current: BloomFilter::optimal(Murmur3, max_elements, 0.00001),
            previous: BloomFilter::optimal(Murmur3, max_elements, 0.00001),
            max_elements,
        }
    }

    /// Returns whether the given bytes are present in the filter, and inserts them if not.
    pub fn feed(&mut self, bytes: &[u8]) -> bool {
        if self.current.contains(bytes) || self.previous.contains(bytes) {
            true
        } else {
            self.current.insert(bytes);
            false
        }
    }

    /// Decay the Bloom filter.
    pub fn decay(&mut self) {
        mem::swap(&mut self.current, &mut self.previous);
        self.current = BloomFilter::optimal(Murmur3, self.max_elements, 0.00001);
    }
}

#[cfg(test)]
mod tests {
    use super::DecayingBloomFilter;

    #[test]
    fn decaying_bloom_filter() {
        let mut filter = DecayingBloomFilter::new(10);
        let first = [0; 32];
        let second = [1; 32];
        let third = [2; 32];

        // An empty filter contains nothing, so this entry gets added
        assert!(!filter.feed(&first[..]));

        // Now the entry is present
        assert!(filter.feed(&first[..]));

        // Other entries can be added
        assert!(!filter.feed(&second[..]));

        // First entry is still present
        assert!(filter.feed(&first[..]));

        // First and second entries are still present after a single decay
        filter.decay();
        assert!(filter.feed(&first[..]));
        assert!(filter.feed(&second[..]));

        // Can still add entries after a decay
        assert!(!filter.feed(&third[..]));

        // Entries are correctly detected
        assert!(filter.feed(&first[..]));
        assert!(filter.feed(&second[..]));
        assert!(filter.feed(&third[..]));

        // First and second entries disappear after a second decay, and get re-added
        filter.decay();
        assert!(!filter.feed(&first[..]));
        assert!(!filter.feed(&second[..]));

        // The third entry remains in the filter...
        assert!(filter.feed(&third[..]));

        // ... but disappears after a third decay, while the first and second remain
        filter.decay();
        assert!(filter.feed(&first[..]));
        assert!(filter.feed(&second[..]));
        assert!(!filter.feed(&third[..]));
    }
}
