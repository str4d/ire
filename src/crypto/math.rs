use num::bigint::BigUint;

pub fn rectify(bi: &BigUint, len: usize) -> Vec<u8> {
    let mut b = bi.to_bytes_be();
    // Pad with 0s if necessary
    match b.len() {
        sz if sz == len => b,
        sz if sz > (len + 1) => panic!("key too big ({}) max is {}", sz, len + 1),
        0 => {
            println!("Warning: dh_pub is zero!");
            vec![0u8; len]
        }
        sz if sz > len => {
            match b[0] {
                0 => Vec::from(&b[1..]),
                _ => panic!("key too big ({}) max is {}", sz, len),
            }
        }
        _ => {
            match b[0] & 0x80 {
                0 => {
                    // Smaller than needed
                    let mut ret = vec![0u8; len];
                    ret.truncate(len - b.len());
                    ret.append(&mut b);
                    ret
                }
                _ => panic!("negative"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}
