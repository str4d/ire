use cookie_factory::*;
use nom::*;
use nom::{
    bits::{bits, streaming::take as take_bits},
    combinator::{cond, map},
    error::ErrorKind,
    number::streaming::{be_u16, be_u32},
    sequence::{pair, tuple},
};
use sha2::{Digest, Sha256};
use std::iter;

use super::{
    FirstFragmentDeliveryInstructions, FollowOnFragmentDeliveryInstructions, TunnelMessage,
    TunnelMessageDeliveryInstructions, TunnelMessageDeliveryType,
};
use crate::data::frame::{gen_hash, gen_tunnel_id, hash, tunnel_id};

// Checksum

fn checksum(buf: &[u8], iv: &[u8]) -> u32 {
    let mut hasher = Sha256::default();
    hasher.update(buf);
    hasher.update(iv);
    let mut buf = [0; 4];
    buf.copy_from_slice(&hasher.finalize()[0..4]);
    u32::from_be_bytes(buf)
}

fn validate_checksum<'a>(input: &'a [u8], cs: u32, buf: &[u8], iv: &[u8]) -> IResult<&'a [u8], ()> {
    if cs == checksum(buf, iv) {
        Ok((input, ()))
    } else {
        Err(Err::Error((input, ErrorKind::Verify)))
    }
}

fn gen_checksum<'a>(
    input: (&'a mut [u8], usize),
    start: usize,
    end: usize,
    iv: &[u8],
) -> Result<(&'a mut [u8], usize), GenError> {
    gen_be_u32!(input, checksum(&input.0[start..end], iv))
}

// Padding

fn gen_nonzero_padding(
    input: (&mut [u8], usize),
    length: usize,
) -> Result<(&mut [u8], usize), GenError> {
    // TODO: real non-zero padding
    do_gen!(input, gen_many!(iter::repeat(1).take(length), set_be_u8))
}

// FirstFragmentDeliveryInstructions

const DELIVERY_TYPE_LOCAL: u8 = 0;
const DELIVERY_TYPE_TUNNEL: u8 = 1;
const DELIVERY_TYPE_ROUTER: u8 = 2;

fn first_frag_di(i: &[u8]) -> IResult<&[u8], FirstFragmentDeliveryInstructions> {
    let (i, (delivery_type, fragmented)) = map(
        bits::<_, (u8, u8, u8, u8, u8), (_, _), _, _>(tuple((
            take_bits(1u8),
            take_bits(2u8),
            take_bits(1u8),
            take_bits(1u8),
            take_bits(3u8),
        ))),
        |(_, delivery_type, _, fragmented, _)| (delivery_type, fragmented > 0),
    )(i)?;

    let (i, delivery_type) = match delivery_type {
        DELIVERY_TYPE_LOCAL => Ok((i, TunnelMessageDeliveryType::Local)),
        DELIVERY_TYPE_TUNNEL => map(pair(tunnel_id, hash), |(tid, to)| {
            TunnelMessageDeliveryType::Tunnel(tid, to)
        })(i),
        DELIVERY_TYPE_ROUTER => map(hash, TunnelMessageDeliveryType::Router)(i),
        _ => Err(nom::Err::Error((i, ErrorKind::Char))),
    }?;

    let (i, msg_id) = cond(fragmented, be_u32)(i)?;

    Ok((
        i,
        FirstFragmentDeliveryInstructions {
            delivery_type,
            msg_id,
        },
    ))
}

fn gen_first_frag_di<'a>(
    input: (&'a mut [u8], usize),
    di: &FirstFragmentDeliveryInstructions,
) -> Result<(&'a mut [u8], usize), GenError> {
    let mut x = 0;
    x |= (match di.delivery_type {
        TunnelMessageDeliveryType::Local => DELIVERY_TYPE_LOCAL,
        TunnelMessageDeliveryType::Tunnel(_, _) => DELIVERY_TYPE_TUNNEL,
        TunnelMessageDeliveryType::Router(_) => DELIVERY_TYPE_ROUTER,
    } << 5)
        & 0b1100000;
    if di.msg_id.is_some() {
        x |= 0b1000;
    }
    match &di.delivery_type {
        TunnelMessageDeliveryType::Local => do_gen!(
            input,
            gen_be_u8!(x) >> gen_cond!(di.msg_id.is_some(), gen_be_u32!(di.msg_id.unwrap()))
        ),
        TunnelMessageDeliveryType::Tunnel(tid, to) => do_gen!(
            input,
            gen_be_u8!(x)
                >> gen_tunnel_id(&tid)
                >> gen_hash(&to)
                >> gen_cond!(di.msg_id.is_some(), gen_be_u32!(di.msg_id.unwrap()))
        ),
        TunnelMessageDeliveryType::Router(to) => do_gen!(
            input,
            gen_be_u8!(x)
                >> gen_hash(&to)
                >> gen_cond!(di.msg_id.is_some(), gen_be_u32!(di.msg_id.unwrap()))
        ),
    }
}

// FollowOnFragmentDeliveryInstructions

fn follow_on_frag_di(i: &[u8]) -> IResult<&[u8], FollowOnFragmentDeliveryInstructions> {
    map(
        pair(
            map(
                bits::<_, (u8, u8, u8), (_, _), _, _>(tuple((
                    take_bits(1u8),
                    take_bits(6u8),
                    take_bits(1u8),
                ))),
                |(_, fragment_number, last_fragment)| (fragment_number, last_fragment > 0),
            ),
            be_u32,
        ),
        |(flags, msg_id)| FollowOnFragmentDeliveryInstructions {
            fragment_number: flags.0,
            last_fragment: flags.1,
            msg_id,
        },
    )(i)
}

fn gen_follow_on_frag_di<'a>(
    input: (&'a mut [u8], usize),
    di: &FollowOnFragmentDeliveryInstructions,
) -> Result<(&'a mut [u8], usize), GenError> {
    let mut x = 0b10000000;
    x |= (di.fragment_number << 1) & 0b01111110;
    if di.last_fragment {
        x |= 0b1;
    }
    do_gen!(input, gen_be_u8!(x) >> gen_be_u32!(di.msg_id))
}

// TunnelMessageDeliveryInstructions

named!(
    tmdi<TunnelMessageDeliveryInstructions>,
    switch!(
        peek!(bits!(take_bits!(1u8))),
        0 => do_parse!(
            di: first_frag_di >>
            (TunnelMessageDeliveryInstructions::First(di))
        ) |
        1 => do_parse!(
            di: follow_on_frag_di >>
            (TunnelMessageDeliveryInstructions::FollowOn(di))
        )
    )
);

fn gen_tmdi<'a>(
    input: (&'a mut [u8], usize),
    tmdi: &TunnelMessageDeliveryInstructions,
) -> Result<(&'a mut [u8], usize), GenError> {
    match tmdi {
        TunnelMessageDeliveryInstructions::First(di) => gen_first_frag_di(input, di),
        TunnelMessageDeliveryInstructions::FollowOn(di) => gen_follow_on_frag_di(input, di),
    }
}

// TunnelMessage

named!(
    tunnel_message<TunnelMessage>,
    do_parse!(
        iv: take!(16)
            >> checksum: be_u32
            >> padding: take_until!(&b"\x00"[..])
            >> take!(1)
            >> msg_bytes: peek!(take!(1008 - 4 - padding.len() - 1))
            >> call!(validate_checksum, checksum, msg_bytes, iv)
            >> msg: many0!(complete!(pair!(tmdi, length_data!(be_u16))))
            >> (TunnelMessage(msg))
    )
);

fn gen_tmdi_fragment_pair<'a>(
    input: (&'a mut [u8], usize),
    (tmdi, frag): &(TunnelMessageDeliveryInstructions, &[u8]),
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_tmdi(tmdi) >> gen_be_u16!(frag.len() as u16) >> gen_slice!(frag)
    )
}

fn gen_tunnel_message<'a>(
    input: (&'a mut [u8], usize),
    iv: &[u8],
    tm: &TunnelMessage,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_slice!(iv)
            >> checksum: gen_skip!(4)
            >> gen_nonzero_padding(1008 - 4 - 1 - tm.byte_len())
            >> gen_be_u8!(0)
            >> msg_start: gen_many!(&tm.0, gen_tmdi_fragment_pair)
            >> msg_end: gen_at_offset!(checksum, gen_checksum(msg_start, msg_end, iv))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! bake_and_eat {
        ($oven:expr, $monster:expr, $value:expr, $expected:expr) => {
            let mut res = vec![];
            res.resize($expected.len(), 0);
            match $oven((&mut res, 0), &$value) {
                Ok(_) => assert_eq!(&res, &$expected),
                Err(e) => panic!("Unexpected error: {:?}", e),
            }
            match $monster(&res) {
                Ok((_, m)) => assert_eq!(m, $value),
                Err(e) => panic!("Unexpected error: {:?}", e),
            }
        };
    }

    #[test]
    fn test_validate_checksum() {
        let a = b"payloadspam";
        let iv = [0; 16];
        assert_eq!(
            validate_checksum(&a[..], 0xfc8213b7, &a[..7], &iv[..]),
            Ok((&a[..], ()))
        );
        assert_eq!(
            validate_checksum(&a[..], 0xfc8213b7, &a[..8], &iv[..]),
            Err(Err::Error((&a[..], ErrorKind::Verify)))
        );
    }

    #[test]
    fn test_gen_checksum() {
        // Valid payload checksum
        let a = b"\xfc\x82\x13\xb7payloadspam";
        let iv = [0; 16];
        // Copy payload into a buffer with an empty checksum
        let mut b = Vec::new();
        b.extend_from_slice(&[0; 4][..]);
        b.extend(a[4..].iter().cloned());
        // Generate and validate checksum of payload
        let res = gen_checksum((&mut b[..], 0), 4, 11, &iv[..]);
        assert!(res.is_ok());
        let (o, n) = res.unwrap();
        assert_eq!(o, &a[..]);
        assert_eq!(n, 4);
    }

    #[test]
    fn test_first_frag_di() {
        macro_rules! eval {
            ($value:expr, $expected:expr) => {
                bake_and_eat!(gen_first_frag_di, first_frag_di, $value, $expected)
            };
        }

        eval!(
            FirstFragmentDeliveryInstructions {
                delivery_type: TunnelMessageDeliveryType::Local,
                msg_id: None,
            },
            [0]
        );

        eval!(
            FirstFragmentDeliveryInstructions {
                delivery_type: TunnelMessageDeliveryType::Local,
                msg_id: Some(123_456_789),
            },
            [0x08, 0x07, 0x5b, 0xcd, 0x15]
        );
    }

    #[test]
    fn test_follow_on_frag_di() {
        macro_rules! eval {
            ($value:expr, $expected:expr) => {
                bake_and_eat!(gen_follow_on_frag_di, follow_on_frag_di, $value, $expected)
            };
        }

        eval!(
            FollowOnFragmentDeliveryInstructions {
                fragment_number: 1,
                last_fragment: false,
                msg_id: 123_456_789,
            },
            [0x82, 0x07, 0x5b, 0xcd, 0x15]
        );

        eval!(
            FollowOnFragmentDeliveryInstructions {
                fragment_number: 37,
                last_fragment: true,
                msg_id: 123_456_789,
            },
            [0xcb, 0x07, 0x5b, 0xcd, 0x15]
        );
    }

    #[test]
    fn test_tunnel_message() {
        let iv = [0; 16];

        macro_rules! eval {
            ($value:expr, $expected:expr) => {
                let mut res = vec![];
                res.resize(1024, 0);
                match gen_tunnel_message((&mut res, 0), &iv[..], &$value) {
                    Ok(_) => {
                        // IV
                        assert_eq!(&res[0..16], &iv[..]);
                        // Non-zero padding
                        res[16..1024 - $value.byte_len() - 1]
                            .iter()
                            .for_each(|b| assert!(*b != 0));
                        // Zero byte
                        assert_eq!(res[1024 - $value.byte_len() - 1], 0);
                        // Expected content
                        assert_eq!(&res[1024 - $value.byte_len()..], &$expected);
                    }
                    Err(e) => panic!("Unexpected error: {:?}", e),
                }
                match tunnel_message(&res) {
                    Ok((_, m)) => assert_eq!(m, $value),
                    Err(e) => panic!("Unexpected error: {:?}", e),
                }
            };
        }

        eval!(
            TunnelMessage(vec![
                (
                    TunnelMessageDeliveryInstructions::First(FirstFragmentDeliveryInstructions {
                        delivery_type: TunnelMessageDeliveryType::Local,
                        msg_id: Some(123_456_789),
                    }),
                    &vec![0x12, 0x34, 0x56, 0x78][..]
                ),
                (
                    TunnelMessageDeliveryInstructions::FollowOn(
                        FollowOnFragmentDeliveryInstructions {
                            fragment_number: 1,
                            last_fragment: false,
                            msg_id: 123_456_789,
                        }
                    ),
                    &vec![0x9a, 0xbc, 0xde][..]
                )
            ]),
            [
                0x08, 0x07, 0x5b, 0xcd, 0x15, 0x00, 0x04, 0x12, 0x34, 0x56, 0x78, 0x82, 0x07, 0x5b,
                0xcd, 0x15, 0x00, 0x03, 0x9a, 0xbc, 0xde
            ]
        );

        eval!(
            TunnelMessage(vec![
                (
                    TunnelMessageDeliveryInstructions::FollowOn(
                        FollowOnFragmentDeliveryInstructions {
                            fragment_number: 37,
                            last_fragment: true,
                            msg_id: 123_456_789,
                        }
                    ),
                    &vec![0xee, 0xee, 0xee][..]
                ),
                (
                    TunnelMessageDeliveryInstructions::First(FirstFragmentDeliveryInstructions {
                        delivery_type: TunnelMessageDeliveryType::Local,
                        msg_id: None,
                    }),
                    &vec![0xff, 0xff, 0xff, 0xff, 0xff][..]
                )
            ]),
            [
                0xcb, 0x07, 0x5b, 0xcd, 0x15, 0x00, 0x03, 0xee, 0xee, 0xee, 0x00, 0x00, 0x05, 0xff,
                0xff, 0xff, 0xff, 0xff
            ]
        );
    }
}
