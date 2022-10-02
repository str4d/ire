use cookie_factory::{
    bytes::{be_u16 as gen_be_u16, be_u32 as gen_be_u32, be_u8 as gen_be_u8},
    combinator::{back_to_the_buffer, cond as gen_cond, slice as gen_slice},
    gen, gen_simple,
    multi::many_ref as gen_many_ref,
    sequence::{pair as gen_pair, tuple as gen_tuple},
    Seek, SerializeFn, WriteContext,
};
use nom::{
    bits::{bits, streaming::take as take_bits},
    bytes::streaming::{tag, take, take_until},
    combinator::{complete, cond, map, peek, verify},
    error::{Error as NomError, ErrorKind},
    multi::{length_data, many0},
    number::streaming::{be_u16, be_u32},
    sequence::{pair, preceded, terminated, tuple},
    Err, IResult,
};
use sha2::{Digest, Sha256};
use std::{io::Write, iter};

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
        Err(Err::Error(NomError::new(input, ErrorKind::Verify)))
    }
}

fn gen_checksum<'a, W: 'a + Write>(contents: &[u8], iv: &[u8]) -> impl SerializeFn<W> + 'a {
    gen_be_u32(checksum(contents, iv))
}

// Padding

fn gen_nonzero_padding<'a, W: 'a + Write>(length: usize) -> impl SerializeFn<W> + 'a {
    // TODO: real non-zero padding
    gen_many_ref(iter::repeat(1).take(length), gen_be_u8)
}

// FirstFragmentDeliveryInstructions

const DELIVERY_TYPE_LOCAL: u8 = 0;
const DELIVERY_TYPE_TUNNEL: u8 = 1;
const DELIVERY_TYPE_ROUTER: u8 = 2;

fn first_frag_di(i: &[u8]) -> IResult<&[u8], FirstFragmentDeliveryInstructions> {
    let (i, (delivery_type, fragmented)) = map(
        bits::<_, (u8, u8, u8, u8, u8), NomError<_>, _, _>(tuple((
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
        _ => Err(nom::Err::Error(NomError::new(i, ErrorKind::Char))),
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

fn gen_first_frag_di<'a, W: 'a + Write>(
    di: &'a FirstFragmentDeliveryInstructions,
) -> impl SerializeFn<W> + 'a {
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
    move |w: WriteContext<W>| match &di.delivery_type {
        TunnelMessageDeliveryType::Local => gen_tuple((
            gen_be_u8(x),
            gen_cond(di.msg_id.is_some(), gen_be_u32(di.msg_id.unwrap())),
        ))(w),
        TunnelMessageDeliveryType::Tunnel(tid, to) => gen_tuple((
            gen_be_u8(x),
            gen_tunnel_id(&tid),
            gen_hash(&to),
            gen_cond(di.msg_id.is_some(), gen_be_u32(di.msg_id.unwrap())),
        ))(w),
        TunnelMessageDeliveryType::Router(to) => gen_tuple((
            gen_be_u8(x),
            gen_hash(&to),
            gen_cond(di.msg_id.is_some(), gen_be_u32(di.msg_id.unwrap())),
        ))(w),
    }
}

// FollowOnFragmentDeliveryInstructions

fn follow_on_frag_di(i: &[u8]) -> IResult<&[u8], FollowOnFragmentDeliveryInstructions> {
    map(
        pair(
            map(
                bits::<_, (u8, u8, u8), NomError<_>, _, _>(tuple((
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

fn gen_follow_on_frag_di<'a, W: 'a + Write>(
    di: &'a FollowOnFragmentDeliveryInstructions,
) -> impl SerializeFn<W> + 'a {
    let mut x = 0b10000000;
    x |= (di.fragment_number << 1) & 0b01111110;
    if di.last_fragment {
        x |= 0b1;
    }
    gen_pair(gen_be_u8(x), gen_be_u32(di.msg_id))
}

// TunnelMessageDeliveryInstructions

fn tmdi(i: &[u8]) -> IResult<&[u8], TunnelMessageDeliveryInstructions> {
    let (i, first) = peek(map(
        bits::<_, _, NomError<(&[u8], usize)>, _, _>(take_bits(1u8)),
        |b: u8| b == 0,
    ))(i)?;
    if first {
        map(first_frag_di, TunnelMessageDeliveryInstructions::First)(i)
    } else {
        map(
            follow_on_frag_di,
            TunnelMessageDeliveryInstructions::FollowOn,
        )(i)
    }
}

fn gen_tmdi<'a, W: 'a + Write>(
    tmdi: &'a TunnelMessageDeliveryInstructions,
) -> impl SerializeFn<W> + 'a {
    move |w: WriteContext<W>| match tmdi {
        TunnelMessageDeliveryInstructions::First(di) => gen_first_frag_di(di)(w),
        TunnelMessageDeliveryInstructions::FollowOn(di) => gen_follow_on_frag_di(di)(w),
    }
}

// TunnelMessage

fn tunnel_message(i: &[u8]) -> IResult<&[u8], TunnelMessage> {
    let (i, (iv, cs, padding)) = terminated(
        tuple((take(16usize), be_u32, take_until(&b"\x00"[..]))),
        tag(&[0]),
    )(i)?;

    preceded(
        verify(peek(take(1008 - 4 - padding.len() - 1)), move |msg_bytes| {
            checksum(msg_bytes, iv) == cs
        }),
        map(
            many0(complete(pair(tmdi, length_data(be_u16)))),
            TunnelMessage,
        ),
    )(i)
}

fn gen_tmdi_fragment_pair<'a, W: 'a + Write>(
    (tmdi, frag): &'a (TunnelMessageDeliveryInstructions, &[u8]),
) -> impl SerializeFn<W> + 'a {
    gen_pair(
        gen_tmdi(tmdi),
        gen_pair(gen_be_u16(frag.len() as u16), gen_slice(frag)),
    )
}

fn gen_tunnel_message<'a, W: 'a + Seek>(
    iv: &'a [u8],
    tm: &'a TunnelMessage,
) -> impl SerializeFn<W> + 'a {
    gen_pair(
        gen_slice(iv),
        back_to_the_buffer(
            4,
            move |buf| {
                let buf = gen_pair(
                    gen_nonzero_padding(1008 - 4 - 1 - tm.byte_len()),
                    gen_be_u8(0),
                )(buf)?;

                // We need to capture these bytes so we can calculate the checksum.
                let mut contents = vec![];
                let (_, len) = gen(gen_many_ref(&tm.0, gen_tmdi_fragment_pair), &mut contents)?;
                contents.truncate(len as usize);
                Ok((gen(gen_slice(&contents), buf)?.0, contents))
            },
            move |buf, contents| gen_simple(gen_checksum(&contents, iv), buf),
        ),
    )
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    macro_rules! bake_and_eat {
        ($oven:expr, $monster:expr, $value:expr, $expected:expr) => {
            let mut res = vec![];
            res.resize($expected.len(), 0);
            match gen($oven(&$value), &mut res) {
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
            Err(Err::Error(NomError {
                input: &a[..],
                code: ErrorKind::Verify
            }))
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
        let res = gen(gen_checksum(&b[4..11], &iv[..]), &mut b);
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
                match gen(
                    gen_tunnel_message(&iv[..], &$value),
                    Cursor::new(&mut res[..]),
                ) {
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
