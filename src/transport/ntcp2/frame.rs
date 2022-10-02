use std::io::Write;

use cookie_factory::{
    bytes::{be_u16 as gen_be_u16, be_u32 as gen_be_u32, be_u64 as gen_be_u64, be_u8 as gen_be_u8},
    combinator::{back_to_the_buffer, slice as gen_slice},
    gen, gen_simple,
    multi::many_ref as gen_many_ref,
    sequence::{pair as gen_pair, tuple as gen_tuple},
    Seek, SerializeFn, WriteContext,
};
use nom::{
    bits::{bits, streaming::take as take_bits},
    bytes::streaming::{tag, take},
    combinator::{complete, map},
    error::Error as NomError,
    multi::{length_data, length_value, many1},
    number::streaming::{be_u16, be_u32, be_u64, be_u8},
    sequence::{pair, preceded, tuple},
    IResult,
};
use rand::{rngs::OsRng, Rng};

use crate::data::RouterInfo;
use crate::i2np::frame::{gen_ntcp2_message, ntcp2_message};
use crate::i2np::Message;
use crate::{
    data::frame::{gen_router_info, router_info},
    util::gen_bttb,
};

use super::{Block, Frame, RouterInfoFlags};

//
// Blocks
//

// DateTime

fn datetime(i: &[u8]) -> IResult<&[u8], Block> {
    map(preceded(tag("\x00\x04"), be_u32), Block::DateTime)(i)
}

fn gen_datetime<W: Write>(ts: u32) -> impl SerializeFn<W> {
    gen_pair(gen_be_u16(4), gen_be_u32(ts))
}

// Options

fn options(i: &[u8]) -> IResult<&[u8], Block> {
    map(length_data(be_u16), |options| {
        Block::Options(Vec::from(options))
    })(i)
}

fn gen_options<'a, W: 'a + Write>(options: &'a [u8]) -> impl SerializeFn<W> + 'a {
    gen_pair(gen_be_u16(options.len() as u16), gen_slice(options))
}

// RouterInfo

fn routerinfo_flags(i: &[u8]) -> IResult<&[u8], RouterInfoFlags> {
    map(
        bits(preceded(
            take_bits::<_, u8, _, NomError<_>>(7u8),
            take_bits(1u8),
        )),
        |flood: u8| RouterInfoFlags { flood: flood > 0 },
    )(i)
}

fn gen_routerinfo_flags<'a, W: 'a + Write>(flags: &RouterInfoFlags) -> impl SerializeFn<W> + 'a {
    let mut x: u8 = 0;
    if flags.flood {
        x |= 0b01;
    }
    gen_be_u8(x)
}

fn routerinfo(i: &[u8]) -> IResult<&[u8], Block> {
    map(
        length_value(be_u16, pair(routerinfo_flags, router_info)),
        |(flags, ri)| Block::RouterInfo(ri, flags),
    )(i)
}

fn gen_routerinfo<'a, W: 'a + Seek>(
    ri: &'a RouterInfo,
    flags: &'a RouterInfoFlags,
) -> impl SerializeFn<W> + 'a {
    back_to_the_buffer(
        2,
        move |buf| {
            gen_bttb(
                gen_pair(gen_routerinfo_flags(flags), gen_router_info(ri)),
                buf,
            )
        },
        move |buf, len| gen_be_u16(len as u16)(buf),
    )
}

// I2NP Message

fn message(i: &[u8]) -> IResult<&[u8], Block> {
    map(length_value(be_u16, ntcp2_message), Block::Message)(i)
}

fn gen_message<'a, W: 'a + Seek>(message: &'a Message) -> impl SerializeFn<W> + 'a {
    back_to_the_buffer(
        2,
        move |buf| gen_bttb(gen_ntcp2_message(message), buf),
        move |buf, len| gen_be_u16(len as u16)(buf),
    )
}

// Termination

fn termination(i: &[u8]) -> IResult<&[u8], Block> {
    let (i, size) = be_u16(i)?;
    map(
        tuple((be_u64, be_u8, take(size - 9))),
        |(valid_received, rsn, addl_data)| {
            Block::Termination(valid_received, rsn, Vec::from(addl_data))
        },
    )(i)
}

fn gen_termination<'a, W: 'a + Seek>(
    valid_received: u64,
    rsn: u8,
    addl_data: &'a [u8],
) -> impl SerializeFn<W> + 'a {
    back_to_the_buffer(
        2,
        move |buf| {
            gen(
                gen_tuple((
                    gen_be_u64(valid_received),
                    gen_be_u8(rsn),
                    gen_slice(addl_data),
                )),
                buf,
            )
        },
        move |buf, len| gen_simple(gen_be_u16(len as u16), buf),
    )
}

// Padding

fn padding(i: &[u8]) -> IResult<&[u8], Block> {
    let (i, size) = be_u16(i)?;
    take(size as usize)(i).map(|(i, _)| (i, Block::Padding(size)))
}

fn gen_padding<W: Write>(size: u16) -> impl SerializeFn<W> {
    let mut padding = vec![0u8; size as usize];
    let mut rng = OsRng;
    rng.fill(&mut padding[..]);
    gen_pair(gen_be_u16(size), gen_slice(padding))
}

// Unknown

fn unknown(i: &[u8]) -> IResult<&[u8], Vec<u8>> {
    map(length_data(be_u16), Vec::from)(i)
}

fn gen_unknown<'a, W: 'a + Write>(data: &'a [u8]) -> impl SerializeFn<W> + 'a {
    gen_pair(gen_be_u16(data.len() as u16), gen_slice(data))
}

//
// Framing
//

fn block(i: &[u8]) -> IResult<&[u8], Block> {
    let (i, blk) = be_u8(i)?;
    match blk {
        0 => datetime(i),
        1 => options(i),
        2 => routerinfo(i),
        3 => message(i),
        4 => termination(i),
        254 => padding(i),
        _ => map(unknown, |data| Block::Unknown(blk, data))(i),
    }
}

fn gen_block<'a, W: 'a + Seek>(block: &'a Block) -> impl SerializeFn<W> + 'a {
    macro_rules! blockgen {
        ($block_type: expr, $block_gen: ident($($block_data: expr),+)) => {
            gen_pair(gen_be_u8($block_type), $block_gen($($block_data),+))
        };
    }

    move |w: WriteContext<W>| match block {
        Block::DateTime(ts) => blockgen!(0, gen_datetime(*ts))(w),
        Block::Options(ref options) => blockgen!(1, gen_options(options))(w),
        Block::RouterInfo(ref ri, ref flags) => blockgen!(2, gen_routerinfo(ri, flags))(w),
        Block::Message(ref message) => blockgen!(3, gen_message(message))(w),
        Block::Termination(valid_received, rsn, ref addl_data) => {
            blockgen!(4, gen_termination(*valid_received, *rsn, addl_data))(w)
        }
        Block::Padding(size) => blockgen!(254, gen_padding(*size))(w),
        Block::Unknown(blk, ref data) => blockgen!(*blk, gen_unknown(data))(w),
    }
}

pub fn frame(i: &[u8]) -> IResult<&[u8], Frame> {
    many1(complete(block))(i)
}

#[allow(clippy::ptr_arg)]
pub fn gen_frame<'a, W: 'a + Seek>(frame: &'a Frame) -> impl SerializeFn<W> + 'a {
    gen_many_ref(frame, gen_block)
}

//
// Handshake
//

// SessionRequest

pub fn session_request(i: &[u8]) -> IResult<&[u8], (u8, u16, u16, u32)> {
    map(
        tuple((
            // TODO(0.9.42): id
            take(1usize),
            be_u8,
            be_u16,
            be_u16,
            take(2usize),
            be_u32,
            take(4usize),
        )),
        |(_, ver, padlen, sclen, _, ts_a, _)| (ver, padlen, sclen, ts_a),
    )(i)
}

pub fn gen_session_request<W: Write>(
    ver: u8,
    padlen: u16,
    sclen: u16,
    ts_a: u32,
) -> impl SerializeFn<W> {
    gen_tuple((
        gen_slice([0u8]),
        gen_be_u8(ver),
        gen_be_u16(padlen),
        gen_be_u16(sclen),
        gen_slice([0u8; 2]),
        gen_be_u32(ts_a),
        gen_slice([0u8; 4]),
    ))
}

// SessionCreated

pub fn session_created(i: &[u8]) -> IResult<&[u8], (u16, u32)> {
    map(
        tuple((take(2usize), be_u16, take(4usize), be_u32, take(4usize))),
        |(_, padlen, _, ts_b, _)| (padlen, ts_b),
    )(i)
}

pub fn gen_session_created<W: Write>(padlen: u16, ts_b: u32) -> impl SerializeFn<W> {
    gen_tuple((
        gen_slice([0u8; 2]),
        gen_be_u16(padlen),
        gen_slice([0u8; 4]),
        gen_be_u32(ts_b),
        gen_slice([0u8; 4]),
    ))
}

// SessionConfirmed

pub fn session_confirmed(i: &[u8]) -> IResult<&[u8], (Frame)> {
    frame(i)
}

pub fn gen_session_confirmed<'a, W: 'a + Seek>(
    ri_a: &'a RouterInfo,
    padlen: u16,
) -> impl SerializeFn<W> + 'a {
    move |w: WriteContext<W>| {
        gen_frame(&vec![
            Block::RouterInfo(ri_a.clone(), RouterInfoFlags { flood: false }),
            Block::Padding(padlen),
        ])(w)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::time::{Duration, UNIX_EPOCH};

    use crate::data::I2PDate;
    use crate::i2np::MessagePayload;
    use crate::tests::ROUTER_INFO;

    use super::*;

    macro_rules! bake_and_eat {
        ($oven:expr, $monster:expr, $value:expr, $expected:expr) => {
            let mut res = vec![];
            res.resize($expected.len(), 0);
            match gen($oven(&$value), Cursor::new(&mut res[..])) {
                Ok(_) => assert_eq!(&res, &$expected),
                Err(e) => panic!("Unexpected error: {:?}", e),
            }
            match $monster(&res) {
                Ok((_, m)) => assert_eq!(m, $value),
                Err(e) => panic!("Unexpected error: {:?}", e),
            }
        };
    }

    macro_rules! eval_block {
        ($value:expr, $expected:expr) => {
            bake_and_eat!(gen_block, block, $value, $expected)
        };
    }

    #[test]
    fn test_datetime() {
        eval_block!(
            Block::DateTime(42),
            [0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x2a]
        );
    }

    #[test]
    fn test_options() {
        eval_block!(
            Block::Options(vec![0x00, 0x01, 0x02, 0x03, 0x04]),
            [0x01, 0x00, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04]
        );
    }

    #[test]
    fn test_router_info() {
        let ri = match router_info(ROUTER_INFO) {
            Ok((_, ri)) => ri,
            Err(e) => panic!("Unexpected error: {:?}", e),
        };
        let mut ri_block = vec![0x02, 0x02, 0x9f, 0x01];
        ri_block.extend_from_slice(ROUTER_INFO);

        eval_block!(
            Block::RouterInfo(ri.clone(), RouterInfoFlags { flood: true }),
            ri_block
        );
    }

    #[test]
    fn test_message() {
        eval_block!(
            Block::Message(Message {
                id: 0,
                expiration: I2PDate::from_system_time(UNIX_EPOCH + Duration::new(1_524_874_654, 0)),
                payload: MessagePayload::Data(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
            }),
            [
                0x03, 0x00, 0x17, 0x14, 0x00, 0x00, 0x00, 0x00, 0x5a, 0xe3, 0xbd, 0x9e, 0x00, 0x00,
                0x00, 0x0a, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            ]
        );
    }

    #[test]
    fn test_termination() {
        eval_block!(
            Block::Termination(42, 7, vec![0xfe]),
            [0x04, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x07, 0xfe,]
        );
    }

    #[test]
    fn test_padding() {
        // Test parsing
        match block(&[
            0xfe, 0x00, 0x0a, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        ]) {
            Ok((_, m)) => assert_eq!(m, Block::Padding(10)),
            Err(e) => panic!("Unexpected error: {:?}", e),
        }

        // Test generation
        let pad_block = Block::Padding(10);
        let mut res1 = vec![];
        res1.resize(13, 0);
        match gen(gen_block(&pad_block), Cursor::new(&mut res1[..])) {
            Ok(_) => (),
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
        let mut res2 = vec![];
        res2.resize(13, 0);
        match gen(gen_block(&pad_block), Cursor::new(&mut res2[..])) {
            Ok(_) => (),
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
        // Headers should be equal
        assert_eq!(&res1[..3], &res2[..3]);
        // Padding should not be equal
        assert!(res1 != res2);
    }

    #[test]
    fn test_unknown() {
        eval_block!(
            Block::Unknown(224, vec![0x12, 0x34, 0x56, 0x78, 0x9a]),
            [0xe0, 0x00, 0x05, 0x12, 0x34, 0x56, 0x78, 0x9a]
        );
    }

    #[test]
    fn test_session_request() {
        let mut res = vec![];
        res.resize(16, 0);
        match gen(
            gen_session_request(0x12, 0x3456, 0x789a, 0xbcde_f123),
            &mut res,
        ) {
            Ok(_) => assert_eq!(
                &res,
                &[
                    0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0x00, 0x00, 0xbc, 0xde, 0xf1, 0x23, 0x00,
                    0x00, 0x00, 0x00
                ]
            ),
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
        match session_request(&res) {
            Ok((_, sr)) => assert_eq!(sr, (0x12, 0x3456, 0x789a, 0xbcde_f123)),
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_session_created() {
        let mut res = vec![];
        res.resize(16, 0);
        match gen(gen_session_created(0x1234, 0x5678_9abc), &mut res) {
            Ok(_) => assert_eq!(
                &res,
                &[
                    0x00, 0x00, 0x12, 0x34, 0x00, 0x00, 0x00, 0x00, 0x56, 0x78, 0x9a, 0xbc, 0x00,
                    0x00, 0x00, 0x00
                ]
            ),
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
        match session_created(&res) {
            Ok((_, sr)) => assert_eq!(sr, (0x1234, 0x5678_9abc)),
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }
}
