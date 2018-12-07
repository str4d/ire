use cookie_factory::*;
use nom::*;
use rand::{rngs::OsRng, Rng};

use crate::data::frame::{gen_router_info, router_info};
use crate::data::RouterInfo;
use crate::i2np::frame::{gen_ntcp2_message, ntcp2_message};
use crate::i2np::Message;

use super::{Block, Frame, RouterInfoFlags};

//
// Blocks
//

// DateTime

named!(
    datetime<Block>,
    do_parse!(tag!("\x00\x04") >> ts: be_u32 >> (Block::DateTime(ts)))
);

fn gen_datetime(input: (&mut [u8], usize), ts: u32) -> Result<(&mut [u8], usize), GenError> {
    do_gen!(input, gen_be_u16!(4) >> gen_be_u32!(ts))
}

// Options

named!(
    options<Block>,
    do_parse!(options: length_bytes!(be_u16) >> (Block::Options(options.to_vec())))
);

fn gen_options<'a>(
    input: (&'a mut [u8], usize),
    options: &[u8],
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(input, gen_be_u16!(options.len()) >> gen_slice!(options))
}

// RouterInfo

#[cfg_attr(rustfmt, rustfmt_skip)]
named!(
    routerinfo_flags<RouterInfoFlags>,
    bits!(do_parse!(
               take_bits!(u8, 7) >>
        flood: take_bits!(u8, 1) >>
        (RouterInfoFlags {
            flood: flood > 0,
        })
    ))
);

fn gen_routerinfo_flags<'a>(
    input: (&'a mut [u8], usize),
    flags: &RouterInfoFlags,
) -> Result<(&'a mut [u8], usize), GenError> {
    let mut x: u8 = 0;
    if flags.flood {
        x |= 0b01;
    }
    gen_be_u8!(input, x)
}

named!(
    routerinfo<Block>,
    length_value!(
        be_u16,
        do_parse!(flags: routerinfo_flags >> ri: router_info >> (Block::RouterInfo(ri, flags)))
    )
);

fn gen_routerinfo<'a>(
    input: (&'a mut [u8], usize),
    ri: &RouterInfo,
    flags: &RouterInfoFlags,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        size: gen_skip!(2)
            >> start: gen_routerinfo_flags(flags)
            >> gen_router_info(ri)
            >> end: gen_at_offset!(size, gen_be_u16!(end - start))
    )
}

// I2NP Message

named!(
    message<Block>,
    do_parse!(message: length_value!(be_u16, ntcp2_message) >> (Block::Message(message)))
);

fn gen_message<'a>(
    input: (&'a mut [u8], usize),
    message: &Message,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        size: gen_skip!(2)
            >> start: gen_ntcp2_message(message)
            >> end: gen_at_offset!(size, gen_be_u16!(end - start))
    )
}

// Termination

named!(
    termination<Block>,
    do_parse!(
        size: be_u16
            >> valid_received: be_u64
            >> rsn: be_u8
            >> addl_data: take!(size - 9)
            >> (Block::Termination(valid_received, rsn, addl_data.to_vec()))
    )
);

fn gen_termination<'a>(
    input: (&'a mut [u8], usize),
    valid_received: u64,
    rsn: u8,
    addl_data: &[u8],
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        size: gen_skip!(2)
            >> start: gen_be_u64!(valid_received)
            >> gen_be_u8!(rsn)
            >> gen_slice!(addl_data)
            >> end: gen_at_offset!(size, gen_be_u16!(end - start))
    )
}

// Padding

named!(
    padding<Block>,
    do_parse!(size: be_u16 >> take!(size) >> (Block::Padding(size)))
);

fn gen_padding(input: (&mut [u8], usize), size: u16) -> Result<(&mut [u8], usize), GenError> {
    let mut padding = vec![0u8; size as usize];
    let mut rng = OsRng::new().expect("should be able to construct RNG");
    rng.fill(&mut padding[..]);
    do_gen!(input, gen_be_u16!(size) >> gen_slice!(padding))
}

// Unknown

named!(
    unknown<Vec<u8>>,
    do_parse!(size: be_u16 >> data: take!(size) >> (data.to_vec()))
);

fn gen_unknown<'a>(
    input: (&'a mut [u8], usize),
    data: &[u8],
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(input, gen_be_u16!(data.len()) >> gen_slice!(data))
}

//
// Framing
//

named!(
    block<Block>,
    switch!(be_u8,
        0 => call!(datetime) |
        1 => call!(options) |
        2 => call!(routerinfo) |
        3 => call!(message) |
        4 => call!(termination) |
        254 => call!(padding) |
        blk => do_parse!(data: call!(unknown) >> (Block::Unknown(blk, data)))
    )
);

fn gen_block<'a>(
    input: (&'a mut [u8], usize),
    block: &Block,
) -> Result<(&'a mut [u8], usize), GenError> {
    macro_rules! blockgen {
        ($block_type: expr, $block_gen: ident($($block_data: expr),+)) => {
            do_gen!(input, gen_be_u8!($block_type) >> $block_gen($($block_data),+))
        };
    }

    match *block {
        Block::DateTime(ts) => blockgen!(0, gen_datetime(ts)),
        Block::Options(ref options) => blockgen!(1, gen_options(options)),
        Block::RouterInfo(ref ri, ref flags) => blockgen!(2, gen_routerinfo(ri, flags)),
        Block::Message(ref message) => blockgen!(3, gen_message(message)),
        Block::Termination(valid_received, rsn, ref addl_data) => {
            blockgen!(4, gen_termination(valid_received, rsn, addl_data))
        }
        Block::Padding(size) => blockgen!(254, gen_padding(size)),
        Block::Unknown(blk, ref data) => blockgen!(blk, gen_unknown(data)),
    }
}

named!(pub frame<Frame>, many1!(complete!(block)));

pub fn gen_frame<'a>(
    input: (&'a mut [u8], usize),
    frame: &Frame,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(input, gen_many_ref!(frame, gen_block))
}

//
// Handshake
//

// SessionRequest

named!(
    pub session_request<(u8, u16, u16, u32)>,
    do_parse!(
                take!(1) >>
        ver:    be_u8 >>
        padlen: be_u16 >>
        sclen:  be_u16 >>
                take!(2) >>
        ts_a:   be_u32 >>
                take!(4) >>
        (ver, padlen, sclen, ts_a)
    )
);

pub fn gen_session_request(
    input: (&mut [u8], usize),
    ver: u8,
    padlen: u16,
    sclen: u16,
    ts_a: u32,
) -> Result<(&mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_slice!([0u8])
            >> gen_be_u8!(ver)
            >> gen_be_u16!(padlen)
            >> gen_be_u16!(sclen)
            >> gen_slice!([0u8; 2])
            >> gen_be_u32!(ts_a)
            >> gen_slice!([0u8; 4])
    )
}

// SessionCreated

named!(
    pub session_created<(u16, u32)>,
    do_parse!(
                take!(2) >>
        padlen: be_u16 >>
                take!(4) >>
        ts_b:   be_u32 >>
                take!(4) >>
        (padlen, ts_b))
);

pub fn gen_session_created(
    input: (&mut [u8], usize),
    padlen: u16,
    ts_b: u32,
) -> Result<(&mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_slice!([0u8; 2])
            >> gen_be_u16!(padlen)
            >> gen_slice!([0u8; 4])
            >> gen_be_u32!(ts_b)
            >> gen_slice!([0u8; 4])
    )
}

// SessionConfirmed

named!(pub session_confirmed<(Frame)>, call!(frame));

pub fn gen_session_confirmed<'a>(
    input: (&'a mut [u8], usize),
    ri_a: &RouterInfo,
    padlen: u16,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_frame(&vec![
            Block::RouterInfo(ri_a.clone(), RouterInfoFlags { flood: false }),
            Block::Padding(padlen),
        ])
    )
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use crate::data::I2PDate;
    use crate::i2np::MessagePayload;
    use crate::tests::ROUTER_INFO;

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
        match gen_block((&mut res1, 0), &pad_block) {
            Ok(_) => (),
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
        let mut res2 = vec![];
        res2.resize(13, 0);
        match gen_block((&mut res2, 0), &pad_block) {
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
        match gen_session_request((&mut res, 0), 0x12, 0x3456, 0x789a, 0xbcde_f123) {
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
        match gen_session_created((&mut res, 0), 0x1234, 0x5678_9abc) {
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
