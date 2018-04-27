use bytes::BytesMut;
use cookie_factory::GenError;
use nom::Err;
use snow;
use std::fmt;
use std::io;
use std::iter::repeat;
use tokio_io::codec::{Decoder, Encoder};

use data::RouterInfo;
use i2np::Message;

mod frame;

// Max NTCP2 message size is ~64kB
const NTCP2_MTU: usize = 65535;

macro_rules! io_err {
    ($err_kind:ident, $err_msg:expr) => {
        Err(io::Error::new(io::ErrorKind::$err_kind, $err_msg))
    };
}

//
// Message transport
//

#[derive(PartialEq)]
pub struct RouterInfoFlags {
    flood: bool,
}

#[derive(PartialEq)]
pub enum Block {
    DateTime(u32),
    Options(Vec<u8>),
    RouterInfo(RouterInfo, RouterInfoFlags),
    Message(Message),
    Termination(u64, u8, Vec<u8>),
    Padding(u16),
    Unknown(u8, Vec<u8>),
}

impl fmt::Debug for Block {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Block::DateTime(ts) => format!("DateTime ({})", ts).fmt(formatter),
            &Block::Options(_) => "Options".fmt(formatter),
            &Block::RouterInfo(ref ri, ref flags) => format!(
                "RouterInfo ({}, flood: {})",
                ri.router_id.hash(),
                flags.flood
            ).fmt(formatter),
            &Block::Message(_) => "I2NP message".fmt(formatter),
            &Block::Termination(_, rsn, _) => {
                format!("Termination (reason: {})", rsn).fmt(formatter)
            }
            &Block::Padding(size) => format!("Padding ({} bytes)", size).fmt(formatter),
            &Block::Unknown(blk, ref data) => {
                format!("Unknown (type: {}, {} bytes)", blk, data.len()).fmt(formatter)
            }
        }
    }
}

type Frame = Vec<Block>;

pub struct Codec {
    noise: snow::Session,
    noise_buf: [u8; NTCP2_MTU],
    next_len: Option<usize>,
}

impl Decoder for Codec {
    type Item = Frame;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> io::Result<Option<Frame>> {
        if let None = self.next_len {
            if buf.len() < 18 {
                return Ok(None);
            }

            // Read the length
            let mut msg_len_buf = [0u8; 2];
            match self.noise.read_message(&buf[..18], &mut msg_len_buf) {
                Ok(_len) => (),
                Err(e) => return io_err!(Other, format!("Decryption error: {:?}", e)),
            }
            buf.split_to(18);
            self.next_len = Some(((msg_len_buf[0] as usize) << 8) + (msg_len_buf[1] as usize));
        }

        match self.next_len {
            Some(len) if buf.len() >= len => {
                // Read the frame
                let frame_len = match self.noise.read_message(&buf[..len], &mut self.noise_buf) {
                    Ok(len) => len,
                    Err(e) => return io_err!(Other, format!("Decryption error: {:?}", e)),
                };

                // Parse the frame
                let f = match frame::frame(&self.noise_buf[..frame_len]) {
                    Err(Err::Incomplete(n)) => {
                        return io_err!(
                            Other,
                            format!("received incomplete message, needed: {:?}", n)
                        )
                    }
                    Err(Err::Error(e)) | Err(Err::Failure(e)) => {
                        return io_err!(Other, format!("parse error: {:?}", e))
                    }
                    Ok((_, frame)) => frame,
                };

                buf.split_to(len);
                self.next_len = None;

                Ok(Some(f))
            }
            _ => Ok(None),
        }
    }
}

impl Encoder for Codec {
    type Item = Frame;
    type Error = io::Error;

    fn encode(&mut self, frame: Frame, buf: &mut BytesMut) -> io::Result<()> {
        match frame::gen_frame((&mut self.noise_buf, 0), &frame).map(|tup| tup.1) {
            Ok(sz) => {
                let msg_len = sz + 16;
                let msg_len_buf = [(msg_len >> 8) as u8, (msg_len & 0xff) as u8];

                let start = buf.len();
                buf.extend(repeat(0).take(18 + msg_len));

                match self.noise.write_message(&msg_len_buf, &mut buf[start..]) {
                    Ok(len) if len == 18 => match self
                        .noise
                        .write_message(&self.noise_buf[..sz], &mut buf[start + len..])
                    {
                        Ok(len) if len == msg_len => Ok(()),
                        Ok(len) => io_err!(
                            InvalidData,
                            format!("encrypted frame is unexpected size: {}", len)
                        ),
                        Err(e) => io_err!(Other, format!("encryption error: {:?}", e)),
                    },
                    Ok(len) => io_err!(
                        InvalidData,
                        format!("encrypted length is unexpected size: {}", len)
                    ),
                    Err(e) => io_err!(Other, format!("encryption error: {:?}", e)),
                }
            }
            Err(e) => match e {
                GenError::BufferTooSmall(sz) => io_err!(
                    InvalidData,
                    format!("message ({}) larger than MTU ({})", sz, NTCP2_MTU)
                ),
                GenError::InvalidOffset
                | GenError::CustomError(_)
                | GenError::NotYetImplemented => io_err!(InvalidData, "could not generate"),
            },
        }
    }
}
