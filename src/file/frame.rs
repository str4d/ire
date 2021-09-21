use nom::{
    bytes::streaming::{tag, take, take_while},
    character::streaming::{char, one_of},
    combinator::{map, map_res, success, value, verify},
    error::{Error as NomError, ErrorKind},
    multi::length_value,
    number::streaming::{be_u16, be_u64, be_u8},
    sequence::{preceded, tuple},
    Err, IResult,
};
use std::io::{Cursor, Read};
use std::str::from_utf8;

use super::{Error, Su3Content, Su3File, SU3_MAGIC};
use crate::crypto::{
    frame::{sig_type, signature},
    SigType,
};
use crate::data::{frame::router_info, ReadError};

fn su3_sig_len(sig_type: SigType) -> impl Fn(&[u8]) -> IResult<&[u8], u16> {
    move |i: &[u8]| verify(be_u16, |sig_len| *sig_len as u32 == sig_type.sig_len())(i)
}

fn su3_version(version_len: u8) -> impl Fn(&[u8]) -> IResult<&[u8], &str> {
    move |i: &[u8]| {
        map_res(
            length_value(success(version_len), take_while(|ch| ch != 0)),
            from_utf8,
        )(i)
    }
}

fn su3_signer(signer_len: u8) -> impl Fn(&[u8]) -> IResult<&[u8], &str> {
    move |i: &[u8]| map_res(take(signer_len as usize), from_utf8)(i)
}

fn su3_zip_reseed(input: &[u8], content_len: u64) -> IResult<&[u8], Su3Content> {
    let (i, content) = take(content_len)(input)?;
    let reader = Cursor::new(content);
    let mut zip = zip::ZipArchive::new(reader)
        .map_err(|_| Err::Error(NomError::new(input, ErrorKind::Verify)))?;

    let ri = (0..zip.len())
        .filter_map(|j| {
            let mut file = zip.by_index(j).unwrap();
            let mut buf = Vec::with_capacity(file.size() as usize);
            if let Err(e) = file
                .read_to_end(&mut buf)
                .map_err(|_| Err::Error(NomError::new(input, ErrorKind::Eof)))
            {
                return Some(Err(e));
            }

            match router_info(&buf) {
                Ok((_, ri)) => Some(Ok(ri)),
                Err(e) => {
                    warn!("Error while parsing {} from reseed:\n{}", file.name(), e);
                    None
                }
            }
        })
        .collect::<Result<_, _>>()?;

    Ok((i, Su3Content::Reseed(ri)))
}

fn su3_content(
    content_len: u64,
    file_type: u8,
    content_type: u8,
) -> impl Fn(&[u8]) -> IResult<&[u8], Su3Content> {
    move |i: &[u8]| match (file_type, content_type) {
        (0x00, 0x03) => su3_zip_reseed(i, content_len),
        _ => unimplemented!(),
    }
}

pub fn su3_file(i: &[u8]) -> IResult<&[u8], Su3File> {
    let (i, (_magic, _, _format_version, sig_type)) =
        tuple((tag(SU3_MAGIC), be_u8, tag(b"\x00"), sig_type))(i)?;

    let (i, (_, _, version_len, _, signer_len, content_len, _, file_type, _, content_type, _)) =
        tuple((
            su3_sig_len(sig_type),
            be_u8,
            verify(be_u8, |len| *len >= 16),
            be_u8,
            be_u8,
            be_u64,
            be_u8,
            be_u8,
            be_u8,
            be_u8,
            take(12usize),
        ))(i)?;

    map(
        tuple((
            su3_version(version_len),
            su3_signer(signer_len),
            su3_content(content_len, file_type, content_type),
            signature(sig_type),
        )),
        move |(version, signer, content, sig)| Su3File {
            version: String::from(version),
            signer: String::from(signer),
            content,
            sig_type,
            msg_len: 40 + version_len as usize + signer_len as usize + content_len as usize,
            sig,
        },
    )(i)
}

// Simple HTTP parser to convert status code into an error
pub fn http_status_line(i: &[u8]) -> IResult<&[u8], Result<(), Error>> {
    map(
        preceded(
            tuple((tag("HTTP/1."), one_of("01"), char(' '))),
            take(3usize),
        ),
        |status| {
            if let Ok(status) = std::str::from_utf8(status) {
                if let Ok(status) = status.parse::<u16>() {
                    if status == 200 {
                        Ok(())
                    } else {
                        Err(Error::Http(status))
                    }
                } else {
                    Err(Error::Read(ReadError::Parser))
                }
            } else {
                Err(Error::Read(ReadError::Parser))
            }
        },
    )(i)
}
