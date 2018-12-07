use nom::{be_u16, be_u64, be_u8, Err, ErrorKind, IResult};
use std::io::{Cursor, Read};
use std::str::from_utf8;
use zip;

use super::{Error, Su3Content, Su3File, SU3_MAGIC};
use crypto::{
    frame::{sig_type, signature},
    SigType,
};
use data::{frame::router_info, ReadError};

named_args!(su3_sig_len(sig_type: SigType)<u16>,
    verify!(be_u16, |sig_len| sig_len as u32 == sig_type.sig_len())
);

named_args!(su3_version(version_len: u8)<&str>,
    map_res!(length_value!(value!(version_len), take_while!(|ch| ch != 0)), from_utf8)
);

fn su3_zip_reseed<'a>(input: &'a [u8], content_len: u64) -> IResult<&'a [u8], Su3Content> {
    let (i, content) = take!(input, content_len)?;
    let reader = Cursor::new(content);
    let mut zip = zip::ZipArchive::new(reader)
        .map_err(|_| Err::Error(error_position!(input, ErrorKind::Custom(1))))?;

    let ri = (0..zip.len())
        .filter_map(|j| {
            let mut file = zip.by_index(j).unwrap();
            let mut buf = Vec::with_capacity(file.size() as usize);
            if let Err(e) = file
                .read_to_end(&mut buf)
                .map_err(|_| Err::Error(error_position!(input, ErrorKind::Custom(2))))
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

named_args!(su3_content(content_len: u64, file_type: u8, content_type: u8)<Su3Content>,
    do_parse!(
        content: switch!(value!((file_type, content_type)),
            (0x00, 0x03) => call!(su3_zip_reseed, content_len)
        ) >> (content)
    )
);

named!(pub su3_file<Su3File>, do_parse!(
    _magic:         tag!(SU3_MAGIC) >>
                    take!(1) >>
    _format_version:tag!(b"\x00") >>
    sig_type:       sig_type >>
                    call!(su3_sig_len, sig_type) >>
                    take!(1) >>
    version_len:    be_u8 >>
                    take!(1) >>
    signer_len:     be_u8 >>
    content_len:    be_u64 >>
                    take!(1) >>
    file_type:      be_u8 >>
                    take!(1) >>
    content_type:   be_u8 >>
                    take!(12) >>
    version:        call!(su3_version, version_len) >>
    signer:         take_str!(signer_len) >>
    content:        call!(su3_content, content_len, file_type, content_type) >>
    sig:            call!(signature, sig_type) >>
    (Su3File {
        version: String::from(version),
        signer: String::from(signer),
        content,
        sig_type,
        msg_len: 40 + version_len as usize + signer_len as usize + content_len as usize,
        sig,
    })
));

// Simple HTTP parser to convert status code into an error
named!(pub http_status_line<Result<(), Error>>, do_parse!(
    tag!("HTTP/1.") >> one_of!("01") >> char!(' ') >> status: take!(3) >> (
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
    )
));
