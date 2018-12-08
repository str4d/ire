use cookie_factory::*;
use nom::*;

use super::{
    auth::{ClientAuthData, ClientAuthType, AUTH_COOKIE_LEN, AUTH_ID_LEN},
    EncLS2ClientAuth, EncLS2Payload, EncryptedLS2,
};
use crate::constants::{NETDB_STORE_ENC_LS2, NETDB_STORE_LS2, NETDB_STORE_META_LS2};
use crate::crypto::frame::{
    gen_sig_type, gen_signature, gen_signing_key, sig_type, signature, signing_key,
};
use crate::data::ls2::frame::{
    gen_lease_set_2, gen_meta_ls2, gen_transient_key, lease_set_2, meta_ls2, transient_key,
};

// Layer 2: payload

named!(
    pub(crate) enc_ls2_payload<EncLS2Payload>,
    switch!(be_u8,
        NETDB_STORE_LS2 => do_parse!(ls2: lease_set_2 >> (EncLS2Payload::LS2(ls2))) |
        NETDB_STORE_META_LS2 => do_parse!(meta_ls2: meta_ls2 >> (EncLS2Payload::MetaLS2(meta_ls2)))
    )
);

pub(crate) fn gen_enc_ls2_payload<'a>(
    input: (&'a mut [u8], usize),
    payload: &EncLS2Payload,
) -> Result<(&'a mut [u8], usize), GenError> {
    match payload {
        EncLS2Payload::LS2(ls2) => {
            do_gen!(input, gen_be_u8!(NETDB_STORE_LS2) >> gen_lease_set_2(ls2))
        }
        EncLS2Payload::MetaLS2(meta_ls2) => do_gen!(
            input,
            gen_be_u8!(NETDB_STORE_META_LS2) >> gen_meta_ls2(meta_ls2)
        ),
    }
}

// Layer 1: client authentication

named!(
    client_auth_data<ClientAuthData>,
    do_parse!(
        client_id: take!(AUTH_ID_LEN)
            >> client_cookie: take!(AUTH_COOKIE_LEN)
            >> ({
                let client_id = {
                    let mut tmp = [0; AUTH_ID_LEN];
                    tmp.copy_from_slice(client_id);
                    tmp
                };
                let client_cookie = {
                    let mut tmp = [0; AUTH_COOKIE_LEN];
                    tmp.copy_from_slice(client_cookie);
                    tmp
                };
                ClientAuthData {
                    client_id,
                    client_cookie,
                }
            })
    )
);

fn gen_client_auth_data<'a>(
    input: (&'a mut [u8], usize),
    auth_data: &ClientAuthData,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_slice!(auth_data.client_id) >> gen_slice!(auth_data.client_cookie)
    )
}

struct ClientAuthFlags {
    per_client: bool,
    auth_type: u8,
}

impl ClientAuthFlags {
    fn none() -> Self {
        ClientAuthFlags {
            per_client: false,
            auth_type: 0,
        }
    }

    fn with_type(auth_type: u8) -> Self {
        ClientAuthFlags {
            per_client: true,
            auth_type,
        }
    }
}

fn gen_client_auth_flags<'a>(
    input: (&'a mut [u8], usize),
    flags: &ClientAuthFlags,
) -> Result<(&'a mut [u8], usize), GenError> {
    let mut x: u8 = 0;
    if flags.per_client {
        x |= 0b0001;
        x |= (flags.auth_type << 1) & 0b1110;
    }
    gen_be_u8!(input, x)
}

pub fn take_all<'a>(input: &'a [u8]) -> IResult<&'a [u8], &'a [u8]> {
    let (res, i) = input.split_at(input.len());
    Ok((i, res))
}

named!(
    pub(crate) enc_ls2_client_auth<EncLS2ClientAuth>,
    do_parse!(
        flags:
            bits!(do_parse!(
                take_bits!(u8, 4)
                    >> auth_type: take_bits!(u8, 3)
                    >> per_client: take_bits!(u8, 1)
                    >> (ClientAuthFlags {
                        per_client: per_client > 0,
                        auth_type,
                    })
            ))
            >> auth_data:
                cond!(
                    flags.per_client,
                    switch!(value!(flags.auth_type),
                        0 => do_parse!(
                            epk: take!(32) >>
                            entries: length_count!(be_u16, client_auth_data) >>
                            (ClientAuthType::X25519({
                                let mut point = [0; 32];
                                point.copy_from_slice(epk);
                                point
                            }, entries))
                        ) |
                        1 => do_parse!(
                            auth_salt: take!(32) >>
                            entries: length_count!(be_u16, client_auth_data) >>
                            (ClientAuthType::PSK({
                                let mut salt = [0; 32];
                                salt.copy_from_slice(auth_salt);
                                salt
                            }, entries))
                        )
                    )
                )
            >> inner_ciphertext: call!(take_all)
            >> (EncLS2ClientAuth {
                auth_data,
                inner_ciphertext: inner_ciphertext.to_vec(),
            })
    )
);

pub(crate) fn gen_enc_ls2_client_auth<'a>(
    input: (&'a mut [u8], usize),
    client_auth: &EncLS2ClientAuth,
) -> Result<(&'a mut [u8], usize), GenError> {
    match client_auth.auth_data.as_ref() {
        None => do_gen!(
            input,
            gen_client_auth_flags(&ClientAuthFlags::none())
                >> gen_slice!(client_auth.inner_ciphertext)
        ),
        Some(ClientAuthType::X25519(epk, auth_data)) => do_gen!(
            input,
            gen_client_auth_flags(&ClientAuthFlags::with_type(0))
                >> gen_slice!(epk.as_bytes())
                >> gen_be_u16!(auth_data.len())
                >> gen_many!(&auth_data, gen_client_auth_data)
                >> gen_slice!(client_auth.inner_ciphertext)
        ),
        Some(ClientAuthType::PSK(auth_salt, auth_data)) => do_gen!(
            input,
            gen_client_auth_flags(&ClientAuthFlags::with_type(1))
                >> gen_slice!(&auth_salt)
                >> gen_be_u16!(auth_data.len())
                >> gen_many!(&auth_data, gen_client_auth_data)
                >> gen_slice!(client_auth.inner_ciphertext)
        ),
    }
}

// Layer 0: plaintext information

struct EncLS2Flags {
    offline: bool,
}

named!(
    pub encrypted_ls2<EncryptedLS2>,
    do_parse!(
        blinded_sig_type: sig_type
            >> blinded_key: call!(signing_key, blinded_sig_type)
            >> created: be_u32
            >> expires: be_u16
            >> flags:
                bits!(do_parse!(
                    take_bits!(u16, 15)
                        >> offline: take_bits!(u8, 1)
                        >> (EncLS2Flags {
                            offline: offline > 0,
                        })
                ))
            >> transient: cond!(flags.offline, call!(transient_key, blinded_sig_type))
            >> outer_ciphertext: length_data!(be_u16)
            >> signature:
                call!(
                    signature,
                    if let Some(transient) = transient.as_ref() {
                        transient.pubkey.sig_type()
                    } else {
                        blinded_sig_type
                    }
                )
            >> (EncryptedLS2 {
                blinded_key,
                created,
                expires,
                transient,
                outer_ciphertext: outer_ciphertext.to_vec(),
                signature: Some(signature),
            })
    )
);

fn gen_encrypted_ls2_minus_sig<'a>(
    input: (&'a mut [u8], usize),
    enc_ls2: &EncryptedLS2,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_sig_type(enc_ls2.blinded_key.sig_type())
            >> gen_signing_key(&enc_ls2.blinded_key)
            >> gen_be_u32!(enc_ls2.created)
            >> gen_be_u16!(enc_ls2.expires)
            >> gen_be_u16!({
                let mut x: u16 = 0;
                if enc_ls2.transient.is_some() {
                    x |= 0b01;
                }
                x
            })
            >> gen_cond!(
                enc_ls2.transient.is_some(),
                do_gen!(gen_transient_key(enc_ls2.transient.as_ref().unwrap()))
            )
            >> gen_be_u16!(enc_ls2.outer_ciphertext.len())
            >> gen_slice!(enc_ls2.outer_ciphertext)
    )
}

pub fn gen_encrypted_ls2_signed_msg<'a>(
    input: (&'a mut [u8], usize),
    enc_ls2: &EncryptedLS2,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_be_u8!(NETDB_STORE_ENC_LS2) >> gen_encrypted_ls2_minus_sig(enc_ls2)
    )
}

pub fn gen_encrypted_ls2<'a>(
    input: (&'a mut [u8], usize),
    enc_ls2: &EncryptedLS2,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_encrypted_ls2_minus_sig(enc_ls2) >> gen_signature(enc_ls2.signature.as_ref().unwrap())
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
    fn test_enc_ls2_client_auth() {
        macro_rules! eval {
            ($value:expr, $expected:expr) => {
                bake_and_eat!(
                    gen_enc_ls2_client_auth,
                    enc_ls2_client_auth,
                    $value,
                    $expected
                )
            };
        }

        eval!(
            EncLS2ClientAuth {
                auth_data: None,
                inner_ciphertext: vec![],
            },
            [0x00]
        );

        eval!(
            EncLS2ClientAuth {
                auth_data: None,
                inner_ciphertext: vec![1, 2, 3, 4],
            },
            [0x00, 0x01, 0x02, 0x03, 0x04]
        );

        eval!(
            EncLS2ClientAuth {
                auth_data: Some(ClientAuthType::X25519([0xff; 32], vec![])),
                inner_ciphertext: vec![1, 2, 3, 4],
            },
            &[
                0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04
            ][..]
        );

        eval!(
            EncLS2ClientAuth {
                auth_data: Some(ClientAuthType::PSK([0xff; 32], vec![])),
                inner_ciphertext: vec![1, 2, 3, 4],
            },
            &[
                0x03, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04
            ][..]
        );
    }
}
