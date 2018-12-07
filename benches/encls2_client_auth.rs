use criterion::{criterion_group, criterion_main, Criterion};
use ire::{
    crypto::{SigningPrivateKey, SigningPublicKey},
    data::{
        dest::DestinationSecretKeys,
        ls2::{
            enc::{
                auth::{ClientInfo, ClientSecretKey, X25519ClientInfo},
                EncLS2Payload, EncryptedLS2,
            },
            LeaseSet2,
        },
    },
};
use rand::{thread_rng, RngCore};
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

fn fake_ls2(created: u32, expires: u16) -> LeaseSet2 {
    let (dest, ls2_sigkey) = {
        let dsk = DestinationSecretKeys::new();
        (dsk.dest, dsk.signing_private_key)
    };

    let mut ls2 = LeaseSet2::new(dest, created, expires, None);
    ls2.sign(&ls2_sigkey).unwrap();
    ls2
}

fn server_x25519(c: &mut Criterion) {
    let mut rng = thread_rng();
    let ls2 = fake_ls2(123_456_789, 2345);

    let payload = EncLS2Payload::LS2(ls2);
    let credential = b"credential";

    let blinded_privkey = SigningPrivateKey::new();
    let blinded_pubkey = SigningPublicKey::from_secret(&blinded_privkey).unwrap();

    c.bench_function_over_inputs(
        "EncLS2_Server_X25519",
        move |b, &&count| {
            let mut client_info = Vec::with_capacity(count);
            for _ in 0..count {
                let mut x25519_sk = [0u8; 32];
                rng.fill_bytes(&mut x25519_sk);
                let x25519_pk = x25519(x25519_sk, X25519_BASEPOINT_BYTES);
                client_info.push(X25519ClientInfo(x25519_pk));
            }
            let client_info = ClientInfo::X25519(client_info);

            b.iter(|| {
                EncryptedLS2::encrypt_payload(
                    &payload,
                    credential,
                    blinded_pubkey.clone(),
                    None,
                    &blinded_privkey,
                    Some(client_info.clone()),
                )
            })
        },
        &[1, 10, 20, 50, 100],
    );
}

fn client_x25519(c: &mut Criterion) {
    let mut rng = thread_rng();
    let ls2 = fake_ls2(123_456_789, 2345);

    let payload = EncLS2Payload::LS2(ls2);
    let credential = b"credential";

    let blinded_privkey = SigningPrivateKey::new();
    let blinded_pubkey = SigningPublicKey::from_secret(&blinded_privkey).unwrap();

    c.bench_function_over_inputs(
        "EncLS2_Client_X25519",
        move |b, &&count| {
            let mut auth_keys = Vec::with_capacity(count);
            let mut client_info = Vec::with_capacity(count);
            for _ in 0..count {
                let mut x25519_sk = [0u8; 32];
                rng.fill_bytes(&mut x25519_sk);
                let x25519_pk = x25519(x25519_sk, X25519_BASEPOINT_BYTES);

                auth_keys.push(ClientSecretKey::X25519(x25519_sk));
                client_info.push(X25519ClientInfo(x25519_pk));
            }
            let client_info = ClientInfo::X25519(client_info);

            let enc_ls2 = EncryptedLS2::encrypt_payload(
                &payload,
                credential,
                blinded_pubkey.clone(),
                None,
                &blinded_privkey,
                Some(client_info.clone()),
            )
            .unwrap();

            b.iter(|| enc_ls2.decrypt(credential, Some(&auth_keys.last().unwrap())))
        },
        &[1, 10, 20, 50, 100],
    );
}

criterion_group!(benches, server_x25519, client_x25519);
criterion_main!(benches);
