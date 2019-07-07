//! Tunnel encryption operations.

use aes::{
    self,
    block_cipher_trait::{generic_array::GenericArray as AesGenericArray, BlockCipher},
};

use crate::crypto::{Aes256, SessionKey};
use crate::i2np::TunnelData;

/// Implements layered encryption and decryption of tunnel messages.
///
/// See the ["Participant Processing" section][processing] of the tunnel implementation
/// documentation for details of the algorithm.
///
/// [processing]: https://geti2p.net/en/docs/tunnels/implementation#tunnel.participant
#[derive(Clone, Debug)]
pub struct LayerCipher {
    iv_cipher: aes::Aes256,
    layer_key: SessionKey,
}

impl LayerCipher {
    /// Create a `LayerCipher` for the tunnel hop with the given IV and layer keys.
    pub fn new(iv_key: &SessionKey, layer_key: SessionKey) -> Self {
        let iv_key = AesGenericArray::from_slice(&iv_key.0);
        LayerCipher {
            iv_cipher: aes::Aes256::new(&iv_key),
            layer_key,
        }
    }

    /// Encrypt a [`TunnelData`] message using the IV and layer keys for this hop.
    ///
    /// Used by tunnel participants, including IBGWs and OBEPs that are not the tunnel
    /// creator.
    pub fn encrypt_layer(&self, td: &mut TunnelData) {
        // Encrypt the received IV with AES256/ECB using the IV key to determine the current IV
        self.iv_cipher
            .encrypt_block(AesGenericArray::from_mut_slice(&mut td.data[0..16]));

        // Use that IV with the layer key to encrypt the data
        let mut cipher = Aes256::new(&self.layer_key, &td.data[0..16], &[0; 16]);
        assert_eq!(cipher.encrypt_blocks(&mut td.data[16..]), Some(1008));

        // Encrypt the current IV with AES256/ECB using the IV key again
        self.iv_cipher
            .encrypt_block(AesGenericArray::from_mut_slice(&mut td.data[0..16]));
    }

    /// Decrypt a [`TunnelData`] message using the IV and layer keys for this hop.
    ///
    /// Used by the tunnel creator to preprocess outgoing `TunnelData` messages, and
    /// postprocess incoming `TunnelData` messages.
    pub fn decrypt_layer(&self, td: &mut TunnelData) {
        // Decrypt the received IV with AES256/ECB using the IV key to determine the current IV
        self.iv_cipher
            .decrypt_block(AesGenericArray::from_mut_slice(&mut td.data[0..16]));

        // Use that IV with the layer key to decrypt the data
        let mut cipher = Aes256::new(&self.layer_key, &[0; 16], &td.data[0..16]);
        assert_eq!(cipher.decrypt_blocks(&mut td.data[16..]), Some(1008));

        // Decrypt the current IV with AES256/ECB using the IV key again
        self.iv_cipher
            .decrypt_block(AesGenericArray::from_mut_slice(&mut td.data[0..16]));
    }
}

#[cfg(test)]
mod tests {
    use super::LayerCipher;
    use crate::crypto::SessionKey;
    use crate::data::TunnelId;
    use crate::i2np::TunnelData;

    #[test]
    fn round_trip() {
        let iv_key = SessionKey([1; 32]);
        let layer_key = SessionKey([2; 32]);

        let mut td = TunnelData {
            tid: TunnelId(1234),
            data: [0; 1024],
        };

        let cipher = LayerCipher::new(&iv_key, layer_key);

        cipher.encrypt_layer(&mut td);
        assert!(td.data[..] != [0; 1024][..]);
        cipher.decrypt_layer(&mut td);
        assert_eq!(&td.data[..], &[0; 1024][..]);

        cipher.decrypt_layer(&mut td);
        assert!(td.data[..] != [0; 1024][..]);
        cipher.encrypt_layer(&mut td);
        assert_eq!(&td.data[..], &[0; 1024][..]);
    }
}
