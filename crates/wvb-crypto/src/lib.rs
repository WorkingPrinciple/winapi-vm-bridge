//! Noise handshake and transport primitives for canonical bridge sessions.

use snow::{Builder, HandshakeState, TransportState, params::NoiseParams};
use zeroize::{Zeroize, ZeroizeOnDrop};

const XXPSK3: &str = "Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s";
const IK: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
pub const NOISE_MESSAGE_MAX: usize = u16::MAX as usize;

#[derive(Debug)]
pub enum CryptoError {
    Noise(snow::Error),
    InvalidKey,
    InvalidPsk,
    HandshakeIncomplete,
    MessageTooLarge,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for CryptoError {}

impl From<snow::Error> for CryptoError {
    fn from(value: snow::Error) -> Self {
        Self::Noise(value)
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct StaticPrivateKey([u8; 32]);

impl StaticPrivateKey {
    pub fn generate() -> Result<(Self, [u8; 32]), CryptoError> {
        let params: NoiseParams = XXPSK3.parse().map_err(CryptoError::Noise)?;
        let pair = Builder::new(params).generate_keypair()?;
        let private: [u8; 32] = pair
            .private
            .try_into()
            .map_err(|_| CryptoError::InvalidKey)?;
        let public: [u8; 32] = pair
            .public
            .try_into()
            .map_err(|_| CryptoError::InvalidKey)?;
        Ok((Self(private), public))
    }

    #[must_use]
    pub fn from_bytes(value: [u8; 32]) -> Self {
        Self(value)
    }

    fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PairingPsk([u8; 32]);

impl PairingPsk {
    #[must_use]
    pub fn from_bytes(value: [u8; 32]) -> Self {
        Self(value)
    }

    fn as_array(&self) -> &[u8; 32] {
        &self.0
    }
}

pub struct Handshake {
    state: HandshakeState,
}

impl Handshake {
    pub fn pairing_initiator(
        local_private: &StaticPrivateKey,
        psk: &PairingPsk,
    ) -> Result<Self, CryptoError> {
        let params: NoiseParams = XXPSK3.parse().map_err(CryptoError::Noise)?;
        let state = Builder::new(params)
            .local_private_key(local_private.as_slice())?
            .psk(3, psk.as_array())
            .map_err(|_| CryptoError::InvalidPsk)?
            .build_initiator()?;
        Ok(Self { state })
    }

    pub fn pairing_responder(
        local_private: &StaticPrivateKey,
        psk: &PairingPsk,
    ) -> Result<Self, CryptoError> {
        let params: NoiseParams = XXPSK3.parse().map_err(CryptoError::Noise)?;
        let state = Builder::new(params)
            .local_private_key(local_private.as_slice())?
            .psk(3, psk.as_array())
            .map_err(|_| CryptoError::InvalidPsk)?
            .build_responder()?;
        Ok(Self { state })
    }

    pub fn session_initiator(
        local_private: &StaticPrivateKey,
        remote_public: &[u8; 32],
    ) -> Result<Self, CryptoError> {
        let params: NoiseParams = IK.parse().map_err(CryptoError::Noise)?;
        let state = Builder::new(params)
            .local_private_key(local_private.as_slice())?
            .remote_public_key(remote_public)?
            .build_initiator()?;
        Ok(Self { state })
    }

    pub fn session_responder(local_private: &StaticPrivateKey) -> Result<Self, CryptoError> {
        let params: NoiseParams = IK.parse().map_err(CryptoError::Noise)?;
        let state = Builder::new(params)
            .local_private_key(local_private.as_slice())?
            .build_responder()?;
        Ok(Self { state })
    }

    pub fn write(&mut self, payload: &[u8], output: &mut [u8]) -> Result<usize, CryptoError> {
        if output.len() > NOISE_MESSAGE_MAX {
            return Err(CryptoError::MessageTooLarge);
        }
        Ok(self.state.write_message(payload, output)?)
    }

    pub fn read(&mut self, message: &[u8], output: &mut [u8]) -> Result<usize, CryptoError> {
        if message.len() > NOISE_MESSAGE_MAX {
            return Err(CryptoError::MessageTooLarge);
        }
        Ok(self.state.read_message(message, output)?)
    }

    #[must_use]
    pub fn finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    pub fn remote_static(&self) -> Result<[u8; 32], CryptoError> {
        let remote = self
            .state
            .get_remote_static()
            .ok_or(CryptoError::HandshakeIncomplete)?;
        remote.try_into().map_err(|_| CryptoError::InvalidKey)
    }

    pub fn into_transport(self) -> Result<Transport, CryptoError> {
        if !self.state.is_handshake_finished() {
            return Err(CryptoError::HandshakeIncomplete);
        }
        Ok(Transport {
            state: self.state.into_transport_mode()?,
        })
    }
}

pub struct Transport {
    state: TransportState,
}

impl Transport {
    pub fn encrypt(&mut self, plaintext: &[u8], output: &mut [u8]) -> Result<usize, CryptoError> {
        if plaintext.len().saturating_add(16) > NOISE_MESSAGE_MAX {
            return Err(CryptoError::MessageTooLarge);
        }
        Ok(self.state.write_message(plaintext, output)?)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8], output: &mut [u8]) -> Result<usize, CryptoError> {
        if ciphertext.len() > NOISE_MESSAGE_MAX {
            return Err(CryptoError::MessageTooLarge);
        }
        Ok(self.state.read_message(ciphertext, output)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(psk_a: [u8; 32], psk_b: [u8; 32]) -> Result<(Transport, Transport), CryptoError> {
        let (client_key, _) = StaticPrivateKey::generate()?;
        let (broker_key, _) = StaticPrivateKey::generate()?;
        let mut client = Handshake::pairing_initiator(&client_key, &PairingPsk::from_bytes(psk_a))?;
        let mut broker = Handshake::pairing_responder(&broker_key, &PairingPsk::from_bytes(psk_b))?;
        let mut message = [0_u8; 256];
        let mut payload = [0_u8; 256];
        let length = client.write(&[], &mut message)?;
        broker.read(&message[..length], &mut payload)?;
        let length = broker.write(&[], &mut message)?;
        client.read(&message[..length], &mut payload)?;
        let length = client.write(&[], &mut message)?;
        broker.read(&message[..length], &mut payload)?;
        Ok((client.into_transport()?, broker.into_transport()?))
    }

    #[test]
    fn pairing_and_encrypted_transport_round_trip() {
        let (mut client, mut broker) = pair([7; 32], [7; 32]).unwrap();
        let plaintext = b"canonical";
        let mut ciphertext = [0_u8; 128];
        let mut output = [0_u8; 128];
        let encrypted = client.encrypt(plaintext, &mut ciphertext).unwrap();
        let decrypted = broker
            .decrypt(&ciphertext[..encrypted], &mut output)
            .unwrap();
        assert_eq!(&output[..decrypted], plaintext);
    }

    #[test]
    fn wrong_pairing_psk_fails() {
        assert!(pair([1; 32], [2; 32]).is_err());
    }

    #[test]
    fn future_ik_session_authenticates_static_keys() {
        let (client_key, client_public) = StaticPrivateKey::generate().unwrap();
        let (broker_key, broker_public) = StaticPrivateKey::generate().unwrap();
        let mut client = Handshake::session_initiator(&client_key, &broker_public).unwrap();
        let mut broker = Handshake::session_responder(&broker_key).unwrap();
        let mut message = [0_u8; 256];
        let mut payload = [0_u8; 256];
        let length = client.write(&[], &mut message).unwrap();
        broker.read(&message[..length], &mut payload).unwrap();
        let length = broker.write(&[], &mut message).unwrap();
        client.read(&message[..length], &mut payload).unwrap();
        assert_eq!(client.remote_static().unwrap(), broker_public);
        assert_eq!(broker.remote_static().unwrap(), client_public);
        assert!(client.into_transport().is_ok());
        assert!(broker.into_transport().is_ok());
    }

    #[test]
    fn oversized_transport_plaintext_is_rejected() {
        let (mut client, _) = pair([3; 32], [3; 32]).unwrap();
        let mut output = vec![0_u8; NOISE_MESSAGE_MAX + 32];
        let input = vec![0_u8; NOISE_MESSAGE_MAX - 15];
        assert!(matches!(
            client.encrypt(&input, &mut output),
            Err(CryptoError::MessageTooLarge)
        ));
    }
}
