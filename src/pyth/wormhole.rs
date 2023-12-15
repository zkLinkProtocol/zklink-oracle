use pairing::Engine;
use sync_vm::{circuit_structures::byte::Byte, franklin_crypto::bellman::SynthesisError};

use crate::{
    params::{LEN_MERKLE_TREE_HASH, NUM_WORMHOLE_SIGNATURES},
    utils::new_synthesis_error,
};

// Circuit representation of [`wormhole vaa`](https://docs.wormhole.com/wormhole/explore-wormhole/vaa)
// We only put part of the VAA fields here.
//
// Representation of wormhole VAA. We only put parts of VAA fields here.
// - https://docs.wormhole.com/wormhole/explore-wormhole/vaa
// - https://github.com/wormhole-foundation/wormhole/blob/bfd4ba40ef2d213ad69bac638c72009ba4a07878/sdk/rust/core/src/vaa.rs#L84-L100
#[derive(Debug, Clone)]
pub struct WormholeMessage<E: Engine> {
    pub signatures: [Byte<E>; NUM_WORMHOLE_SIGNATURES],
    pub body: WormholeBody<E>,
}

const LEN_WORMHOLE_BODY_TIMESTAMP: usize = 4;
const LEN_WORMHOLE_BODY_NONCE: usize = 4;
const LEN_WORMHOLE_BODY_EMITTER_CHAIN: usize = 2;
const LEN_WORMHOLE_BODY_EMITTER_ADDRESS: usize = 32;
const LEN_WORMHOLE_BODY_SEQUENCE: usize = 8;
const LEN_WORMHOLE_BODY_CONSISTENCY_LEVEL: usize = 1;
const LEN_WORMHOLE_BODY: usize = LEN_WORMHOLE_BODY_TIMESTAMP
    + LEN_WORMHOLE_BODY_NONCE
    + LEN_WORMHOLE_BODY_EMITTER_CHAIN
    + LEN_WORMHOLE_BODY_EMITTER_ADDRESS
    + LEN_WORMHOLE_BODY_SEQUENCE
    + LEN_WORMHOLE_BODY_CONSISTENCY_LEVEL
    + LEN_MESSAGE;
#[derive(Debug, Clone)]
pub struct WormholeBody<E: Engine> {
    pub timestamp: [Byte<E>; LEN_WORMHOLE_BODY_TIMESTAMP],
    pub nonce: [Byte<E>; LEN_WORMHOLE_BODY_NONCE],
    pub emitter_chain: [Byte<E>; LEN_WORMHOLE_BODY_EMITTER_CHAIN],
    pub emitter_address: [Byte<E>; LEN_WORMHOLE_BODY_EMITTER_ADDRESS],
    pub sequence: [Byte<E>; LEN_WORMHOLE_BODY_SEQUENCE],
    pub consistency_level: [Byte<E>; LEN_WORMHOLE_BODY_CONSISTENCY_LEVEL],
    pub payload: Message<E>,
}

// Circuit representation of body in wormhole VAA.
// - https://docs.wormhole.com/wormhole/explore-wormhole/vaa#body
// - https://github.com/wormhole-foundation/wormhole/blob/bfd4ba40ef2d213ad69bac638c72009ba4a07878/sdk/rust/core/src/vaa.rs#L112-L121
impl<E: Engine> WormholeBody<E> {
    pub fn new(bytes: [Byte<E>; LEN_WORMHOLE_BODY]) -> Self {
        let mut offset = 0;
        let timestamp = bytes[offset..offset + LEN_WORMHOLE_BODY_TIMESTAMP]
            .try_into()
            .unwrap();
        offset += LEN_WORMHOLE_BODY_TIMESTAMP;
        let nonce = bytes[offset..offset + LEN_WORMHOLE_BODY_NONCE]
            .try_into()
            .unwrap();
        offset += LEN_WORMHOLE_BODY_NONCE;
        let emitter_chain = bytes[offset..offset + LEN_WORMHOLE_BODY_EMITTER_CHAIN]
            .try_into()
            .unwrap();
        offset += LEN_WORMHOLE_BODY_EMITTER_CHAIN;
        let emitter_address = bytes[offset..offset + LEN_WORMHOLE_BODY_EMITTER_ADDRESS]
            .try_into()
            .unwrap();
        offset += LEN_WORMHOLE_BODY_EMITTER_ADDRESS;
        let sequence = bytes[offset..offset + LEN_WORMHOLE_BODY_SEQUENCE]
            .try_into()
            .unwrap();
        offset += LEN_WORMHOLE_BODY_SEQUENCE;
        let consistency_level = bytes[offset..offset + LEN_WORMHOLE_BODY_CONSISTENCY_LEVEL]
            .try_into()
            .unwrap();
        offset += LEN_WORMHOLE_BODY_CONSISTENCY_LEVEL;
        let payload = Message::new(bytes[offset..offset + LEN_MESSAGE].try_into().unwrap());
        Self {
            timestamp,
            nonce,
            emitter_chain,
            emitter_address,
            sequence,
            consistency_level,
            payload,
        }
    }

    pub fn new_from_slice(bytes: &[Byte<E>]) -> Result<Self, SynthesisError> {
        if bytes.len() != LEN_WORMHOLE_BODY {
            return Err(new_synthesis_error(format!(
                "invalid bytes length {}, expect {}",
                bytes.len(),
                LEN_MESSAGE
            )));
        }
        Ok(Self::new(bytes.try_into().unwrap()))
    }

    pub fn to_bytes(&self) -> [Byte<E>; LEN_WORMHOLE_BODY] {
        let mut bytes = [Byte::<E>::zero(); LEN_WORMHOLE_BODY];
        let mut offset = 0;
        bytes[offset..offset + LEN_WORMHOLE_BODY_TIMESTAMP].copy_from_slice(&self.timestamp);
        offset += LEN_WORMHOLE_BODY_TIMESTAMP;
        bytes[offset..offset + LEN_WORMHOLE_BODY_NONCE].copy_from_slice(&self.nonce);
        offset += LEN_WORMHOLE_BODY_NONCE;
        bytes[offset..offset + LEN_WORMHOLE_BODY_EMITTER_CHAIN]
            .copy_from_slice(&self.emitter_chain);
        offset += LEN_WORMHOLE_BODY_EMITTER_CHAIN;
        bytes[offset..offset + LEN_WORMHOLE_BODY_EMITTER_ADDRESS]
            .copy_from_slice(&self.emitter_address);
        offset += LEN_WORMHOLE_BODY_EMITTER_ADDRESS;
        bytes[offset..offset + LEN_WORMHOLE_BODY_SEQUENCE].copy_from_slice(&self.sequence);
        offset += LEN_WORMHOLE_BODY_SEQUENCE;
        bytes[offset..offset + LEN_WORMHOLE_BODY_CONSISTENCY_LEVEL]
            .copy_from_slice(&self.consistency_level);
        offset += LEN_WORMHOLE_BODY_CONSISTENCY_LEVEL;
        bytes[offset..offset + LEN_MESSAGE].copy_from_slice(&self.payload.to_bytes());
        bytes
    }
}

const LEN_MAGIC: usize = 4;
const LEN_PAYLOAD_TYPE: usize = 1;
const LEN_SLOT: usize = 8;
const LEN_RING_SIZE: usize = 4;
const LEN_ROOT: usize = LEN_MERKLE_TREE_HASH;
const LEN_MESSAGE: usize = LEN_MAGIC + LEN_PAYLOAD_TYPE + LEN_SLOT + LEN_RING_SIZE + LEN_ROOT;
// Representation of pyth-defined wormhole payload
// - https://github.com/pyth-network/pyth-crosschain/blob/1d82f92d80598e689f4130983d06b12412b83427/pythnet/pythnet_sdk/src/wire.rs#L109-L112
#[derive(Debug, Clone)]
pub struct Message<E: Engine> {
    pub magic: [Byte<E>; LEN_MAGIC],
    pub payload_type: [Byte<E>; LEN_PAYLOAD_TYPE],
    pub slot: [Byte<E>; LEN_SLOT],
    pub ring_size: [Byte<E>; LEN_RING_SIZE],
    pub root: [Byte<E>; LEN_ROOT],
}

impl<E: Engine> Message<E> {
    pub fn new(bytes: [Byte<E>; LEN_MESSAGE]) -> Self {
        let mut offset = 0;
        let magic = bytes[offset..offset + LEN_MAGIC].try_into().unwrap();
        offset += LEN_MAGIC;
        let payload_type = bytes[offset..offset + LEN_PAYLOAD_TYPE].try_into().unwrap();
        offset += LEN_PAYLOAD_TYPE;
        let slot = bytes[offset..offset + LEN_SLOT].try_into().unwrap();
        offset += LEN_SLOT;
        let ring_size = bytes[offset..offset + LEN_RING_SIZE].try_into().unwrap();
        offset += LEN_RING_SIZE;
        let root = bytes[offset..offset + LEN_ROOT].try_into().unwrap();
        Self {
            magic,
            payload_type,
            slot,
            ring_size,
            root,
        }
    }
    pub fn new_from_slice(bytes: &[Byte<E>]) -> Result<Self, SynthesisError> {
        if bytes.len() != LEN_MESSAGE {
            return Err(new_synthesis_error(format!(
                "invalid bytes length {}, expect {}",
                bytes.len(),
                LEN_MESSAGE
            )));
        }
        Ok(Self::new(bytes.try_into().unwrap()))
    }

    pub fn to_bytes(&self) -> [Byte<E>; LEN_MESSAGE] {
        let mut bytes = [Byte::<E>::zero(); LEN_MESSAGE];
        let mut offset = 0;
        bytes[offset..offset + LEN_MAGIC].copy_from_slice(&self.magic);
        offset += LEN_MAGIC;
        bytes[offset..offset + LEN_PAYLOAD_TYPE].copy_from_slice(&self.payload_type);
        offset += LEN_PAYLOAD_TYPE;
        bytes[offset..offset + LEN_SLOT].copy_from_slice(&self.slot);
        offset += LEN_SLOT;
        bytes[offset..offset + LEN_RING_SIZE].copy_from_slice(&self.ring_size);
        offset += LEN_RING_SIZE;
        bytes[offset..offset + LEN_ROOT].copy_from_slice(&self.root);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use pairing::bn256::Bn256;
    use sync_vm::franklin_crypto::bellman::SynthesisError;

    use crate::utils::{bytes_assert_eq, hex_to_bytes_constant};

    #[test]
    fn test_wormhole_payload() -> Result<(), SynthesisError> {
        let hex_str = "415557560000000000069b993c00002710095bb7e5fa374ea08603a6698123d99101547a50";
        let bytes = hex_to_bytes_constant::<Bn256>(hex_str)?;
        let payload = super::Message::new_from_slice(&bytes)?;
        {
            bytes_assert_eq(&payload.magic, "41555756");
            bytes_assert_eq(&payload.payload_type, "00");
            bytes_assert_eq(&payload.slot, "00000000069b993c");
            bytes_assert_eq(&payload.ring_size, "00002710");
            bytes_assert_eq(&payload.root, "095bb7e5fa374ea08603a6698123d99101547a50");
        }

        bytes_assert_eq(&payload.to_bytes(), hex_str);
        Ok(())
    }

    #[test]
    fn test_wormhole_body() -> Result<(), SynthesisError> {
        let hex_str = "655ccff800000000001ae101faedac5851e32b9b23b5f9411a8c2bac4aae3ed4dd7b811dd1a72ea4aa71000000000195faa401415557560000000000069b993c00002710095bb7e5fa374ea08603a6698123d99101547a50";
        let bytes = hex_to_bytes_constant::<Bn256>(hex_str)?;
        let body = super::WormholeBody::new_from_slice(&bytes)?;
        {
            bytes_assert_eq(&body.timestamp, "655ccff8");
            bytes_assert_eq(&body.nonce, "00000000");
            bytes_assert_eq(&body.emitter_chain, "001a");
            bytes_assert_eq(
                &body.emitter_address,
                "e101faedac5851e32b9b23b5f9411a8c2bac4aae3ed4dd7b811dd1a72ea4aa71",
            );
            bytes_assert_eq(&body.sequence, "000000000195faa4");
            bytes_assert_eq(&body.consistency_level, "01");
            bytes_assert_eq(
                &body.payload.to_bytes(),
                "415557560000000000069b993c00002710095bb7e5fa374ea08603a6698123d99101547a50",
            );
        }

        bytes_assert_eq(&body.to_bytes(), hex_str);
        Ok(())
    }
}
