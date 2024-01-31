use advanced_circuit_component::franklin_crypto::bellman::pairing::Engine;
use advanced_circuit_component::{
    circuit_structures::byte::{Byte, IntoBytes as _},
    franklin_crypto::{
        bellman::{plonk::better_better_cs::cs::ConstraintSystem, SynthesisError},
        plonk::circuit::boolean::Boolean,
    },
    traits::CSAllocatable,
    vm::{
        partitioner::{smart_and, smart_or},
        primitives::uint256::UInt256,
    },
};

use crate::{
    gadgets::{
        ecdsa::Signature,
        ethereum::Address,
        keccak160::{self, MerkleRoot},
    },
    utils::new_synthesis_error,
};

/// Circuit (partial) representation of wormhole [`VAA<P>`](https://github.com/wormhole-foundation/wormhole/blob/bfd4ba40ef2d213ad69bac638c72009ba4a07878/sdk/rust/core/src/vaa.rs#L80-L100)
///
/// Visit [VAAs documentation](https://docs.wormhole.com/wormhole/explore-wormhole/vaa) for more.
#[derive(Debug, Clone)]
pub struct Vaa<E: Engine, const N: usize> {
    pub signatures: [Signature<E>; N],
    pub body: VaaBody<E>,
}

impl<E: Engine, const N: usize> Vaa<E, N> {
    /// Create VAA from witness. Size of signatures in witness must be at least N, otherwise it
    /// returns error.
    pub fn from_vaa_witness<CS: ConstraintSystem<E>>(
        cs: &mut CS,
        message: wormhole_sdk::Vaa<&serde_wormhole::RawMessage>,
    ) -> Result<Self, SynthesisError> {
        let (header, body): (wormhole_sdk::vaa::Header, wormhole_sdk::vaa::Body<_>) =
            message.into();
        let body = VaaBody::from_vaa_body_witness(cs, body)?;
        if header.signatures.len() < N {
            return Err(new_synthesis_error(format!(
                "Only have {} signature. expect {} at least",
                header.signatures.len(),
                N
            )));
        }

        let signatures = (0..N)
            .map(|i| {
                let signature = header.signatures[i].signature;
                Signature::from_bytes_witness(cs, &signature)
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            signatures: signatures.try_into().unwrap(),
            body,
        })
    }

    pub fn merkle_root(&self) -> &MerkleRoot<E> {
        &self.body.payload.root
    }

    pub fn signatures(&self) -> &[Signature<E>; N] {
        &self.signatures
    }

    /// Recover public keys from VAA signatures.
    pub fn ecrecover<CS: ConstraintSystem<E>>(
        &self,
        cs: &mut CS,
    ) -> Result<[crate::gadgets::ecdsa::EcRecoverRes<E>; N], SynthesisError> {
        let msg_hash = {
            let bytes = self.body.to_bytes();
            use crate::gadgets::keccak256::digest;
            let hash1 = digest(cs, &bytes)?;
            let hash2 = digest(cs, &hash1)?;
            UInt256::from_be_bytes_fixed(cs, &hash2)?
        };

        let mut pubkeys = [Default::default(); N];
        for (i, pubkey) in pubkeys.iter_mut().enumerate().take(self.signatures.len()) {
            *pubkey = self.signatures[i].ecrecover(cs, &msg_hash)?;
        }
        Ok(pubkeys)
    }

    /// Check if all VAA sigantures are signed by one from guardian set.
    /// There is not quorum check and you should make sure all signatures are valid.
    pub fn check_by_pubkey<CS: ConstraintSystem<E>>(
        &self,
        cs: &mut CS,
        guardian_set: &[(UInt256<E>, UInt256<E>)],
    ) -> Result<Boolean, SynthesisError> {
        if guardian_set.is_empty() {
            return Ok(Boolean::Constant(false));
        }
        let recovered = self.ecrecover(cs)?;
        let mut is_ok = vec![];
        for (successful, (x, y)) in recovered {
            let mut is_matched = vec![];
            for pubkey in guardian_set {
                let x_is_equal = UInt256::equals(cs, &x, &pubkey.0)?;
                let y_is_equal = UInt256::equals(cs, &y, &pubkey.1)?;
                let is_equal = Boolean::and(cs, &x_is_equal, &y_is_equal)?;
                is_matched.push(is_equal);
            }
            let is_matched = smart_or(cs, &is_matched)?;
            is_ok.push(smart_and(cs, &[successful, is_matched])?)
        }
        let is_ok = smart_and(cs, &is_ok)?;
        Ok(is_ok)
    }

    pub fn check_by_address<CS: ConstraintSystem<E>>(
        &self,
        cs: &mut CS,
        guardian_set: &[Address<E>],
    ) -> Result<Boolean, SynthesisError> {
        if guardian_set.is_empty() {
            return Ok(Boolean::Constant(false));
        }
        let recovered = self.ecrecover(cs)?;
        // Add a true bool to avoid panic if no signatures need to check
        let mut is_ok = vec![Boolean::constant(true)];
        let mut guardian_used = vec![];
        for _ in 0..guardian_set.len() {
            guardian_used.push(Boolean::alloc_from_witness(cs, Some(false))?);
        }
        for (successful, (x, y)) in recovered {
            let (x, y) = (
                x.into_be_bytes(cs)?.try_into().unwrap(),
                y.into_be_bytes(cs)?.try_into().unwrap(),
            );
            let address = Address::from_pubkey(cs, &x, &y)?;
            let mut is_matched = vec![];
            for (i, guardian) in guardian_set.iter().enumerate() {
                // Make sure we use each guardian only once.
                let guardian = guardian.mask(cs, &guardian_used[i].not())?;
                let is_equal = guardian.equals(cs, &address)?;
                guardian_used[i] = Boolean::or(cs, &guardian_used[i], &is_equal)?;
                is_matched.push(is_equal);
            }
            let is_matched = smart_or(cs, &is_matched)?;
            is_ok.push(smart_and(cs, &[successful, is_matched])?)
        }
        let is_ok = smart_and(cs, &is_ok)?;
        Ok(is_ok)
    }
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
/// Circuit representation of body in wormhole VAA [`Body<P>`](https://github.com/wormhole-foundation/wormhole/blob/bfd4ba40ef2d213ad69bac638c72009ba4a07878/sdk/rust/core/src/vaa.rs#L110-L121).
///
/// Visit [VAAs documentation](https://docs.wormhole.com/wormhole/explore-wormhole/vaa#body) for more.
pub struct VaaBody<E: Engine> {
    pub timestamp: [Byte<E>; LEN_WORMHOLE_BODY_TIMESTAMP],
    pub nonce: [Byte<E>; LEN_WORMHOLE_BODY_NONCE],
    pub emitter_chain: [Byte<E>; LEN_WORMHOLE_BODY_EMITTER_CHAIN],
    pub emitter_address: [Byte<E>; LEN_WORMHOLE_BODY_EMITTER_ADDRESS],
    pub sequence: [Byte<E>; LEN_WORMHOLE_BODY_SEQUENCE],
    pub consistency_level: [Byte<E>; LEN_WORMHOLE_BODY_CONSISTENCY_LEVEL],
    pub payload: VaaPayload<E>,
}

impl<E: Engine> VaaBody<E> {
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

    pub fn from_vaa_body_witness<CS: ConstraintSystem<E>>(
        cs: &mut CS,
        witness: wormhole_sdk::vaa::Body<&serde_wormhole::RawMessage>,
    ) -> Result<Self, SynthesisError> {
        let timestamp = {
            let bytes = witness.timestamp.to_be_bytes();
            CSAllocatable::alloc_from_witness(cs, Some(bytes))?
        };
        let nonce = {
            let bytes = witness.nonce.to_be_bytes();
            CSAllocatable::alloc_from_witness(cs, Some(bytes))?
        };
        let emitter_chain = {
            let bytes = serde_wormhole::to_vec(&witness.emitter_chain)
                .unwrap()
                .try_into()
                .unwrap();
            CSAllocatable::alloc_from_witness(cs, Some(bytes))?
        };
        let emitter_address = {
            let bytes = serde_wormhole::to_vec(&witness.emitter_address)
                .unwrap()
                .try_into()
                .unwrap();
            CSAllocatable::alloc_from_witness(cs, Some(bytes))?
        };
        let sequence = {
            let bytes = witness.sequence.to_be_bytes();
            CSAllocatable::alloc_from_witness(cs, Some(bytes))?
        };
        let consistency_level = {
            let bytes = witness.consistency_level.to_be_bytes();
            CSAllocatable::alloc_from_witness(cs, Some(bytes))?
        };
        let payload = {
            let payload =
                pythnet_sdk::wire::v1::WormholeMessage::try_from_bytes(witness.payload.as_ref())
                    .map_err(new_synthesis_error)?;
            VaaPayload::from_wormhole_message_witness(cs, payload)?
        };
        Ok(Self {
            timestamp,
            nonce,
            emitter_chain,
            emitter_address,
            sequence,
            consistency_level,
            payload,
        })
    }
}

const LEN_MAGIC: usize = 4;
const LEN_PAYLOAD_TYPE: usize = 1;
const LEN_SLOT: usize = 8;
const LEN_RING_SIZE: usize = 4;
const LEN_ROOT: usize = keccak160::WIDTH_HASH_BYTES;
const LEN_MESSAGE: usize = LEN_MAGIC + LEN_PAYLOAD_TYPE + LEN_SLOT + LEN_RING_SIZE + LEN_ROOT;
const PAYLOAD_TYPE: u8 = 0; // Fixed payload type for now.
/// Representation of pyth-defined wormhole payload [`WormholeMessage`](https://github.com/pyth-network/pyth-crosschain/blob/1d82f92d80598e689f4130983d06b12412b83427/pythnet/pythnet_sdk/src/wire.rs#L108-L112).
#[derive(Debug, Clone)]
pub struct VaaPayload<E: Engine> {
    pub magic: [Byte<E>; LEN_MAGIC],
    pub payload_type: [Byte<E>; LEN_PAYLOAD_TYPE],
    pub slot: [Byte<E>; LEN_SLOT],
    pub ring_size: [Byte<E>; LEN_RING_SIZE],
    pub root: MerkleRoot<E>,
}

impl<E: Engine> VaaPayload<E> {
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
        bytes[offset..offset + LEN_ROOT].copy_from_slice(&self.root.inner());
        bytes
    }

    pub fn from_wormhole_message_witness<CS: ConstraintSystem<E>>(
        cs: &mut CS,
        witness: pythnet_sdk::wire::v1::WormholeMessage,
    ) -> Result<Self, SynthesisError> {
        let magic = CSAllocatable::alloc_from_witness(cs, Some(witness.magic))?;
        let payload_type = CSAllocatable::alloc_from_witness(cs, Some([PAYLOAD_TYPE]))?;
        let pythnet_sdk::wire::v1::WormholePayload::Merkle(payload) = witness.payload;
        let slot = {
            let bytes = payload.slot.to_be_bytes();
            CSAllocatable::alloc_from_witness(cs, Some(bytes))?
        };
        let ring_size = {
            let bytes = payload.ring_size.to_be_bytes();
            CSAllocatable::alloc_from_witness(cs, Some(bytes))?
        };
        let root = {
            let root = CSAllocatable::alloc_from_witness(cs, Some(payload.root))?;
            MerkleRoot::new(root)
        };
        Ok(Self {
            magic,
            payload_type,
            slot,
            ring_size,
            root,
        })
    }
}

#[cfg(test)]
mod tests {
    use advanced_circuit_component::franklin_crypto::bellman::pairing::Engine;
    use advanced_circuit_component::{
        franklin_crypto::{
            bellman::{plonk::better_better_cs::cs::ConstraintSystem, SynthesisError},
            plonk::circuit::boolean::Boolean,
        },
        vm::primitives::uint256::UInt256,
    };

    use crate::utils::{
        new_synthesis_error,
        testing::{bytes_assert_eq, create_test_constraint_system},
        uint256_from_bytes_witness,
    };

    #[test]
    fn test_wormhole_payload() -> Result<(), SynthesisError> {
        let cs = &mut create_test_constraint_system()?;
        let hex_str = "415557560000000000069b993c00002710095bb7e5fa374ea08603a6698123d99101547a50";
        let data = hex::decode(hex_str).unwrap();
        let payload = pythnet_sdk::wire::v1::WormholeMessage::try_from_bytes(&data).unwrap();
        let payload = super::VaaPayload::<_>::from_wormhole_message_witness(cs, payload)?;
        bytes_assert_eq(&payload.to_bytes(), hex_str);
        Ok(())
    }

    #[test]
    fn test_wormhole_body() -> Result<(), SynthesisError> {
        let cs = &mut create_test_constraint_system()?;
        let data = hex::decode(get_vaa()).unwrap();
        let vaa: wormhole_sdk::Vaa<&serde_wormhole::RawMessage> =
            serde_wormhole::from_slice(&data).unwrap();
        let (_, body): (_, wormhole_sdk::vaa::Body<_>) = vaa.into();
        let expected = hex::encode(serde_wormhole::to_vec(&body).unwrap());
        let body = super::VaaBody::<_>::from_vaa_body_witness(cs, body)?;
        bytes_assert_eq(&body.to_bytes(), expected);
        Ok(())
    }

    #[test]
    fn test_vaa() -> Result<(), SynthesisError> {
        let cs = &mut create_test_constraint_system()?;
        let data = hex::decode(get_vaa()).unwrap();
        let vaa: wormhole_sdk::Vaa<&serde_wormhole::RawMessage> =
            serde_wormhole::from_slice(&data).unwrap();
        // We can safely create Vaa with signatures less than len of witness VAA.
        assert_eq!(vaa.signatures.len(), 13);
        let vaa = super::Vaa::<_, 1>::from_vaa_witness(cs, vaa.clone())?;

        let guardian_set = {
            let pubkeys = [
            "2a953a2e8b1052eb70c1d7b556b087deed598b55608396686c1c811b9796c763078687ce10459f4f25fb7a0fbf8727bb0fb51e00820e93a123f652ee843cf08d",
        ];
            pubkeys
                .iter()
                .map(|pk| uint256_pubkey(cs, pk))
                .collect::<Result<Vec<_>, _>>()?
        };

        let valid = vaa.check_by_pubkey(cs, &guardian_set)?;
        Boolean::enforce_equal(cs, &valid, &Boolean::Constant(true))?;
        Ok(())
    }

    fn uint256_pubkey<E: Engine, CS: ConstraintSystem<E>>(
        cs: &mut CS,
        hex_str: &str,
    ) -> Result<(UInt256<E>, UInt256<E>), SynthesisError> {
        let data = hex::decode(hex_str).map_err(new_synthesis_error)?;
        if data.len() != 64 {
            return Err(new_synthesis_error(format!(
                "hex string must be 64 characters long, got {}",
                hex_str.len()
            )));
        }
        let x = uint256_from_bytes_witness(cs, &data[0..32])?;
        let y = uint256_from_bytes_witness(cs, &data[32..])?;
        Ok((x, y))
    }

    fn get_vaa() -> &'static str {
        "01000000030d00d5df1d274a402c5eb4c8b60254f1d1df67c64c6afddd75ed03562aac6d4ad0714bd0874f0837683bec3357999a4c2d922f79e908c39a5a6ff4ec6e21a78956fa00021e32f66495cb657049f04b251629811395d082d4aecee8a95e447e83372a4e9443a647f44880f3da72d58dfc0f9fa963e4aac0c283342d9a91c4e19d3ca62a5b0103381bfdf0853bbf0f7b4cb4d65851ac7f60dcc9ba3d8442c95de61410cbf09ef279454fa725fd2e90697f55e065005ad64e6696c009fd1767b7bf9b79738399bf00068260c97865c386a3496aa56da2327159998ab1db26ae79010685f75518d4eecb67cda0cda4408a636301d0d376f3ff71db66f088e24d871bf8f9d75f901b84e8010743b8b7f7b4d53e5499bc0d2548a952cb2b6559da1a0583d3128d930926c6cf281ff58828c54cc9e39c774b70fb5ab7ab400eaa6356bc06700b2f744c6a13fd06010859f92b8bd6fa6cb257d5a41327b48c2ac880773eda6617f8511a8003a56fff15502b2b90f65cbe16ddfda2324e3d0b4039fba3332cde2adf48f01e46e8717839000a2fcf534a53c3e53addf02dea50a6e87b20f41922708a38768af6ad48dc53ca0f65844530c842f2746ecef4a950843e2adfdd1f8765e3a172e346a793fe136b90010bf3022b0f4927b6b701a84e949da4cfacbc8cc2e72037516c1ba12ef7a354e77c454822878d7d948e50c0e7118cfca2a4d5a33810e7c5cf63a47a0115cb3c5f98000c06c01308e45e4d95711e735ef2ef9e5eddeaf1e0a52faf28e0e9cb2b37acde794557d6ce463ac7b9c16f753ddd142f5716c64bfe3c9c01960f07d46cafd7157e010d5cd199cddb07c62c95eb3d199a324e79392562af5568a33842e23c1a0f2550a1010f6a4af293d651e13acb8a5f1967da722df8422ee871731ca0d9e0a908fc7f010ecc18446ff3bf2a129401967556df7de3bbfcc2c37d4441cde11d71b86a8128aa22e2154e4943570aed1d2aaa747ddc10729702688b70751a9d9c411b9e0271da0010922dd9890ea99eb32ffb3fe2fcda2258b875147601af4bad528edf70a33f382b79b4ef1515a7c5aa60af16a75c555d714b4ce7b31275d4b4eb427089849ff0920012997ca65ec7fcf0418fd036ddead5743206a7a350fd44602759a4bba2acfc949924244db3d12d76885c162b988135e642c1d6c27aa4ba504668c7932d37ead91b00655ccff800000000001ae101faedac5851e32b9b23b5f9411a8c2bac4aae3ed4dd7b811dd1a72ea4aa71000000000195faa401415557560000000000069b993c00002710095bb7e5fa374ea08603a6698123d99101547a50"
    }
}
