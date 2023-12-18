use pairing::Engine;
use sync_vm::{
    circuit_structures::byte::Byte,
    franklin_crypto::{
        bellman::{plonk::better_better_cs::cs::ConstraintSystem, SynthesisError},
        plonk::circuit::boolean::Boolean,
    },
    traits::CSAllocatable,
};

use crate::{
    gadgets::keccak160::{self, MerklePath, MerkleRoot},
    utils::new_synthesis_error,
};

use super::wormhole::WormholeMessage;

// const UPDATE_BYTES_LEN: usize = 2 + 85 + 1 + 10 * 20;
// Circuit representation of pyth `PriceUpdate`
// - https://github.com/pyth-network/pyth-crosschain/blob/178ad4cb0edff38f43d8e26f23d1d9e83448093c/pythnet/pythnet_sdk/src/wire.rs#L109-L111
#[derive(Debug, Clone)]
pub struct Update<E: Engine, const N: usize> {
    pub message: PriceFeed<E>,
    pub proof: MerklePath<E, N>,
}

impl<E: Engine, const N: usize> Update<E, N> {
    pub fn alloc_from_witness<CS: ConstraintSystem<E>>(
        cs: &mut CS,
        witness: pythnet_sdk::wire::v1::MerklePriceUpdate,
    ) -> Result<Self, SynthesisError> {
        use pythnet_sdk::messages::Message;
        let message = {
            let message: Vec<u8> = witness.message.into();
            let price_feed = pythnet_sdk::wire::from_slice::<byteorder::BE, Message>(&message)
                .map_err(new_synthesis_error)?;
            PriceFeed::alloc_from_witness(cs, price_feed)?
        };
        let proof = {
            let proof = witness.proof.to_bytes();
            if proof.len() != N * keccak160::WIDTH_HASH_BYTES {
                return Err(new_synthesis_error(format!(
                    "invalid proof length {}, expect {}",
                    proof.len(),
                    N * keccak160::WIDTH_HASH_BYTES
                )));
            }

            let merkle_paths: [[u8; keccak160::WIDTH_HASH_BYTES]; N] = proof
                .chunks_exact(keccak160::WIDTH_HASH_BYTES)
                .map(|chunk| chunk.try_into().unwrap())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();

            let merkle_paths = merkle_paths
                .into_iter()
                .map(|hash| keccak160::Hash::alloc_from_witness(cs, Some(hash)))
                .collect::<Result<Vec<_>, _>>()?
                .try_into()
                .unwrap();

            MerklePath(merkle_paths)
        };
        // let merkle_paths = MerklePath::new(merkle_paths.try_into().unwrap());
        Ok(Self { message, proof })
    }

    pub fn check<CS: ConstraintSystem<E>>(
        &self,
        cs: &mut CS,
        root: &MerkleRoot<E>,
    ) -> Result<Boolean, SynthesisError> {
        root.check(cs, &self.proof, &self.message.to_bytes())
    }
}

// Circuit representation of pyth `AccumulatorUpdate`
// - https://github.com/pyth-network/pyth-crosschain/blob/178ad4cb0edff38f43d8e26f23d1d9e83448093c/pythnet/pythnet_sdk/src/wire.rs#L60-L66
// - https://github.com/pyth-network/pyth-client-py/blob/d6571704433f044dfa6881e7b76f629f6e194482/pythclient/price_feeds.py#L710-L804
#[derive(Debug, Clone)]
pub struct AccumulatorUpdates<E: Engine, const M: usize, const N: usize> {
    pub wormhole_message: WormholeMessage<E>,
    pub updates: [Update<E, M>; N],
}

impl<E: Engine, const M: usize, const N: usize> AccumulatorUpdates<E, M, N> {
    pub fn check<CS: ConstraintSystem<E>>(&self, cs: &mut CS) -> Result<Boolean, SynthesisError> {
        let root = self.wormhole_message.merkle_root();
        let mut result = Boolean::constant(true);
        for update in self.updates.iter() {
            let check = update.check(cs, &root)?;
            result = Boolean::and(cs, &result, &check)?;
        }
        Ok(result)
    }
}

const LEN_PRICE_FEED_TYPE: usize = 1;
const LEN_FEED_ID: usize = 32;
const LEN_PRICE: usize = 8;
const LEN_CONF: usize = 8;
const LEN_EXPONENT: usize = 4;
const LEN_PUBLISH_TIME: usize = 8;
const LEN_PREV_PUBLISH_TIME: usize = 8;
const LEN_EMA_PRICE: usize = 8;
const LEN_EMA_CONF: usize = 8;
pub const LEN_PRICE_FEED: usize = LEN_PRICE_FEED_TYPE
    + LEN_FEED_ID
    + LEN_PRICE
    + LEN_CONF
    + LEN_EXPONENT
    + LEN_PUBLISH_TIME
    + LEN_PREV_PUBLISH_TIME
    + LEN_EMA_PRICE
    + LEN_EMA_CONF;
#[derive(Debug, Clone)]
pub struct PriceFeed<E: Engine> {
    pub price_feed_type: [Byte<E>; LEN_PRICE_FEED_TYPE],
    pub feed_id: [Byte<E>; LEN_FEED_ID],
    pub price: [Byte<E>; LEN_PRICE],
    pub conf: [Byte<E>; LEN_CONF],
    pub exponent: [Byte<E>; LEN_EXPONENT],
    pub publish_time: [Byte<E>; LEN_PUBLISH_TIME],
    pub prev_publish_time: [Byte<E>; LEN_PREV_PUBLISH_TIME],
    pub ema_price: [Byte<E>; LEN_EMA_PRICE],
    pub ema_conf: [Byte<E>; LEN_EMA_CONF],
}

impl<E: Engine> PriceFeed<E> {
    pub fn alloc_from_witness<CS: ConstraintSystem<E>>(
        cs: &mut CS,
        witness: pythnet_sdk::messages::Message,
    ) -> Result<Self, SynthesisError> {
        let witness = match witness {
            pythnet_sdk::messages::Message::PriceFeedMessage(p) => p,
            _ => return Err(new_synthesis_error("invalid message type")),
        };
        let price_feed_type = [Byte::<E>::alloc_from_witness(cs, Some(0u8))?];
        let feed_id = {
            let bytes = witness.feed_id;
            CSAllocatable::alloc_from_witness(cs, Some(bytes))?
        };
        let price = {
            let bytes = witness.price.to_be_bytes();
            CSAllocatable::alloc_from_witness(cs, Some(bytes))?
        };
        let conf = {
            let bytes = witness.conf.to_be_bytes();
            CSAllocatable::alloc_from_witness(cs, Some(bytes))?
        };
        let exponent = {
            let bytes = witness.exponent.to_be_bytes();
            CSAllocatable::alloc_from_witness(cs, Some(bytes))?
        };
        let publish_time = {
            let bytes = witness.publish_time.to_be_bytes();
            CSAllocatable::alloc_from_witness(cs, Some(bytes))?
        };
        let prev_publish_time = {
            let bytes = witness.prev_publish_time.to_be_bytes();
            CSAllocatable::alloc_from_witness(cs, Some(bytes))?
        };
        let ema_price = {
            let bytes = witness.ema_price.to_be_bytes();
            CSAllocatable::alloc_from_witness(cs, Some(bytes))?
        };
        let ema_conf = {
            let bytes = witness.ema_conf.to_be_bytes();
            CSAllocatable::alloc_from_witness(cs, Some(bytes))?
        };
        Ok(Self {
            price_feed_type,
            feed_id,
            price,
            conf,
            exponent,
            publish_time,
            prev_publish_time,
            ema_price,
            ema_conf,
        })
    }

    // TODO: delete
    pub fn new(bytes: [Byte<E>; LEN_PRICE_FEED]) -> Self {
        let mut offset = 0 as usize;
        let price_feed_type = bytes[offset..offset + LEN_PRICE_FEED_TYPE]
            .try_into()
            .unwrap();
        offset += LEN_PRICE_FEED_TYPE;
        let feed_id = bytes[offset..offset + LEN_FEED_ID].try_into().unwrap();
        offset += LEN_FEED_ID;
        let price = bytes[offset..offset + LEN_PRICE].try_into().unwrap();
        offset += LEN_PRICE;
        let conf = bytes[offset..offset + LEN_CONF].try_into().unwrap();
        offset += LEN_CONF;
        let exponent = bytes[offset..offset + LEN_EXPONENT].try_into().unwrap();
        offset += LEN_EXPONENT;
        let publish_time = bytes[offset..offset + LEN_PUBLISH_TIME].try_into().unwrap();
        offset += LEN_PUBLISH_TIME;
        let prev_publish_time = bytes[offset..offset + LEN_PREV_PUBLISH_TIME]
            .try_into()
            .unwrap();
        offset += LEN_PREV_PUBLISH_TIME;
        let ema_price = bytes[offset..offset + LEN_EMA_PRICE].try_into().unwrap();
        offset += LEN_EMA_PRICE;
        let ema_conf = bytes[offset..offset + LEN_EMA_CONF].try_into().unwrap();
        Self {
            price_feed_type,
            feed_id,
            price,
            conf,
            exponent,
            publish_time,
            prev_publish_time,
            ema_price,
            ema_conf,
        }
    }

    pub fn new_from_slice(bytes: &[Byte<E>]) -> Result<Self, SynthesisError> {
        let bytes = bytes.try_into().map_err(new_synthesis_error)?;
        Ok(Self::new(bytes))
    }

    // TODO: add cs as parameter
    pub fn to_bytes(&self) -> [Byte<E>; LEN_PRICE_FEED] {
        let mut bytes = [Byte::<E>::zero(); LEN_PRICE_FEED];
        let mut offset = 0 as usize;
        bytes[offset..offset + LEN_PRICE_FEED_TYPE].copy_from_slice(&self.price_feed_type);
        offset += LEN_PRICE_FEED_TYPE;
        bytes[offset..offset + LEN_FEED_ID].copy_from_slice(&self.feed_id);
        offset += LEN_FEED_ID;
        bytes[offset..offset + LEN_PRICE].copy_from_slice(&self.price);
        offset += LEN_PRICE;
        bytes[offset..offset + LEN_CONF].copy_from_slice(&self.conf);
        offset += LEN_CONF;
        bytes[offset..offset + LEN_EXPONENT].copy_from_slice(&self.exponent);
        offset += LEN_EXPONENT;
        bytes[offset..offset + LEN_PUBLISH_TIME].copy_from_slice(&self.publish_time);
        offset += LEN_PUBLISH_TIME;
        bytes[offset..offset + LEN_PREV_PUBLISH_TIME].copy_from_slice(&self.prev_publish_time);
        offset += LEN_PREV_PUBLISH_TIME;
        bytes[offset..offset + LEN_EMA_PRICE].copy_from_slice(&self.ema_price);
        offset += LEN_EMA_PRICE;
        bytes[offset..offset + LEN_EMA_CONF].copy_from_slice(&self.ema_conf);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        gadgets::keccak160,
        utils::{
            bytes_constant_from_hex_str,
            testing::{bytes_assert_eq, create_test_constraint_system},
        },
    };
    use pairing::bn256::Bn256;
    use pythnet_sdk::wire::from_slice;
    use sync_vm::franklin_crypto::{bellman::SynthesisError, plonk::circuit::boolean::Boolean};

    #[test]
    // TODO: rename
    fn tset_price_feed() -> Result<(), SynthesisError> {
        let hex_str = "00e62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b4300000352813ebdc00000000042eeb9f6fffffff800000000655ccff700000000655ccff700000356d0a75ce0000000005b0d7112";
        let bytes = bytes_constant_from_hex_str::<Bn256>(hex_str).unwrap();
        let price_feed = super::PriceFeed::new_from_slice(&bytes)?;
        {
            bytes_assert_eq(&price_feed.price_feed_type, "00");
            bytes_assert_eq(
                &price_feed.feed_id,
                "e62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43",
            );
            bytes_assert_eq(&price_feed.price, "00000352813ebdc0");
            bytes_assert_eq(&price_feed.conf, "0000000042eeb9f6");
            bytes_assert_eq(&price_feed.exponent, "fffffff8");
            bytes_assert_eq(&price_feed.publish_time, "00000000655ccff7");
            bytes_assert_eq(&price_feed.prev_publish_time, "00000000655ccff7");
            bytes_assert_eq(&price_feed.ema_price, "00000356d0a75ce0");
            bytes_assert_eq(&price_feed.ema_conf, "000000005b0d7112");
        }
        bytes_assert_eq(&price_feed.to_bytes(), hex_str);
        Ok(())
    }

    #[test]
    fn test_price_feed_alloc_from_witness() -> Result<(), SynthesisError> {
        let cs = &mut create_test_constraint_system()?;
        let hex_str = "00e62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b4300000352813ebdc00000000042eeb9f6fffffff800000000655ccff700000000655ccff700000356d0a75ce0000000005b0d7112";
        let data = hex::decode(hex_str).unwrap();
        let price_feed = {
            let p = from_slice::<byteorder::BE, pythnet_sdk::messages::Message>(&data).unwrap();
            super::PriceFeed::alloc_from_witness(cs, p)?
        };
        let bytes = price_feed.to_bytes();
        bytes_assert_eq(&bytes, hex_str);
        Ok(())
    }

    #[test]
    fn test_update_alloc_from_witness() -> Result<(), SynthesisError> {
        let cs = &mut create_test_constraint_system()?;
        let hex_str = "005500e62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b4300000352813ebdc00000000042eeb9f6fffffff800000000655ccff700000000655ccff700000356d0a75ce0000000005b0d71120ad97a31be8c09393bfbcd8cc36a4c486949eaab2bbe6e19294367c1689b7521ba31bcd504b01db4a0c74a56d137795aefe2df9137c1a7d82af648cb8aeece3482a0d6194ec36d2dab3b491296f5d9947b5b87bac5e58c2760c4677e0bb994618fb5c5d853fecc55351cd68a5029d4bc2b6f9ab5c23e7b9462af514a8475ffa181ea1216d2a8f3447464f8685f9b935ce5124e872d4a8b9ea16f9487952dff1ce6a2ef5e724d4da1e5f2bf897e52ac6a31ac60868776163f6ab8f1d74214184da7952bc731ff51f01f";
        let data = hex::decode(hex_str).unwrap();
        let update =
            from_slice::<byteorder::BE, pythnet_sdk::wire::v1::MerklePriceUpdate>(&data).unwrap();
        let update = super::Update::<Bn256, 10>::alloc_from_witness(cs, update)?;
        {
            let root = {
                use sync_vm::traits::CSAllocatable;

                let hash = hex::decode("095bb7e5fa374ea08603a6698123d99101547a50")
                    .unwrap()
                    .try_into()
                    .unwrap();
                let hash = keccak160::Hash::alloc_from_witness(cs, Some(hash))?;
                keccak160::MerkleRoot::new(hash)
            };
            let check = update.check(cs, &root)?;
            Boolean::enforce_equal(cs, &check, &Boolean::constant(true))?;
        }
        Ok(())
    }
}
