use pairing::Engine;
use sync_vm::{
    circuit_structures::byte::Byte,
    franklin_crypto::{
        bellman::{plonk::better_better_cs::cs::ConstraintSystem, SynthesisError},
        plonk::circuit::boolean::Boolean,
    },
};

use crate::{
    gadgets::keccak160::{MerklePath, MerkleRoot},
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
    pub fn new(message: PriceFeed<E>, proof: MerklePath<E, N>) -> Self {
        Self { message, proof }
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
        let root = MerkleRoot::new(self.wormhole_message.body.payload.root.clone());
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
    use crate::utils::{bytes_constant_from_hex_str, testing::bytes_assert_eq};
    use pairing::bn256::Bn256;
    use sync_vm::franklin_crypto::bellman::SynthesisError;

    #[test]
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
}
