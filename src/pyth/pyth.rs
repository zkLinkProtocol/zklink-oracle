use std::{array::TryFromSliceError, error::Error};

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

const UPDATE_BYTES_LEN: usize = 2 + 85 + 2 + 10 * 20;
const LEN_UPDATE2: usize = 2 + LEN_PRICE_FEED + 1 + 10 * 20;

// Circuit representation of pyth `PriceUpdate`
// - https://github.com/pyth-network/pyth-crosschain/blob/178ad4cb0edff38f43d8e26f23d1d9e83448093c/pythnet/pythnet_sdk/src/wire.rs#L109-L111
#[derive(Debug, Clone)]
struct Update2<E: Engine, const N: usize> {
    pub message: PriceFeed<E>,
    pub proof: MerklePath<E, N>,
}
impl<E: Engine, const N: usize> Update2<E, N> {
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

// #[derive(Debug, Clone)]
// struct Update<E: Engine> {
//     pub message_len: [Byte<E>; 2],
//     pub message: Vec<Byte<E>>,
//     pub proof_size: Byte<E>,
//     pub proof: MerklePath<E>,
// }

// impl<E: Engine> Update<E> {
//     pub fn new(bytes: &[Byte<E>]) -> Result<Self, SynthesisError> {
//         let (message_len, message, proof_size, proof) = Self::decompose(bytes)?;
//         Ok(Self {
//             message_len,
//             message,
//             proof_size,
//             proof,
//         })
//     }

//     pub fn decompose(
//         bytes: &[Byte<E>],
//     ) -> Result<([Byte<E>; 2], Vec<Byte<E>>, Byte<E>, MerklePath<E>), SynthesisError> {
//         let len = bytes.len();
//         if len < 2 {
//             return Err(new_synthesis_error(format!("bytes length {} < 2", len)));
//         }

//         let message_len = ((bytes[0].get_byte_value().unwrap() as usize) << 8)
//             + (bytes[1].get_byte_value().unwrap() as usize);
//         let proof_offset = 2 + message_len;
//         if len < proof_offset + 1 {
//             return Err(new_synthesis_error(format!(
//                 "bytes length {} < {}",
//                 len,
//                 proof_offset + 1
//             )));
//         }
//         let proof_size = bytes[proof_offset].get_byte_value().unwrap() as usize;
//         if len != proof_offset + 1 + proof_size * 20 {
//             return Err(new_synthesis_error(format! {
//                 "bytes length {} != {}", len, proof_offset + 1 + proof_size * 20
//             }));
//         }
//         let message_len = bytes[0..2].to_vec().try_into().unwrap();
//         let message = bytes[2..proof_offset].to_vec();
//         let proof_size = bytes[proof_offset..proof_offset + 1][0];
//         let proof = {
//             let proof = bytes[proof_offset + 1..].to_vec();
//             let proof = proof
//                 .chunks(keccak160::HASH_BYTE_WIDTH)
//                 .into_iter()
//                 .map(|chunk| keccak160::hash_from_slice(&chunk))
//                 .collect::<Result<Vec<_>, _>>()?;
//             MerklePath::new(proof)
//         };
//         Ok((message_len, message, proof_size, proof))
//     }
// }

#[derive(Debug, Clone)]
// Circuit representation of pyth `AccumulatorUpdate`
// - https://github.com/pyth-network/pyth-crosschain/blob/178ad4cb0edff38f43d8e26f23d1d9e83448093c/pythnet/pythnet_sdk/src/wire.rs#L60-L66
// - https://github.com/pyth-network/pyth-client-py/blob/d6571704433f044dfa6881e7b76f629f6e194482/pythclient/price_feeds.py#L710-L804
struct AccumulatorUpdates<E: Engine> {
    pub magic: [Byte<E>; 4],
    pub majoc_version: Byte<E>,
    pub minor_version: Byte<E>,
    pub trailing_header_len: Byte<E>,
    pub trailing_header: Vec<Byte<E>>,
    pub update_type: Byte<E>,
    pub vaa_length: [Byte<E>; 2],
    pub vaa: Vec<Byte<E>>,
    pub num_updates: Byte<E>,
    // pub updates: Vec<Update<E>>,
}

impl<E: Engine> AccumulatorUpdates<E> {
    pub fn new(bytes: Vec<Byte<E>>) -> Result<Self, SynthesisError> {
        let mut offset = 0;
        let magic = bytes[offset..offset + 4].to_vec().try_into().unwrap();
        offset += 4;
        let majoc_version = bytes[offset];
        offset += 1;
        let minor_version = bytes[offset];
        offset += 1;
        let (trailing_header_len, trailing_header) = {
            let len = bytes[offset];
            let len_usize = bytes[offset].get_byte_value().unwrap() as usize;
            let content = bytes[offset + 1..offset + 1 + len_usize].to_vec();
            offset += 1 + len_usize;
            (len, content)
        };
        let update_type = bytes[offset];
        offset += 1;
        let (vaa_length, vaa) = {
            let len = bytes[offset..offset + 2].to_vec().try_into().unwrap();
            let len_usize = ((bytes[offset].get_byte_value().unwrap() as usize) << 8)
                + (bytes[offset + 1].get_byte_value().unwrap() as usize);
            let content = bytes[offset + 2..offset + 2 + len_usize].to_vec();
            offset += 2 + len_usize;
            (len, content)
        };
        let num_updates = bytes[offset];
        offset += 1;
        Ok(Self {
            magic,
            majoc_version,
            minor_version,
            trailing_header_len,
            trailing_header,
            update_type,
            vaa_length,
            vaa,
            num_updates,
        })
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
const LEN_PRICE_FEED: usize = LEN_PRICE_FEED_TYPE
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
    use crate::utils::{bytes_assert_eq, hex_to_bytes_constant};
    use pairing::bn256::Bn256;
    use sync_vm::{circuit_structures::byte::Byte, franklin_crypto::bellman::SynthesisError};

    // #[test]
    // fn test_updates_new() -> Result<(), SynthesisError> {
    //     let bytes = "005500c9d8b075a5c69303365ae23633d4e085199bf5c520a3b90fed1322a0342ffc3300000367b487485200000000f2e39195fffffff800000000655f19a500000000655f19a500000366b50bd8c0000000011756c6340a719ee4b8bf510572e2fbbbff4f978b600c1644c6dbad2501b25e1494aa4406f99bc8a25318e240733ceb7e92859c5b475c06cdbc8566a0625c5c8ef1cd7995103c2b06b2797e9cbec59b66ebce03aee4e269bffeb83c14fb0a39ee76d06e93d492eeaba6237e89d1965b929bdec06580fef49468b124ac07d1188dae596f66c764cb8c2b221aaacf221ec4b50f1fa79c2eaab85f58a9cdadc77a54e2f45bd5614853e6936dcd6ba91c10c3e3af0292ec3992a78468e35a9eac20b6c83e345fe523c51d0d502f22b5";
    //     let bytes = hex::decode(bytes)
    //         .unwrap()
    //         .into_iter()
    //         .map(|b| Byte::<Bn256>::constant(b))
    //         .collect::<Vec<_>>();
    //     let update = super::Update::new(&bytes)?;

    //     bytes_assert_eq(&update.message, "0055");
    //     bytes_assert_eq(&update.message, "00c9d8b075a5c69303365ae23633d4e085199bf5c520a3b90fed1322a0342ffc3300000367b487485200000000f2e39195fffffff800000000655f19a500000000655f19a500000366b50bd8c0000000011756c634");
    //     bytes_assert_eq(&[update.proof_size], "0a");
    //     bytes_assert_eq(
    //         &update.proof.inner()[0],
    //         "719ee4b8bf510572e2fbbbff4f978b600c1644c6",
    //     );
    //     Ok(())
    // }

    #[test]
    fn test_accumulator_updates() -> Result<(), SynthesisError> {
        let bytes = "504e41550100000003b801000000030d00d728a974b0ca5103e51553fbf1f3a6714d13f0ff790f17aaf7c15bf6c224b23127b57d00c54c13a511be05070b5531066d42f90fa654e11fc6a0ea7afceb14d4000245e36bbde083b3184db9d10abf9b4057cd17f12a5eb16935cc9395ae5412fbcb4c239541363bf3bac6cc8b0d376f5f9a75724b9104b51a951172ebb6170fdd0d00032d0b89c97e86a6565118b0eb00797c5af8dce0255bab01507651707a56faf7c16448769264302c02c1e2d5442157c200628426ee22e899dbceaabeb2b2a5d81d0106ee92dec7698af9ef092776c0885ea4102384638b4a668ff69c81c3421ba13e8542b5224999bc79ae79bb9b697ea46515babdefe86eb637bcdcd5c62e3780b02c000764cdc852d7a6aaa139e21e76ff2e32a4b48c6324ced09d2941c5dfee6efca88a71b3b7781190c6e56785f079604c9f02837aa9af167886f6322e5035c928e07c010a4236874844d614201372d0860e7d32b82f6812bb2ea09c4aa5593d3e22a7193576d1d8336dcedd7548a636d027589247c85cc8ab4b661d361136dd6c2487707e000b6316f3fff7f27d7e112b99ccde935887b5c9c3ad8ffd91f86c07fd634aac335e3c45090cc97b219c7d5218784e78b96e36657b1cf1021e74402da2624c3ec5f7000c83a3f7e417cf6f02517652b931695aeb85a6941ad57f188e4e485888871fb803731752055360a6a06de918faeb30822814d5de7e71d38ce28bfb0d4bd5fdb053010d4cc5b65defbce9efca29814d5a782774de219bd6d8af6d74d355462f696128cb002bc92fc3c8a6ee8f49b11f9d63b49d9290de65ff95cbab2a7eb9c111ec5f6f000e820f2d14e65b117d9babd3990289bdad168e4ebb867a7085994879190a9a91ee5480a9e9c6ffaeb9c1dac3463a2ff08ad77a116c62bc6af5496df012dfea6b0301107bd838dad5af50ffd717e490170439a29943e2b34122d4030b185688d192c474071dfee4ba4d802bc61eaa1abaf394b190b292c3e402da8ef9cb576ca95ce2cb0111fd97f02792a6dc86417b97e4bf13a764c7c205bd61cf47f4a2f7c2620474b3bf706540efdf9e6260aff2c3f188b415609185ffdf3d6296ceb2d9df8eb8c800a10012158d010289db2636396a6190817250eab31801337bee032a467667feca47d41c3cc1e15e4218586ac777abbf2db95c2ae97223ce896e50222caaf76679af92f201655f19a600000000001ae101faedac5851e32b9b23b5f9411a8c2bac4aae3ed4dd7b811dd1a72ea4aa7100000000019b75750141555756000000000006a12f90000027107fb32c3012f67272158be9987275ad7c3f86b82d02005500c9d8b075a5c69303365ae23633d4e085199bf5c520a3b90fed1322a0342ffc3300000367b487485200000000f2e39195fffffff800000000655f19a500000000655f19a500000366b50bd8c0000000011756c6340a719ee4b8bf510572e2fbbbff4f978b600c1644c6dbad2501b25e1494aa4406f99bc8a25318e240733ceb7e92859c5b475c06cdbc8566a0625c5c8ef1cd7995103c2b06b2797e9cbec59b66ebce03aee4e269bffeb83c14fb0a39ee76d06e93d492eeaba6237e89d1965b929bdec06580fef49468b124ac07d1188dae596f66c764cb8c2b221aaacf221ec4b50f1fa79c2eaab85f58a9cdadc77a54e2f45bd5614853e6936dcd6ba91c10c3e3af0292ec3992a78468e35a9eac20b6c83e345fe523c51d0d502f22b5005500ff61491a931112ddf1bd8147cd1b641375f79f5825126d665480874634fd0ace000000306ae225da00000000063cdaf3fffffff800000000655f19a500000000655f19a50000003044f393e000000000059b1ff30afd052ff1a1f0fd3638fc34ad246bc2b004ec0e6743110fcaf3f85db51e7cc3334f9ecfab7c0d28c87bf8e15a9a54f1fb5de587224ed3c1aaf24398a9246b25cdeedbb2e070b592b23fcc8d2ff79a4f8d74f09471c5e7dff820ea8c30763a7e421ecdf27ab3375c716a792bbcbb49821d2df7c1cb46efc1bea7c1ab2e28acae7334e513deb21dbaece63873660f1fa79c2eaab85f58a9cdadc77a54e2f45bd5614853e6936dcd6ba91c10c3e3af0292ec3992a78468e35a9eac20b6c83e345fe523c51d0d502f22b5";
        let bytes = hex::decode(bytes)
            .unwrap()
            .into_iter()
            .map(|b| Byte::<Bn256>::constant(b))
            .collect::<Vec<_>>();
        let updates = super::AccumulatorUpdates::new(bytes)?;
        bytes_assert_eq(&updates.magic, "504e4155");
        bytes_assert_eq(&[updates.majoc_version], "01");
        bytes_assert_eq(&[updates.minor_version], "00");
        bytes_assert_eq(&[updates.trailing_header_len], "00");
        bytes_assert_eq(&updates.trailing_header, "");
        bytes_assert_eq(&[updates.update_type], "00");
        bytes_assert_eq(&updates.vaa_length, "03b8");
        bytes_assert_eq(&updates.vaa, "01000000030d00d728a974b0ca5103e51553fbf1f3a6714d13f0ff790f17aaf7c15bf6c224b23127b57d00c54c13a511be05070b5531066d42f90fa654e11fc6a0ea7afceb14d4000245e36bbde083b3184db9d10abf9b4057cd17f12a5eb16935cc9395ae5412fbcb4c239541363bf3bac6cc8b0d376f5f9a75724b9104b51a951172ebb6170fdd0d00032d0b89c97e86a6565118b0eb00797c5af8dce0255bab01507651707a56faf7c16448769264302c02c1e2d5442157c200628426ee22e899dbceaabeb2b2a5d81d0106ee92dec7698af9ef092776c0885ea4102384638b4a668ff69c81c3421ba13e8542b5224999bc79ae79bb9b697ea46515babdefe86eb637bcdcd5c62e3780b02c000764cdc852d7a6aaa139e21e76ff2e32a4b48c6324ced09d2941c5dfee6efca88a71b3b7781190c6e56785f079604c9f02837aa9af167886f6322e5035c928e07c010a4236874844d614201372d0860e7d32b82f6812bb2ea09c4aa5593d3e22a7193576d1d8336dcedd7548a636d027589247c85cc8ab4b661d361136dd6c2487707e000b6316f3fff7f27d7e112b99ccde935887b5c9c3ad8ffd91f86c07fd634aac335e3c45090cc97b219c7d5218784e78b96e36657b1cf1021e74402da2624c3ec5f7000c83a3f7e417cf6f02517652b931695aeb85a6941ad57f188e4e485888871fb803731752055360a6a06de918faeb30822814d5de7e71d38ce28bfb0d4bd5fdb053010d4cc5b65defbce9efca29814d5a782774de219bd6d8af6d74d355462f696128cb002bc92fc3c8a6ee8f49b11f9d63b49d9290de65ff95cbab2a7eb9c111ec5f6f000e820f2d14e65b117d9babd3990289bdad168e4ebb867a7085994879190a9a91ee5480a9e9c6ffaeb9c1dac3463a2ff08ad77a116c62bc6af5496df012dfea6b0301107bd838dad5af50ffd717e490170439a29943e2b34122d4030b185688d192c474071dfee4ba4d802bc61eaa1abaf394b190b292c3e402da8ef9cb576ca95ce2cb0111fd97f02792a6dc86417b97e4bf13a764c7c205bd61cf47f4a2f7c2620474b3bf706540efdf9e6260aff2c3f188b415609185ffdf3d6296ceb2d9df8eb8c800a10012158d010289db2636396a6190817250eab31801337bee032a467667feca47d41c3cc1e15e4218586ac777abbf2db95c2ae97223ce896e50222caaf76679af92f201655f19a600000000001ae101faedac5851e32b9b23b5f9411a8c2bac4aae3ed4dd7b811dd1a72ea4aa7100000000019b75750141555756000000000006a12f90000027107fb32c3012f67272158be9987275ad7c3f86b82d");
        bytes_assert_eq(&[updates.num_updates], "02");

        println!("YES");
        Ok(())
    }

    #[test]
    fn tset_price_feed() -> Result<(), SynthesisError> {
        let hex_str = "00e62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b4300000352813ebdc00000000042eeb9f6fffffff800000000655ccff700000000655ccff700000356d0a75ce0000000005b0d7112";
        let bytes = hex_to_bytes_constant::<Bn256>(hex_str).unwrap();
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
