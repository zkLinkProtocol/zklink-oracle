mod price;
mod wormhole;

pub use price::LEN_PRICE_FEED;
pub type Update<E> = price::Update<E, DEEP_MERKLE_TREE>;
pub use price::PriceFeed;
pub use wormhole::WormholeBody;
pub use wormhole::WormholeMessage;
pub use wormhole::WormholePayload;

use crate::params::DEEP_MERKLE_TREE;
