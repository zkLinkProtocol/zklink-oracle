mod price;
mod wormhole;

pub use price::LEN_PRICE_FEED;
pub type Update<E> = price::Update<E, LEN_PRICE_FEED>;
pub type AccumulatorUpdates<E> = price::AccumulatorUpdates<E, LEN_PRICE_FEED, NUM_PRICE_UPDATES>;
pub use price::PriceFeed;
pub use wormhole::WormholePayload;
pub use wormhole::WormholeBody;
pub use wormhole::WormholeMessage;

use crate::params::NUM_PRICE_UPDATES;
