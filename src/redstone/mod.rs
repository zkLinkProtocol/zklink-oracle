pub mod circuit;
pub mod types;

// Number of bytes reserved to store timestamp
pub const TIMESTAMP_BS: usize = 6;
// Number of bytes reserved to store the number of data points
pub const DATA_POINTS_COUNT_BS: usize = 3;
// Number of bytes reserved to store datapoints byte size
pub const DATA_POINT_VALUE_BYTE_SIZE_BS: usize = 4;
// Default value byte size for numeric values
pub const DEFAULT_NUM_VALUE_BS: usize = 32;
// Default precision for numeric values
pub const DEFAULT_NUM_VALUE_DECIMALS: usize = 8;

