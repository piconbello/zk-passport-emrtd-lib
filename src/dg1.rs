pub type MrzTd3 = [u8; 88];

pub type Dg1Td3 = [u8; 93];

/// Fixed header bytes for TD3 Machine Readable Zone (MRZ) Document Group 1 (DG1)
///
/// Structure:
/// - `0x61`: Tag for DG1
/// - `0x5B`: Total length (91 bytes) of MRZ data including subtag and length
/// - `0x5F, 0x1F`: Sub-tag indicating MRZ data
/// - `0x58`: Length of MRZ data (88 bytes)
///
/// This header follows ASN.1 BER-TLV encoding where:
/// - T (Tag): Identifies the data type
/// - L (Length): Specifies the length of the value
/// - V (Value): Contains the actual data (MRZ in this case)
pub const MRZ_TD3_HEADER: [u8; 5] = [0x61, 0x5B, 0x5F, 0x1F, 0x58];
