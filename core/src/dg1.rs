use color_eyre::eyre::{bail, Error, Result};
use der::Reader;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DG1Variant {
    TD1,
    TD2,
    TD3,
}

impl TryFrom<&[u8]> for DG1Variant {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        // Create a reader for the input data
        let mut reader = der::SliceReader::new(value)?;

        // Skip the outer tag - just read a single byte
        reader.read_byte()?;

        // Read the length field
        let length_byte = reader.read_byte()?;
        let _content_length = if length_byte < 0x80 {
            length_byte as usize
        } else {
            let num_length_bytes = length_byte & 0x7F;
            let mut len = 0;
            for _ in 0..num_length_bytes {
                len = (len << 8) | (reader.read_byte()? as usize);
            }
            len
        };

        // Skip to the 5F1F tag
        // First, check that we have 0x5F 0x1F
        if reader.read_byte()? != 0x5F || reader.read_byte()? != 0x1F {
            bail!("Expected 0x5F1F tag for MRZ data");
        }

        // Read the length of MRZ data
        let mrz_length_byte = reader.read_byte()?;
        let mrz_length = if mrz_length_byte < 0x80 {
            mrz_length_byte as usize
        } else {
            let num_length_bytes = mrz_length_byte & 0x7F;
            let mut len = 0;
            for _ in 0..num_length_bytes {
                len = (len << 8) | (reader.read_byte()? as usize);
            }
            len
        };

        // Determine variant based on MRZ data length
        match mrz_length {
            90 => Ok(DG1Variant::TD1), // 3 lines x 30 characters
            72 => Ok(DG1Variant::TD2), // 2 lines x 36 characters
            88 => Ok(DG1Variant::TD3), // 2 lines x 44 characters
            _ => bail!("Invalid DG1 variant with length {}", mrz_length),
        }
    }
}
