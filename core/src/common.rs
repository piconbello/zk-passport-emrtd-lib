pub mod nid_serialization {
    use color_eyre::eyre::Result;
    use openssl::nid::Nid;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(nid: &Nid, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Get the short name representation of the NID
        let name = nid
            .short_name()
            .map_err(|e| serde::ser::Error::custom(format!("Failed to get NID name: {}", e)))?;
        serializer.serialize_str(name)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Nid, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        // Deserialize the string name
        let name = String::deserialize(deserializer)?;

        // Convert string to CString for FFI
        let c_str = std::ffi::CString::new(name.clone())
            .map_err(|e| Error::custom(format!("Invalid string for NID conversion: {}", e)))?;

        // Use unsafe block to call OpenSSL's OBJ_sn2nid
        let nid = unsafe { openssl_sys::OBJ_sn2nid(c_str.as_ptr()) };

        if nid == 0 {
            return Err(Error::custom(format!(
                "Unknown OpenSSL object name: {}",
                name
            )));
        }

        Ok(Nid::from_raw(nid))
    }
}
