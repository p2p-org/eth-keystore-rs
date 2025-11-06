use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::KeystoreError;

pub mod encryptor;

#[cfg(feature = "v3")]
pub mod v3;

#[cfg(feature = "v4")]
pub mod v4;

#[derive(Serialize)]
#[serde(tag = "version")]
pub enum EthKeystore {
    #[cfg(feature = "v3")]
    #[serde(rename = "3")]
    V3(v3::EthKeystore),

    #[cfg(feature = "v4")]
    #[serde(rename = "4")]
    V4(v4::EthKeystore),
}

impl EthKeystore {
    pub fn private_key(&self, password: impl AsRef<[u8]>) -> Result<Vec<u8>, KeystoreError> {
        match self {
            #[cfg(feature = "v3")]
            Self::V3(keystore) => keystore.crypto.private_key(password),
            #[cfg(feature = "v4")]
            Self::V4(keystore) => keystore.crypto.private_key(password),
        }
    }

    pub fn id(&self) -> Uuid {
        match self {
            #[cfg(feature = "v3")]
            Self::V3(keystore) => keystore.id,
            #[cfg(feature = "v4")]
            Self::V4(keystore) => keystore.id,
        }
    }
}

impl<'de> Deserialize<'de> for EthKeystore {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = serde_json::Value::deserialize(deserializer)?;
        if let Some(version) = v["version"].as_u64() {
            match version {
                #[cfg(feature = "v3")]
                3 => {
                    let keystore: v3::EthKeystore = serde_json::from_value(v).unwrap();
                    Ok(EthKeystore::V3(keystore))
                }
                #[cfg(feature = "v4")]
                4 => {
                    let keystore: v4::EthKeystore = serde_json::from_value(v).unwrap();
                    Ok(EthKeystore::V4(keystore))
                }
                _ => Err(serde::de::Error::unknown_variant(
                    &version.to_string(),
                    &[
                        #[cfg(feature = "v3")]
                        "3",
                        #[cfg(feature = "v4")]
                        "4",
                    ],
                )),
            }
        } else {
            Err(serde::de::Error::custom("version is required"))
        }
    }
}
