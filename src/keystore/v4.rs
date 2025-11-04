use aes::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use digest::Update;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use scrypt::scrypt;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::KeystoreError;

#[serde_as]
#[derive(Debug, Deserialize, Serialize)]
pub struct EthKeystore {
    pub description: Option<String>,
    pub path: Option<String>,
    #[serde_as(as = "serde_with::hex::Hex")]
    pub pubkey: Vec<u8>,
    pub id: Uuid,
    pub crypto: Crypto,
    pub version: u8,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct Crypto {
    pub checksum: Checksum,
    pub cipher: Cipher,
    pub kdf: Kdf,
}

impl Crypto {
    pub fn private_key(&self, password: impl AsRef<[u8]>) -> Result<Vec<u8>, KeystoreError> {
        let key = self.kdf.derive_key(password)?;
        let checksum = Sha256::new()
            .chain(&key[16..32])
            .chain(self.cipher.message())
            .finalize();

        if checksum.as_ref() != self.checksum.message {
            return Err(KeystoreError::MacMismatch);
        }

        let pk = self.cipher.decrypt(key)?;

        Ok(pk)
    }
}

#[serde_as]
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct Checksum {
    pub function: String,
    #[serde_as(as = "serde_with::hex::Hex")]
    pub message: Vec<u8>,
    pub params: ChecksumParams,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct ChecksumParams {}

#[serde_as]
#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "function")]
pub enum Cipher {
    #[serde(rename = "aes-128-ctr")]
    Aes128Ctr {
        #[serde_as(as = "serde_with::hex::Hex")]
        message: Vec<u8>,
        params: CipherParamsAes128Ctr,
    },
}

impl Cipher {
    fn message(&self) -> &[u8] {
        match self {
            Self::Aes128Ctr { message, .. } => message,
        }
    }

    fn decrypt(&self, key: impl AsRef<[u8]>) -> Result<Vec<u8>, KeystoreError> {
        match self {
            Self::Aes128Ctr { message, params } => {
                let mut decryptor: Ctr128BE<aes::Aes128> =
                    Ctr128BE::new_from_slices(&key.as_ref()[..16], &params.iv[..16])?;
                let mut buf = message.clone();
                decryptor.apply_keystream(&mut buf);
                Ok(buf)
            }
        }
    }
}

#[serde_as]
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct CipherParamsAes128Ctr {
    #[serde_as(as = "serde_with::hex::Hex")]
    pub iv: Vec<u8>,
}

#[serde_as]
#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "function", rename_all = "lowercase")]
pub enum Kdf {
    Pbkdf2 {
        #[serde_as(as = "serde_with::hex::Hex")]
        message: Vec<u8>,
        params: KdfParamsPbkdf2,
    },
    Scrypt {
        #[serde_as(as = "serde_with::hex::Hex")]
        message: Vec<u8>,
        params: KdfParamsScrypt,
    },
}

#[serde_as]
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct KdfParamsPbkdf2 {
    pub dklen: u8,
    pub c: u32,
    pub prf: String,
    #[serde_as(as = "serde_with::hex::Hex")]
    pub salt: Vec<u8>,
}

#[serde_as]
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct KdfParamsScrypt {
    pub dklen: u8,
    pub n: u32,
    pub p: u32,
    pub r: u32,
    #[serde_as(as = "serde_with::hex::Hex")]
    pub salt: Vec<u8>,
}

impl Kdf {
    pub fn derive_key(&self, password: impl AsRef<[u8]>) -> Result<Vec<u8>, KeystoreError> {
        match self {
            Self::Pbkdf2 { params, .. } => {
                let mut key = vec![0u8; params.dklen as usize];
                pbkdf2::<Hmac<Sha256>>(password.as_ref(), &params.salt, params.c, &mut key)
                    .expect("HMAC can be initialized with any key length");
                Ok(key)
            }
            Self::Scrypt { params, .. } => {
                let mut key = vec![0u8; params.dklen as usize];
                let scrypt_params = scrypt::Params::new(
                    params.n.ilog2() as u8,
                    params.r,
                    params.p,
                    params.dklen as usize,
                )?;
                scrypt(password.as_ref(), &params.salt, &scrypt_params, &mut key)?;
                Ok(key)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use hex::FromHex;

    use super::*;

    #[test]
    fn test_deserialize_pbkdf2() {
        let data = r#"
        {
            "crypto": {
                "cipher": {
                    "function": "aes-128-ctr",
                    "params": {
                        "iv": "6087dab2f9fdbbfaddc31a909735c1e6"
                    },
                    "message": "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46"
                },
                "kdf": {
                    "function": "pbkdf2",
                    "params": {
                        "c": 262144,
                        "dklen": 32,
                        "prf": "hmac-sha256",
                        "salt": "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"
                    },
                    "message": ""
                },
                "checksum": {
                    "function": "sha256",
                    "message": "517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2",
                    "params": {}
                }
            },
            "pubkey": "E1Fc7834857EcE72e1cBAAA227cf038aE9168268",
            "id": "3198bc9c-6672-5ab3-d995-4942343ae5b6",
            "version": 4
        }"#;
        let keystore: EthKeystore = serde_json::from_str(data).unwrap();
        assert_eq!(
            keystore.id,
            Uuid::parse_str("3198bc9c-6672-5ab3-d995-4942343ae5b6").unwrap()
        );
        assert_eq!(
            keystore.pubkey,
            Vec::from_hex("E1Fc7834857EcE72e1cBAAA227cf038aE9168268").unwrap(),
        );
        assert_eq!(
            keystore.crypto,
            Crypto {
                checksum: Checksum {
                    function: String::from("sha256"),
                    message: Vec::from_hex(
                        "517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"
                    )
                    .unwrap(),
                    params: ChecksumParams {},
                },
                cipher: Cipher::Aes128Ctr {
                    message: Vec::from_hex(
                        "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46"
                    )
                    .unwrap(),
                    params: CipherParamsAes128Ctr {
                        iv: Vec::from_hex("6087dab2f9fdbbfaddc31a909735c1e6").unwrap(),
                    }
                },
                kdf: Kdf::Pbkdf2 {
                    message: Vec::from_hex("").unwrap(),
                    params: KdfParamsPbkdf2 {
                        dklen: 32,
                        c: 262144,
                        prf: String::from("hmac-sha256"),
                        salt: Vec::from_hex(
                            "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"
                        )
                        .unwrap()
                    }
                }
            }
        );
    }

    #[test]
    fn test_deserialize_scrypt() {
        let data = r#"
        {
            "crypto": {
                "cipher": {
                    "function": "aes-128-ctr",
                    "params": {
                        "iv": "83dbcc02d8ccb40e466191a123791e0e"
                    },
                    "message": "d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c"
                },
                "kdf": {
                    "function": "scrypt",
                    "params": {
                        "dklen": 32,
                        "n": 262144,
                        "p": 8,
                        "r": 1,
                        "salt": "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19"
                    },
                    "message": ""
                },
                "checksum": {
                    "function": "sha256",
                    "message": "2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097",
                    "params": {}
                }
            },
            "pubkey": "E1Fc7834857EcE72e1cBAAA227cf038aE9168268",
            "id": "3198bc9c-6672-5ab3-d995-4942343ae5b6",
            "version": 4
        }"#;
        let keystore: EthKeystore = serde_json::from_str(data).unwrap();
        assert_eq!(
            keystore.id,
            Uuid::parse_str("3198bc9c-6672-5ab3-d995-4942343ae5b6").unwrap()
        );
        assert_eq!(
            keystore.pubkey,
            Vec::from_hex("E1Fc7834857EcE72e1cBAAA227cf038aE9168268").unwrap(),
        );
        assert_eq!(
            keystore.crypto,
            Crypto {
                checksum: Checksum {
                    function: String::from("sha256"),
                    message: Vec::from_hex(
                        "2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097"
                    )
                    .unwrap(),
                    params: ChecksumParams {},
                },
                cipher: Cipher::Aes128Ctr {
                    message: Vec::from_hex(
                        "d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c"
                    )
                    .unwrap(),
                    params: CipherParamsAes128Ctr {
                        iv: Vec::from_hex("83dbcc02d8ccb40e466191a123791e0e").unwrap(),
                    }
                },
                kdf: Kdf::Scrypt {
                    message: Vec::from_hex("").unwrap(),
                    params: KdfParamsScrypt {
                        dklen: 32,
                        n: 262144,
                        p: 8,
                        r: 1,
                        salt: Vec::from_hex(
                            "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19"
                        )
                        .unwrap()
                    }
                }
            }
        );
    }
}
