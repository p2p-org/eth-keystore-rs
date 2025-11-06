use aes::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use digest::{Digest, Update};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::{CryptoRng, Rng};
use scrypt::{scrypt, Params};
use sha2::Sha256;
use sha3::Keccak256;
use uuid::Uuid;

#[cfg(feature = "v3")]
use crate::keystore::v3;

#[cfg(feature = "v4")]
use crate::keystore::v4;

use crate::{keystore::EthKeystore, KeystoreError};

const DEFAULT_DKLEN: u8 = 32;
const DEFAULT_SCRYPT_N: u8 = 13;
const DEFAULT_SCRYPT_P: u32 = 1;
const DEFAULT_SCRYPT_R: u32 = 8;
pub const DEFAULT_KEY_SIZE: usize = 32;
const DEFAULT_IV_SIZE: usize = 16;

pub struct Encryptor<R: Rng + CryptoRng> {
    version: KeystoreVersion,
    kdf: Kdf,

    // common kdf params
    dklen: u8,

    rng: R,
}

impl<R: Rng + CryptoRng> Encryptor<R> {
    #[cfg(feature = "v3")]
    pub fn new_v3(rng: R) -> Self {
        Encryptor {
            version: KeystoreVersion::V3,
            kdf: Kdf::default(),
            dklen: DEFAULT_DKLEN,
            rng,
        }
    }

    #[cfg(feature = "v4")]
    pub fn new_v4(rng: R) -> Self {
        Encryptor {
            version: KeystoreVersion::V4,
            kdf: Kdf::default(),
            dklen: DEFAULT_DKLEN,
            rng,
        }
    }

    pub fn kdf(&mut self, kdf: Kdf) {
        self.kdf = kdf;
    }

    pub fn dklen(&mut self, dklen: u8) {
        self.dklen = dklen;
    }

    pub fn encrypt(
        &mut self,
        pk: impl AsRef<[u8]>,
        password: impl AsRef<[u8]>,
    ) -> Result<EthKeystore, KeystoreError> {
        let mut salt = vec![0u8; DEFAULT_KEY_SIZE];
        self.rng.fill(salt.as_mut_slice());

        let mut iv = vec![0u8; DEFAULT_IV_SIZE];
        self.rng.fill(iv.as_mut_slice());

        let key = self.kdf.derive_key(self.dklen as usize, &salt, password)?;

        let mut cipher: Ctr128BE<aes::Aes128> =
            Ctr128BE::new_from_slices(&key[..16], &iv[..16]).unwrap();

        let mut ciphertext = pk.as_ref().to_vec();
        cipher.apply_keystream(&mut ciphertext);

        let id = Uuid::new_v4();

        match self.version {
            #[cfg(feature = "v3")]
            KeystoreVersion::V3 => {
                #[cfg(feature = "geth-compat")]
                use crate::utils::geth_compat::address_from_pk;

                let checksum = Keccak256::new()
                    .chain(&key[16..32])
                    .chain(&ciphertext)
                    .finalize();

                let kdf_type = match self.kdf {
                    Kdf::Pbkdf2 { .. } => v3::KdfType::Pbkdf2,
                    Kdf::Scrypt { .. } => v3::KdfType::Scrypt,
                };

                let kdfparams = match self.kdf {
                    Kdf::Pbkdf2 { c } => v3::Kdfparams::Pbkdf2 {
                        c,
                        dklen: self.dklen,
                        prf: String::new(),
                        salt,
                    },
                    Kdf::Scrypt { n, p, r } => v3::Kdfparams::Scrypt {
                        dklen: self.dklen,
                        n: 1 << n as u32,
                        p,
                        r,
                        salt,
                    },
                };

                #[cfg(feature = "geth-compat")]
                let address = address_from_pk(pk)?;

                let keystore = v3::EthKeystore {
                    id,
                    #[cfg(feature = "geth-compat")]
                    address,
                    crypto: v3::Crypto {
                        cipher: String::from("aes-128-ctr"),
                        cipherparams: v3::Cipherparams { iv },
                        ciphertext,
                        kdf: kdf_type,
                        kdfparams,
                        mac: checksum.to_vec(),
                    },
                    version: 3,
                };

                Ok(EthKeystore::V3(keystore))
            }
            #[cfg(feature = "v4")]
            KeystoreVersion::V4 => {
                use crate::utils::pubkey_from_pk;

                let checksum = Sha256::new()
                    .chain(&key[16..32])
                    .chain(&ciphertext)
                    .finalize();

                let kdf = match self.kdf {
                    Kdf::Pbkdf2 { c } => v4::Kdf::Pbkdf2 {
                        message: Vec::new(),
                        params: v4::KdfParamsPbkdf2 {
                            dklen: self.dklen,
                            c,
                            prf: String::new(),
                            salt,
                        },
                    },
                    Kdf::Scrypt { n, p, r } => v4::Kdf::Scrypt {
                        message: Vec::new(),
                        params: v4::KdfParamsScrypt {
                            dklen: self.dklen,
                            n: 1 << n as u32,
                            p,
                            r,
                            salt,
                        },
                    },
                };

                let pubkey = pubkey_from_pk(pk).unwrap_or_default();

                let keystore = v4::EthKeystore {
                    id,
                    version: 4,
                    description: None,
                    path: None,
                    pubkey,
                    crypto: v4::Crypto {
                        checksum: v4::Checksum {
                            function: String::from("sha256"),
                            message: checksum.to_vec(),
                            params: v4::ChecksumParams {},
                        },
                        cipher: v4::Cipher::Aes128Ctr {
                            message: ciphertext,
                            params: v4::CipherParamsAes128Ctr { iv },
                        },
                        kdf,
                    },
                };

                Ok(EthKeystore::V4(keystore))
            }
        }
    }
}

enum KeystoreVersion {
    #[cfg(feature = "v3")]
    V3,
    #[cfg(feature = "v4")]
    V4,
}

pub enum Kdf {
    Pbkdf2 { c: u32 },
    Scrypt { n: u8, p: u32, r: u32 },
}

impl Kdf {
    fn derive_key(
        &self,
        dklen: usize,
        salt: impl AsRef<[u8]>,
        password: impl AsRef<[u8]>,
    ) -> Result<Vec<u8>, KeystoreError> {
        let mut key = vec![0u8; dklen];
        match self {
            Kdf::Pbkdf2 { c } => {
                pbkdf2::<Hmac<Sha256>>(password.as_ref(), salt.as_ref(), *c, &mut key)
                    .expect("HMAC can be initialized with any key length");
            }
            Kdf::Scrypt { n, p, r } => {
                let scrypt_params = Params::new(*n, *r, *p, dklen)?;
                scrypt(password.as_ref(), salt.as_ref(), &scrypt_params, &mut key)?;
            }
        };
        Ok(key)
    }
}

impl Default for Kdf {
    fn default() -> Self {
        Kdf::Scrypt {
            n: DEFAULT_SCRYPT_N,
            p: DEFAULT_SCRYPT_P,
            r: DEFAULT_SCRYPT_R,
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "geth-compat")]
    use ethereum_types::H160;
    use hex::FromHex;
    use rand::RngCore;

    use super::*;

    struct MockRng {
        bytes: Vec<u8>,
    }

    impl RngCore for MockRng {
        fn next_u32(&mut self) -> u32 {
            0
        }

        fn next_u64(&mut self) -> u64 {
            0
        }

        fn fill_bytes(&mut self, dst: &mut [u8]) {
            if dst.len() > self.bytes.len() {
                panic!("not enough \"random\" bytes");
            }

            dst.copy_from_slice(&self.bytes[..dst.len()]);
        }
    }

    impl CryptoRng for MockRng {}

    #[cfg(feature = "v3")]
    #[test]
    fn test_encryptor_pbkdf_v3() {
        let random_bytes =
            Vec::from_hex("0123456789abcdefabcdef01234567899876543210fedcbafedcba9876543210")
                .unwrap();
        let rng = MockRng {
            bytes: random_bytes.clone(),
        };
        let mut encryptor = Encryptor::new_v3(rng);
        encryptor.kdf = Kdf::Pbkdf2 { c: 1000 };

        let pk = Vec::from_hex("dc6a3354a200a18295e50d3d804b148aaa4804d6e9760095721fa568adc341ed")
            .unwrap();
        let password = "changeme";

        let keystore = encryptor.encrypt(pk, password);
        assert!(keystore.is_ok());

        match keystore.unwrap() {
            EthKeystore::V3(keystore) => {
                assert_eq!(keystore.crypto.cipher, "aes-128-ctr");
                assert_eq!(keystore.crypto.cipherparams.iv, random_bytes[..16]);
                assert_eq!(
                    keystore.crypto.ciphertext,
                    Vec::from_hex(
                        "965ee384297ecf97a19aa7f4574cfca451b0756dbaf7af9ab0c3faca0463905c"
                    )
                    .unwrap()
                );
                assert!(matches!(keystore.crypto.kdf, v3::KdfType::Pbkdf2));
                assert_eq!(
                    keystore.crypto.kdfparams,
                    v3::Kdfparams::Pbkdf2 {
                        c: 1000,
                        dklen: 32,
                        prf: String::new(),
                        salt: random_bytes
                    }
                );
                assert_eq!(
                    keystore.crypto.mac,
                    Vec::from_hex(
                        "5fbd7f1b573abc7d97c3e8f0e6e8c64875ed1f0741c24f24eac1f2d55dff2624"
                    )
                    .unwrap()
                );
                #[cfg(feature = "geth-compat")]
                assert_eq!(
                    keystore.address,
                    H160::from_slice(
                        &Vec::from_hex("7a025532658107bdc4bef95d6dbe728699ce790e").unwrap()
                    ),
                );
            }
            #[cfg(feature = "v4")]
            _ => panic!("Wrong keystore version"),
        }
    }

    #[cfg(feature = "v3")]
    #[test]
    fn test_encryptor_scrypt_v3() {
        let random_bytes =
            Vec::from_hex("0123456789abcdefabcdef01234567899876543210fedcbafedcba9876543210")
                .unwrap();
        let rng = MockRng {
            bytes: random_bytes.clone(),
        };
        let mut encryptor = Encryptor::new_v3(rng);

        let pk = Vec::from_hex("dc6a3354a200a18295e50d3d804b148aaa4804d6e9760095721fa568adc341ed")
            .unwrap();
        let password = "changeme";

        let keystore = encryptor.encrypt(pk, password);
        assert!(keystore.is_ok());

        match keystore.unwrap() {
            EthKeystore::V3(keystore) => {
                assert_eq!(keystore.crypto.cipher, "aes-128-ctr");
                assert_eq!(keystore.crypto.cipherparams.iv, random_bytes[..16]);
                assert_eq!(
                    keystore.crypto.ciphertext,
                    Vec::from_hex(
                        "9f6f355d0b491914895c223ee8ca3289ee31240a98198bd2c057e1e8b713ce90"
                    )
                    .unwrap()
                );
                assert!(matches!(keystore.crypto.kdf, v3::KdfType::Scrypt));
                assert_eq!(
                    keystore.crypto.kdfparams,
                    v3::Kdfparams::Scrypt {
                        dklen: 32,
                        n: 8192,
                        p: 1,
                        r: 8,
                        salt: random_bytes
                    },
                );
                assert_eq!(
                    keystore.crypto.mac,
                    Vec::from_hex(
                        "d09a1c9952b287628d0aaa9ed8c12cfc4d0a30fc7d0198ece31d1fae02bf0e7e"
                    )
                    .unwrap()
                );
                #[cfg(feature = "geth-compat")]
                assert_eq!(
                    keystore.address,
                    H160::from_slice(
                        &Vec::from_hex("7a025532658107bdc4bef95d6dbe728699ce790e").unwrap()
                    ),
                );
            }
            #[cfg(feature = "v4")]
            _ => panic!("Wrong keystore version"),
        }
    }

    #[cfg(feature = "v4")]
    #[test]
    fn test_encryptor_pbkdf_v4() {
        let random_bytes =
            Vec::from_hex("0123456789abcdefabcdef01234567899876543210fedcbafedcba9876543210")
                .unwrap();
        let rng = MockRng {
            bytes: random_bytes.clone(),
        };
        let mut encryptor = Encryptor::new_v4(rng);
        encryptor.kdf = Kdf::Pbkdf2 { c: 1000 };

        let pk = Vec::from_hex("479da317e5cb08a3bd33ee2573b82850a2bb71e77ea7a864716911357671677a")
            .unwrap();
        let password = "changeme";

        let keystore = encryptor.encrypt(pk, password);
        assert!(keystore.is_ok());

        match keystore.unwrap() {
            EthKeystore::V4(keystore) => {
                assert_eq!(keystore.pubkey, Vec::from_hex("926f30018103188f3a49e7a88ad6206f9de67a2c9ea9e7ee411b2074dc2d448f5a284c2760cdd874a579931b59516e3f").unwrap());
                assert_eq!(keystore.crypto.checksum.function, String::from("sha256"));
                assert_eq!(
                    keystore.crypto.checksum.message,
                    Vec::from_hex(
                        "4e7e9f04e10b589b01dfe3b8ad1a7153a2ed6b9a1b5d3d6494d281f23e923d4f"
                    )
                    .unwrap(),
                );
                assert_eq!(
                    keystore.crypto.cipher,
                    v4::Cipher::Aes128Ctr {
                        message: Vec::from_hex(
                            "0da973c76eb566b6894c44eca4bfc07e5943005c2d26076bb3b54e97dfd1b6cb"
                        )
                        .unwrap(),
                        params: v4::CipherParamsAes128Ctr {
                            iv: random_bytes[..16].to_vec(),
                        }
                    }
                );
                assert_eq!(
                    keystore.crypto.kdf,
                    v4::Kdf::Pbkdf2 {
                        message: Vec::new(),
                        params: v4::KdfParamsPbkdf2 {
                            dklen: 32,
                            c: 1000,
                            prf: String::new(),
                            salt: random_bytes,
                        }
                    }
                );
            }
            #[cfg(feature = "v3")]
            _ => panic!("Wrong keystore verion"),
        }
    }

    #[cfg(feature = "v4")]
    #[test]
    fn test_encryptor_scrypt_v4() {
        let random_bytes =
            Vec::from_hex("0123456789abcdefabcdef01234567899876543210fedcbafedcba9876543210")
                .unwrap();
        let rng = MockRng {
            bytes: random_bytes.clone(),
        };
        let mut encryptor = Encryptor::new_v4(rng);

        let pk = Vec::from_hex("479da317e5cb08a3bd33ee2573b82850a2bb71e77ea7a864716911357671677a")
            .unwrap();
        let password = "changeme";

        let keystore = encryptor.encrypt(pk, password);
        assert!(keystore.is_ok());

        match keystore.unwrap() {
            EthKeystore::V4(keystore) => {
                assert_eq!(keystore.pubkey, Vec::from_hex("926f30018103188f3a49e7a88ad6206f9de67a2c9ea9e7ee411b2074dc2d448f5a284c2760cdd874a579931b59516e3f").unwrap());
                assert_eq!(keystore.crypto.checksum.function, String::from("sha256"));
                assert_eq!(
                    keystore.crypto.checksum.message,
                    Vec::from_hex(
                        "82f30848f8241efeda469d647eabce3d23107d098c9affd0809865d7fc7a987a"
                    )
                    .unwrap(),
                );
                assert_eq!(
                    keystore.crypto.cipher,
                    v4::Cipher::Aes128Ctr {
                        message: Vec::from_hex(
                            "0498a51e4c82b035a18ac1261b390e53e6c2513b0fc82323c32155b56ca1e807"
                        )
                        .unwrap(),
                        params: v4::CipherParamsAes128Ctr {
                            iv: random_bytes[..16].to_vec(),
                        }
                    }
                );
                assert_eq!(
                    keystore.crypto.kdf,
                    v4::Kdf::Scrypt {
                        message: Vec::new(),
                        params: v4::KdfParamsScrypt {
                            dklen: 32,
                            n: 8192,
                            p: 1,
                            r: 8,
                            salt: random_bytes
                        }
                    }
                );
            }
            #[cfg(feature = "v3")]
            _ => panic!("Wrong keystore verion"),
        }
    }
}
