use eth_keystore::{decrypt_key, encrypt_key, encrypt_with_encryptor, new, Encryptor};
use hex::FromHex;
use std::path::Path;

mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let dir = Path::new("./tests/test-keys");
        let mut rng = rand::rng();
        let (secret, id) = new(dir, &mut rng, "thebestrandompassword", None).unwrap();

        let keypath = dir.join(&id);

        assert_eq!(
            decrypt_key(&keypath, "thebestrandompassword").unwrap(),
            secret
        );
        assert!(decrypt_key(&keypath, "notthebestrandompassword").is_err());
        assert!(std::fs::remove_file(&keypath).is_ok());
    }

    #[test]
    fn test_new_with_name() {
        let dir = Path::new("./tests/test-keys");
        let mut rng = rand::rng();
        let name = "my_keystore";
        let (secret, _id) = new(dir, &mut rng, "thebestrandompassword", Some(name)).unwrap();

        let keypath = dir.join(name);

        assert_eq!(
            decrypt_key(&keypath, "thebestrandompassword").unwrap(),
            secret
        );
        assert!(std::fs::remove_file(&keypath).is_ok());
    }

    #[cfg(all(feature = "v3", not(feature = "geth-compat")))]
    #[test]
    fn test_decrypt_pbkdf2_v3() {
        let secret =
            Vec::from_hex("7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d")
                .unwrap();
        let keypath = Path::new("./tests/test-keys/key-pbkdf2-v3.json");
        assert_eq!(decrypt_key(keypath, "testpassword").unwrap(), secret);
        assert!(decrypt_key(keypath, "wrongtestpassword").is_err());
    }

    #[cfg(all(feature = "v3", not(feature = "geth-compat")))]
    #[test]
    fn test_decrypt_scrypt_v3() {
        let secret =
            Vec::from_hex("80d3a6ed7b24dcd652949bc2f3827d2f883b3722e3120b15a93a2e0790f03829")
                .unwrap();
        let keypath = Path::new("./tests/test-keys/key-scrypt-v3.json");
        assert_eq!(decrypt_key(keypath, "grOQ8QDnGHvpYJf").unwrap(), secret);
        assert!(decrypt_key(keypath, "thisisnotrandom").is_err());
    }

    #[cfg(feature = "v4")]
    #[test]
    fn test_decrypt_pbkdf2_v4() {
        let secret =
            Vec::from_hex("7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d")
                .unwrap();
        let keypath = Path::new("./tests/test-keys/key-pbkdf2-v4.json");
        assert_eq!(decrypt_key(keypath, "testpassword").unwrap(), secret);
        assert!(decrypt_key(keypath, "wrongtestpassword").is_err());
    }

    #[cfg(feature = "v4")]
    #[test]
    fn test_decrypt_scrypt_v4() {
        let secret =
            Vec::from_hex("80d3a6ed7b24dcd652949bc2f3827d2f883b3722e3120b15a93a2e0790f03829")
                .unwrap();
        let keypath = Path::new("./tests/test-keys/key-scrypt-v4.json");
        assert_eq!(decrypt_key(keypath, "grOQ8QDnGHvpYJf").unwrap(), secret);
        assert!(decrypt_key(keypath, "thisisnotrandom").is_err());
    }

    #[test]
    fn test_encrypt_decrypt_key() {
        let secret =
            Vec::from_hex("7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d")
                .unwrap();
        let dir = Path::new("./tests/test-keys");
        let mut rng = rand::rng();
        let name = encrypt_key(dir, &mut rng, &secret, "newpassword", None).unwrap();

        let keypath = dir.join(&name);
        assert_eq!(decrypt_key(&keypath, "newpassword").unwrap(), secret);
        assert!(decrypt_key(&keypath, "notanewpassword").is_err());
        assert!(std::fs::remove_file(&keypath).is_ok());
    }

    #[cfg(feature = "v3")]
    #[test]
    fn test_encrypt_decrypt_with_encryptor_v3() {
        let secret =
            Vec::from_hex("7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d")
                .unwrap();
        let dir = Path::new("./tests/test-keys");
        let encryptor = Encryptor::new_v3(rand::rng());
        let name = encrypt_with_encryptor(dir, encryptor, &secret, "newpassword", None).unwrap();

        let keypath = dir.join(&name);
        assert_eq!(decrypt_key(&keypath, "newpassword").unwrap(), secret);
        assert!(decrypt_key(&keypath, "notanewpassword").is_err());
        assert!(std::fs::remove_file(&keypath).is_ok());
    }

    #[cfg(feature = "v4")]
    #[test]
    fn test_encrypt_decrypt_with_encryptor_v4() {
        let secret =
            Vec::from_hex("7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d")
                .unwrap();
        let dir = Path::new("./tests/test-keys");
        let encryptor = Encryptor::new_v4(rand::rng());
        let name = encrypt_with_encryptor(dir, encryptor, &secret, "newpassword", None).unwrap();

        let keypath = dir.join(&name);
        assert_eq!(decrypt_key(&keypath, "newpassword").unwrap(), secret);
        assert!(decrypt_key(&keypath, "notanewpassword").is_err());
        assert!(std::fs::remove_file(&keypath).is_ok());
    }
}
