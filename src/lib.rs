#![cfg_attr(docsrs, feature(doc_cfg))]
//! A minimalist library to interact with encrypted JSON keystores v3 and v4.

use rand::{CryptoRng, Rng};

use std::{fs::File, path::Path};

mod error;
mod keystore;
mod utils;

use keystore::EthKeystore;

pub use error::KeystoreError;

use crate::keystore::encryptor;
pub use encryptor::Encryptor;

/// Creates a new JSON keystore using the [Scrypt](https://tools.ietf.org/html/rfc7914.html)
/// key derivation function. The keystore is encrypted by a key derived from the provided `password`
/// and stored in the provided directory with either the user-provided filename, or a generated
/// Uuid `id`.
///
/// # Example
///
/// ```no_run
/// use eth_keystore::new;
/// use std::path::Path;
///
/// # async fn foobar() -> Result<(), Box<dyn std::error::Error>> {
/// let dir = Path::new("./keys");
/// let mut rng = rand::thread_rng();
/// // here `None` signifies we don't specify a filename for the keystore.
/// // the default filename is a generated Uuid for the keystore.
/// let (private_key, name) = new(&dir, &mut rng, "password_to_keystore", None)?;
///
/// // here `Some("my_key")` denotes a custom filename passed by the caller.
/// let (private_key, name) = new(&dir, &mut rng, "password_to_keystore", Some("my_key"))?;
/// # Ok(())
/// # }
/// ```
pub fn new<P, R, S>(
    dir: P,
    rng: &mut R,
    password: S,
    name: Option<&str>,
) -> Result<(Vec<u8>, String), KeystoreError>
where
    P: AsRef<Path>,
    R: Rng + CryptoRng,
    S: AsRef<[u8]>,
{
    // Generate a random private key.
    let mut pk = vec![0u8; encryptor::DEFAULT_KEY_SIZE];
    rng.fill_bytes(pk.as_mut_slice());

    let name = encrypt_key(dir, rng, &pk, password, name)?;
    Ok((pk, name))
}

/// Decrypts an encrypted JSON keystore at the provided `path` using the provided `password`.
/// Decryption supports the [Scrypt](https://tools.ietf.org/html/rfc7914.html) and
/// [PBKDF2](https://ietf.org/rfc/rfc2898.txt) key derivation functions.
///
/// # Example
///
/// ```no_run
/// use eth_keystore::decrypt_key;
/// use std::path::Path;
///
/// # async fn foobar() -> Result<(), Box<dyn std::error::Error>> {
/// let keypath = Path::new("./keys/my-key");
/// let private_key = decrypt_key(&keypath, "password_to_keystore")?;
/// # Ok(())
/// # }
/// ```
pub fn decrypt_key<P, S>(path: P, password: S) -> Result<Vec<u8>, KeystoreError>
where
    P: AsRef<Path>,
    S: AsRef<[u8]>,
{
    // Read the file contents as string and deserialize it.
    let file = File::open(path)?;
    let keystore: EthKeystore = serde_json::from_reader(file)?;

    let pk = keystore.private_key(password)?;

    Ok(pk)
}

/// Encrypts the given private key using the [Scrypt](https://tools.ietf.org/html/rfc7914.html)
/// password-based key derivation function, and stores it in the provided directory. On success, it
/// returns the `id` (Uuid) generated for this keystore.
///
/// # Example
///
/// ```no_run
/// use eth_keystore::encrypt_key;
/// use rand::RngCore;
/// use std::path::Path;
///
/// # async fn foobar() -> Result<(), Box<dyn std::error::Error>> {
/// let dir = Path::new("./keys");
/// let mut rng = rand::thread_rng();
///
/// // Construct a 32-byte random private key.
/// let mut private_key = vec![0u8; 32];
/// rng.fill_bytes(private_key.as_mut_slice());
///
/// // Since we specify a custom filename for the keystore, it will be stored in `$dir/my-key`
/// let name = encrypt_key(&dir, &mut rng, &private_key, "password_to_keystore", Some("my-key"))?;
/// # Ok(())
/// # }
/// ```
pub fn encrypt_key<P, R, B, S>(
    dir: P,
    rng: &mut R,
    pk: B,
    password: S,
    name: Option<&str>,
) -> Result<String, KeystoreError>
where
    P: AsRef<Path>,
    R: Rng + CryptoRng,
    B: AsRef<[u8]>,
    S: AsRef<[u8]>,
{
    // use v3 by default
    #[cfg(feature = "v3")]
    let mut encryptor = Encryptor::new_v3(rng);
    #[cfg(all(feature = "v4", not(feature = "v3")))]
    let mut encryptor = Encryptor::new_v4(rng);

    let keystore = encryptor.encrypt(pk, password)?;
    let id = keystore.id().to_string();
    save_keystore(dir, keystore, name)?;

    Ok(id)
}

/// Encrypts the given private key using the provided `Encryptor` instance.
/// On success returns the `id` (Uuid) generated for this keystore.
///
/// # Example
///
/// ```no_run
/// use eth_keystore::{Encryptor, encrypt_with_encryptor};
/// use rand::RngCore;
/// use std::path::Path;
///
/// # async fn foobar() -> Result<(), Box<dyn std::error::Error>> {
/// let dir = Path::new("./keys");
/// let mut rng = rand::thread_rng();
///
/// // Construct a 32-byte random private key.
/// let mut private_key = vec![0u8; 32];
/// rng.fill_bytes(private_key.as_mut_slice());
///
/// let encryptor = Encryptor::new_v3(rng);
/// let name = encrypt_with_encryptor(&dir, encryptor, &private_key, "password_to_keystore", Some("my-key"))?;
/// # Ok(())
/// # }
/// ```
pub fn encrypt_with_encryptor<P, B, S, R>(
    dir: P,
    mut encryptor: Encryptor<R>,
    pk: B,
    password: S,
    name: Option<&str>,
) -> Result<String, KeystoreError>
where
    P: AsRef<Path>,
    R: Rng + CryptoRng,
    B: AsRef<[u8]>,
    S: AsRef<[u8]>,
{
    let keystore = encryptor.encrypt(pk, password)?;
    let id = keystore.id().to_string();
    save_keystore(dir, keystore, name)?;

    Ok(id)
}

fn save_keystore<P>(dir: P, keystore: EthKeystore, name: Option<&str>) -> Result<(), KeystoreError>
where
    P: AsRef<Path>,
{
    let name = if let Some(name) = name {
        name.to_string()
    } else {
        keystore.id().to_string()
    };

    let file = File::create(dir.as_ref().join(name))?;
    serde_json::to_writer(file, &keystore)?;

    Ok(())
}
