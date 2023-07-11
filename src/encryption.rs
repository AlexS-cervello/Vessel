use crate::common::{DB_EXTENSION, VAR_DIR};
use crate::error::Error;
use crate::generator::generate_string;
use crate::generator::DictType;
use chacha20poly1305::{
    aead::{stream, NewAead},
    XChaCha20Poly1305,
};
use cli_clipboard::{ClipboardContext, ClipboardProvider};
use rand::{rngs::OsRng, RngCore};
use std::thread;
use std::time::Duration;
use std::{
    env,
    fs::{File, OpenOptions},
    io::{Read, Write},
};
use zeroize::Zeroize;

fn argon2_config<'a>() -> argon2::Config<'a> {
    return argon2::Config {
        variant: argon2::Variant::Argon2id,
        hash_length: 32,
        lanes: 8,
        mem_cost: 16 * 1024,
        time_cost: 8,
        ..Default::default()
    };
}

fn init_keys(
    password: &str,
    salt: &[u8; 32],
    nonce: &[u8; 19],
) -> (
    Vec<u8>,
    stream::DecryptorBE32<XChaCha20Poly1305>,
    stream::EncryptorBE32<XChaCha20Poly1305>,
) {
    let argon2_config = argon2_config();
    let key = argon2::hash_raw(password.as_bytes(), salt, &argon2_config).unwrap();
    let aead = XChaCha20Poly1305::new(key[..32].as_ref().into());
    let stream_encryptor = stream::EncryptorBE32::from_aead(aead.clone(), nonce.as_ref().into());
    let stream_decryptor = stream::DecryptorBE32::from_aead(aead.clone(), nonce.as_ref().into());
    (key.to_vec(), stream_decryptor, stream_encryptor)
}

fn read_metadata(
    encrypted_file: &mut File,
    salt: &mut [u8; 32],
    nonce: &mut [u8; 19],
) -> Result<(), Error> {
    encrypted_file
        .read_exact(salt)
        .map_err(|_| Error::Generic("Error reading salt".into()))?;
    encrypted_file
        .read_exact(nonce)
        .map_err(|_| Error::Generic("Error reading nonce".into()))?;
    Ok(())
}

fn wipe_keys(mut salt: [u8; 32], mut nonce: [u8; 19], mut key: Vec<u8>) {
    salt.zeroize();
    nonce.zeroize();
    key.zeroize();
}

pub fn create_file(name: &String, password: &String) -> Result<(), Error> {
    // Create output file
    let mut dist_file_path = env::var(VAR_DIR)?;
    dist_file_path.push_str(name);
    dist_file_path.push_str(DB_EXTENSION);

    // Init metadata and keys
    let (mut salt, mut nonce) = ([0u8; 32], [0u8; 19]);
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let (key, _, stream_encryptor) = init_keys(password, &salt, &nonce);

    // Writing to output file
    let mut dist_file = File::create(dist_file_path)?;
    dist_file.write(&salt)?;
    dist_file.write(&nonce)?;

    let msg = b"veas file";
    let ciphertext = stream_encryptor.encrypt_last(&msg[..])?;
    dist_file.write(&ciphertext)?;

    // Wipe keys from memory
    wipe_keys(salt, nonce, key);

    Ok(())
}

pub fn upsert_content(
    encrypted_file_path: &str,
    password: &str,
    username: &str,
    length: u16,
) -> Result<(), Error> {
    // Init salt and nonce
    let (mut salt, mut nonce) = ([0u8; 32], [0u8; 19]);

    // Open file in write and read
    let mut encrypted_file = OpenOptions::new()
        .append(true)
        .create(true)
        .read(true)
        .open(encrypted_file_path)?;

    // Reading metadata
    read_metadata(&mut encrypted_file, &mut salt, &mut nonce)?;

    // Init key and streams
    let (key, stream_decryptor, stream_encryptor) = init_keys(password, &salt, &nonce);

    // Reading encrypted data to vec
    let mut buffer: Vec<u8> = vec![];
    if let Err(err) = encrypted_file.read_to_end(&mut buffer) {
        eprintln!("Error reading file: {}", err);
    }

    // Write salt and nonce back to file
    encrypted_file.set_len(0)?;
    encrypted_file.write(&salt)?;
    encrypted_file.write(&nonce)?;

    // Decrypting data
    let mut original_data = stream_decryptor.decrypt_last(&buffer[..])?;
    let mut data_string = String::from_utf8(original_data.clone())?;
    let pass = generate_string(DictType::Base, length);

    // If username already exists - replace new password for it
    if let Some(index) = data_string.find(format!("{}|", username).as_str()) {
        let start = index + format!("{}/", username).len();
        let end = data_string[start..]
            .find('\n')
            .unwrap_or_else(|| data_string.len() - start);
        data_string.replace_range(start..start + end, pass.as_str());
        original_data = data_string.as_bytes().into();
    } else {
        original_data.extend_from_slice(format!("\n{}|{}", username, pass).as_bytes());
    }

    // Encrypting data and write it to file
    let ciphertext = stream_encryptor.encrypt_last(&original_data[..])?;
    encrypted_file.write(&ciphertext)?;

    // Wipe keys from memory
    wipe_keys(salt, nonce, key);

    Ok(())
}

pub fn copy_pass(
    encrypted_file_path: &str,
    username: &String,
    password: &str,
) -> Result<(), Error> {
    // Init salt and nonce
    let (mut salt, mut nonce) = ([0u8; 32], [0u8; 19]);

    // Open file in write and read
    let mut encrypted_file = OpenOptions::new()
        .append(true)
        .create(true)
        .read(true)
        .open(encrypted_file_path)?;

    // Read metadata
    read_metadata(&mut encrypted_file, &mut salt, &mut nonce)?;

    // Init key and decryptor/encryptor
    let (key, stream_decryptor, _) = init_keys(password, &salt, &nonce);

    // Read data
    let mut buffer: Vec<u8> = vec![];
    if let Err(err) = encrypted_file.read_to_end(&mut buffer) {
        eprintln!("Error reading file: {}", err);
    }

    // Decrypting data
    // original_data is raw bytes, used for read and write bytes to file
    // data_string is String for modifications
    let original_data = stream_decryptor.decrypt_last(&buffer[..])?;
    let data_string = String::from_utf8(original_data)?;

    // Getting pair
    let vec: Vec<String> = data_string.split("\n").map(|s| s.to_string()).collect();
    if let Some(pair) = vec.iter().find(|s| s.starts_with(username)) {
        // Setting vars
        let mut ctx = ClipboardContext::new().unwrap();
        let pass = pair.split("|").nth(1).unwrap();

        // Put password to clipboard
        ctx.set_contents(pass.to_owned()).unwrap();
        ctx.get_contents().unwrap();

        // Printing info
        println!("Password copied to clipboard");
        println!("Will be wiped out in 10 secs");
        thread::sleep(Duration::from_secs(10));

        // Wiping clipboard
        ctx.set_contents(String::new()).unwrap();
        ctx.get_contents().unwrap();
    } else {
        println!("Cannot find password with that username.");
    }
    wipe_keys(salt, nonce, key);
    Ok(())
}

pub fn del_pass(encrypted_file_path: &str, username: &str, password: &str) -> Result<(), Error> {
    // Init salt and nonce
    let (mut salt, mut nonce) = ([0u8; 32], [0u8; 19]);

    // Open file in write and read
    let mut encrypted_file = OpenOptions::new()
        .append(true)
        .create(true)
        .read(true)
        .open(encrypted_file_path)?;

    // Read metadata
    read_metadata(&mut encrypted_file, &mut salt, &mut nonce)?;

    // Init key and decryptor/encryptor
    let (_, stream_decryptor, stream_encryptor) = init_keys(password, &salt, &nonce);

    // Read data
    let mut buffer: Vec<u8> = vec![];
    if let Err(err) = encrypted_file.read_to_end(&mut buffer) {
        eprintln!("Error reading file: {}", err);
    }

    // Decrypting data
    // original_data is raw bytes, used for read and write bytes to file
    // data_string is String for modifications
    let mut original_data = stream_decryptor.decrypt_last(&buffer[..])?;
    let mut data_string = String::from_utf8(original_data)?;

    let mut vec: Vec<String> = data_string.split("\n").map(|s| s.to_string()).collect();
    if let Some(index) = vec.iter().position(|s| s.starts_with(username)) {
        vec.remove(index);
        data_string = vec.join("\n");
    } else {
        println!("Cannot find password with that username.");
    }

    // Write salt and nonce back to file
    encrypted_file.set_len(0)?;
    encrypted_file.write(&salt)?;
    encrypted_file.write(&nonce)?;

    // Encrypting data and write it to file
    original_data = data_string.as_bytes().into();
    let ciphertext = stream_encryptor.encrypt_last(&original_data[..])?;
    encrypted_file.write(&ciphertext)?;

    Ok(())
}
