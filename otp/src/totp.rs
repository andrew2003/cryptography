use error::Error;
use hmac_sha1::hmac_sha1;
use rand::random;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{error, fmt};

const SECRET_MAX_LEN: usize = 128;
const SECRET_MIN_LEN: usize = 16;

#[derive(Debug)]
pub enum GAError {
    Error(&'static str),
}

impl Error for GAError {
    fn description(&self) -> &str {
        match *self {
            GAError::Error(description) => description,
        }
    }
}

impl fmt::Display for GAError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            GAError::Error(desc) => f.write_str(desc),
        }
    }
}

/// A list of all usable characters in base32.
const ALPHABET: [char; 33] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '2', '3', '4', '5', '6', '7', '=',
];

#[derive(Debug)]
pub struct Totp {
    code_len: usize,
}

impl Default for Totp {
    fn default() -> Self {
        Self { code_len: 6 }
    }
}

impl Totp {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create_secret(&self, length: u8) -> String {
        let mut sk = Vec::<char>::new();
        let mut index: usize;

        for _ in 0..length {
            index = (random::<u8>() & 0x1F) as usize;
            sk.push(ALPHABET[index]);
        }
        sk.into_iter().collect()
    }

    pub fn get_code(&self, secret: &str, times_slice: u64) -> Result<String, GAError> {
        if secret.len() < SECRET_MIN_LEN || secret.len() > SECRET_MAX_LEN {
            return Err(GAError::Error(
                "bad secret length. must be less than 128 and more than 16, recommend 32",
            ));
        }

        let message = if times_slice == 0 {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                / 30
        } else {
            times_slice
        };
        let key = Self::base32_decode(secret)?;
        let msg_bytes = message.to_be_bytes();
        let hash = hmac_sha1(&key, &msg_bytes);
        let offset = hash[hash.len() - 1] & 0x0F;

        let mut truncated_hash: [u8; 4] = Default::default();

        truncated_hash.copy_from_slice(&hash[offset as usize..(offset + 4) as usize]);
        let mut code = i32::from_be_bytes(truncated_hash);
        code &= 0x7FFFFFFF;
        code %= 1_000_000;
        let mut code_str = code.to_string();
        for i in 0..(self.code_len - code_str.len()) {
            code_str.insert(i, '0');
        }
        Ok(code_str)
    }

    pub fn verify_code(&self, secret: &str, code: &str, discrepancy: u64, time_slice: u64) -> bool {
        if code.len() != self.code_len {
            return false;
        }
        let curr_time_slice = if time_slice == 0 {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                / 30
        } else {
            time_slice
        };
        let start_time = curr_time_slice.saturating_sub(discrepancy);
        let end_time = curr_time_slice.saturating_add(discrepancy + 1);
        for _time_slice in start_time..end_time {
            if let Ok(c) = self.get_code(secret, _time_slice) {
                if code == c {
                    return true;
                }
            }
        }
        false
    }
    pub fn base32_decode(secret: &str) -> Result<Vec<u8>, GAError> {
        match base32::decode(base32::Alphabet::Rfc4648 { padding: true }, secret) {
            Some(_decode_str) => Ok(_decode_str),
            _ => Err(GAError::Error("secret must be base32 decodeable.")),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::totp::Totp;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_otp_no_delay() {
        let totp = Totp::new();

        let secret = totp.create_secret(128);
        let code = totp.get_code(secret.as_str(), 0).unwrap();
        let is_valid = totp.verify_code(secret.as_str(), &code, 1, 0);
        assert_eq!(is_valid, true)
    }

    #[test]
    fn test_otp_with_delay() {
        let totp = Totp::new();

        let secret = totp.create_secret(128);
        let code = totp.get_code(secret.as_str(), 0).unwrap();

        println!("Start sleeping...");
        thread::sleep(Duration::from_secs(60));
        let is_valid = totp.verify_code(secret.as_str(), &code, 1, 0);
        assert_eq!(is_valid, false)
    }
}
