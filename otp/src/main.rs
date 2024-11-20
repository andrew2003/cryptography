mod totp;

use crate::totp::Totp;

fn main() {
    let totp = Totp::new();

    let secret = totp.create_secret(16);
    println!("Secret: {}", secret);

    let code = totp.get_code(secret.as_str(), 0).unwrap();
    println!("Mã OTP: {}", code);

    let is_valid = totp.verify_code(secret.as_str(), &code, 1, 0);
    println!("Mã OTP hợp lệ: {}", is_valid);
}
