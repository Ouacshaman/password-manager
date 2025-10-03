// Argon2 package is used to generate a master key

use argon2::{self, Argon2};
use std;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let arg_entry_pw = &args[1];
    let b_pw: &[u8] = arg_entry_pw.as_bytes();
    let salt = b"testing password encryption";

    let mut output_key_material = [0u8; 32];
    let _ = Argon2::default().hash_password_into(b_pw, salt, &mut output_key_material);

    println!("{:?}", output_key_material);
}
