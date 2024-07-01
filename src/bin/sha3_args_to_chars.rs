use sha3::{Digest, Sha3_256};

const BASE: u8 = 'A' as u8;
fn main() {
    let mut args_buf: String = String::with_capacity(100);
    let args_res = std::io::stdin().read_line(&mut args_buf);
    if let Err(e) = args_res {
        println!("An error has occurred: {}", e);
    }
    let mut hasher = Sha3_256::new();
    let args = args_buf.split_whitespace();
    for arg in args {
        hasher.update(arg);
    }
    let result = &hasher.finalize()[..];

    for byte in result.iter() {
        let c0 = ((byte & 15) + BASE) as char;
        let c1 = ((byte >> 4) + BASE) as char;
        print!("{}{}", c0, c1);
    }
}
