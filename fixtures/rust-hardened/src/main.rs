use serde::{Deserialize, Serialize};
use std::fs;
use std::io;

// DK-RS-001 hardened: proper error handling with Result
fn read_config(path: &str) -> io::Result<String> {
    let content = fs::read_to_string(path)?;
    Ok(content)
}

fn parse_user(input: &str) -> Result<User, Box<dyn std::error::Error>> {
    let data: serde_json::Value = serde_json::from_str(input)?;
    let name = data["name"]
        .as_str()
        .ok_or("missing or invalid 'name' field")?
        .to_string();
    let email = data["email"]
        .as_str()
        .ok_or("missing or invalid 'email' field")?
        .to_string();
    Ok(User { name, email })
}

// DK-RS-002 hardened: no unsafe blocks, safe slicing with bounds check
fn safe_byte_access(data: &[u8], index: usize) -> Option<u8> {
    data.get(index).copied()
}

#[derive(Serialize, Deserialize, Debug)]
struct User {
    name: String,
    email: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = read_config("config.toml")?;
    println!("{}", config);

    let user = parse_user(r#"{"name": "test", "email": "test@example.com"}"#)?;
    println!("{}", user.name);

    let data = vec![1, 2, 3];
    match safe_byte_access(&data, 0) {
        Some(val) => println!("{}", val),
        None => println!("index out of bounds"),
    }

    Ok(())
}
