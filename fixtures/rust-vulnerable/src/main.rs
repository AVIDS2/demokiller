use serde::{Deserialize, Serialize};
use std::fs;

// DK-RS-001: unwrap abuse in production code
fn read_config(path: &str) -> String {
    // unwrap() panics on error instead of proper error handling
    let content = fs::read_to_string(path).unwrap();
    content.trim().to_string().parse().unwrap()
}

fn parse_user(input: &str) -> User {
    // Multiple unwrap() calls — any could panic
    let data: serde_json::Value = serde_json::from_str(input).unwrap();
    let name = data["name"].as_str().unwrap().to_string();
    let email = data["email"].as_str().unwrap().to_string();
    User { name, email }
}

// DK-RS-002: unsafe block usage
fn dangerous_pointer_operation(data: &[u8]) -> u8 {
    unsafe {
        let ptr = data.as_ptr();
        *ptr.add(100) // Out of bounds — undefined behavior
    }
}

#[derive(Serialize, Deserialize)]
struct User {
    name: String,
    email: String,
}

fn main() {
    let config = read_config("config.toml");
    let port: u16 = config.parse().unwrap();
    println!("port: {}", port);

    let user = parse_user(r#"{"name": "test", "email": "test@example.com"}"#);
    println!("{:?}", user.name);

    let data = vec![1, 2, 3];
    let val = dangerous_pointer_operation(&data);
    println!("{}", val);
}
