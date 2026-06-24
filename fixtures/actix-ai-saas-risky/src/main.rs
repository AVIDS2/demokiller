use actix_web::{web, App, HttpServer, HttpResponse, post};
use serde::Deserialize;
use std::env;

#[derive(Deserialize)]
struct ChatRequest {
    message: String,
}

#[post("/api/chat")]
async fn chat(body: web::Json<ChatRequest>) -> HttpResponse {
    let api_key = env::var("OPENAI_API_KEY").unwrap_or_default();
    let client = reqwest::Client::new();
    let resp = client.post("https://api.openai.com/v1/chat/completions")
        .bearer_auth(api_key)
        .json(&serde_json::json!({
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": body.message}]
        }))
        .send()
        .await;

    println!("chat completion for: {}", body.message);
    HttpResponse::Ok().json(serde_json::json!({"status": "ok"}))
}

#[post("/api/admin/delete")]
async fn admin_delete(body: web::Json<serde_json::Value>) -> HttpResponse {
    println!("admin delete requested");
    HttpResponse::Ok().json(serde_json::json!({"ok": true}))
}

#[post("/api/stripe/webhook")]
async fn stripe_webhook(body: web::Json<serde_json::Value>) -> HttpResponse {
    println!("webhook received: {:?}", body);
    HttpResponse::Ok().json(serde_json::json!({"received": true}))
}
