#![allow(dead_code, unused_variables)]

use clap::Parser;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

mod config;
mod crypto;
mod engine;
mod ipsec;
mod l2tp;
mod ppp;
mod tun;

use config::AppConfig;
use engine::VpnEngine;

#[tokio::main]
async fn main() {
    let mut base_config = AppConfig::parse();

    let stdin_line = if base_config.secrets_stdin {
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
        Some(line).filter(|l| !l.trim().is_empty())
    } else {
        None
    };
    if let Err(e) = base_config.load_secrets(stdin_line.as_deref()) {
        eprintln!("[L2TP] Error: {}", e);
        println!("{}", serde_json::json!({ "event": "error", "message": e }));
        std::process::exit(1);
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        eprintln!("\n[L2TP] Received termination signal, shutting down...");
        shutdown_clone.store(true, Ordering::Relaxed);
    });

    eprintln!("[L2TP] Authenticating with user: '{}'", base_config.user);
    let engine = VpnEngine::new(base_config, shutdown);
    let last_err = engine.run().await.err();

    if let Some(e) = last_err {
        eprintln!("[L2TP] Error: {}", e);
        let err_event = serde_json::json!({
            "event": "error",
            "message": e.to_string(),
        });
        println!("{}", err_event);
        std::process::exit(1);
    }
}

