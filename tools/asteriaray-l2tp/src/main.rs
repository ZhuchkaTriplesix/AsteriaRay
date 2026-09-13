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
    let config = AppConfig::parse();

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        eprintln!("\n[L2TP] Received termination signal, shutting down...");
        shutdown_clone.store(true, Ordering::Relaxed);
    });

    let engine = VpnEngine::new(config, shutdown);
    if let Err(e) = engine.run().await {
        eprintln!("[L2TP] Error: {}", e);
        let err_event = serde_json::json!({
            "event": "error",
            "message": e.to_string(),
        });
        println!("{}", err_event);
        std::process::exit(1);
    }
}
