//! Opt-in live-sender qualification. Never requires PipeWire in normal library tests.
#![cfg(target_os = "linux")]

#[path = "pipewire/audio.rs"]
mod audio;
#[path = "pipewire/process.rs"]
mod process;
#[path = "pipewire/runtime.rs"]
mod runtime;
#[path = "pipewire/wire.rs"]
mod wire;

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use sha2::{Digest, Sha256};
use shairplay::{BindConfig, RaopServer};

async fn receiver(enabled: bool, password: bool, capture: Arc<audio::Capture>) -> RaopServer {
    let builder = RaopServer::builder()
        .name("PipeWire Qualification")
        .hwaddr([0x02, 0x11, 0x22, 0x33, 0x44, 0x55])
        .bind(
            BindConfig::new()
                .addrs(["127.0.0.1".parse().unwrap()])
                .port(0),
        )
        .password(if password { "qualification-only" } else { "" });
    #[cfg(feature = "ap2")]
    let builder = builder.mode(shairplay::AirPlayMode::AirPlay1);
    #[cfg(feature = "pipewire-auth-setup-compat")]
    let builder = builder.pipewire_auth_setup_compat(enabled);
    #[cfg(not(feature = "pipewire-auth-setup-compat"))]
    assert!(!enabled);
    let mut server = builder.build(capture).unwrap();
    server.start().await.unwrap();
    server
}

async fn scenario(enabled: bool, password: bool, transport: &str) -> serde_json::Value {
    eprintln!("PipeWire scenario: enabled={enabled}, password={password}, transport={transport}");
    let capture = Arc::new(audio::Capture::default());
    let mut receiver = receiver(enabled, password, capture.clone()).await;
    let before = receiver.service_info();
    let proxy = wire::Proxy::start(before.port).await;
    let mut sender = runtime::Sender::start(proxy.port, transport, password).await;
    let expected = if password {
        401
    } else if enabled {
        200
    } else {
        404
    };
    let mut audio_reports = Vec::new();
    for round in 0..if expected == 200 { 2 } else { 1 } {
        let start = proxy.events().len();
        sender.play(expected == 200).await;
        proxy.wait_for(start, "POST /auth-setup", expected).await;
        if expected == 200 {
            audio_reports.push(playback(&mut sender, &proxy, &capture, start, round).await);
        } else {
            proxy.wait_closed().await;
            assert!(capture.sessions.lock().unwrap().is_empty());
        }
        wire::verify(&proxy.events()[start..], expected);
    }
    assert_eq!(receiver.service_info().raop_txt, before.raop_txt);
    assert_eq!(receiver.service_info().airplay_txt, before.airplay_txt);
    let events = proxy.events();
    drop(sender);
    drop(proxy);
    receiver.stop().await;
    json!({"runtime_enabled": enabled, "password_protected": password,
        "transport": transport, "expected_probe_status": expected,
        "exchanges": events, "audio": audio_reports, "discovery_unchanged": true})
}

async fn playback(
    sender: &mut runtime::Sender,
    proxy: &wire::Proxy,
    capture: &audio::Capture,
    start: usize,
    round: usize,
) -> serde_json::Value {
    sender.finish().await;
    proxy.wait_for(start, "TEARDOWN", 200).await;
    capture.wait_stopped(round + 1).await;
    let report = capture.verify(round);
    eprintln!("audio round {} result: {report}", round + 1);
    report
}

#[tokio::test]
#[ignore = "requires the isolated, pinned PipeWire environment in scripts/pipewire"]
async fn real_pipewire_auth_setup_qualification() {
    tokio::time::timeout(Duration::from_secs(180), async {
        let version = runtime::Sender::version().await;
        let mut scenarios = Vec::new();
        scenarios.push(scenario(false, false, "udp").await);
        #[cfg(feature = "pipewire-auth-setup-compat")]
        {
            scenarios.push(scenario(true, true, "udp").await);
            let transport =
                std::env::var("QUALIFICATION_TRANSPORT").unwrap_or_else(|_| "udp".into());
            assert!(["udp", "tcp"].contains(&transport.as_str()));
            scenarios.push(scenario(true, false, &transport).await);
        }
        write_report(version, scenarios);
    })
    .await
    .expect("live PipeWire qualification deadline");
}

fn write_report(version: serde_json::Value, scenarios: Vec<serde_json::Value>) {
    let passed = scenarios.iter().all(|scenario| {
        scenario["audio"]
            .as_array()
            .unwrap()
            .iter()
            .all(|audio| audio["exact_payload"] == true)
    });
    let report = json!({"schema_version": 2, "pipewire": version, "passed": passed,
            "source_wav_sha256": hex::encode(Sha256::digest(audio::wav())),
            "sender_config_sha256": hex::encode(Sha256::digest(include_bytes!("pipewire/pipewire.conf.in"))),
            "receiver_revision": std::env::var("QUALIFICATION_REVISION").unwrap(),
            "working_tree_dirty": std::env::var("QUALIFICATION_DIRTY").unwrap() == "true",
            "container_image": std::env::var("QUALIFICATION_IMAGE").unwrap(),
            "debug_assertions": cfg!(debug_assertions),
            "architecture": std::env::consts::ARCH,
            "compatibility_feature": cfg!(feature = "pipewire-auth-setup-compat"),
            "ap2_feature": cfg!(feature = "ap2"), "scenarios": scenarios});
    let bytes = serde_json::to_vec_pretty(&report).unwrap();
    println!("{}", std::str::from_utf8(&bytes).unwrap());
    if let Ok(path) = std::env::var("QUALIFICATION_REPORT") {
        std::fs::write(path, bytes).unwrap();
    }
    assert!(
        passed,
        "live audio qualification failed; see sanitized JSON evidence"
    );
}
