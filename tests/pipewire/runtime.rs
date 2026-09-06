use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use super::process::Process;
use serde_json::{Value, json};

pub(super) struct Sender {
    root: PathBuf,
    daemon: Option<Process>,
    player: Option<Process>,
    sink_id: Option<u64>,
}

impl Sender {
    pub(super) async fn start(port: u16, transport: &str, password: bool) -> Self {
        let mut sender = Self::workspace();
        let config = include_str!("pipewire.conf.in")
            .replace("@PORT@", &port.to_string())
            .replace("@TRANSPORT@", transport)
            .replace(
                "@PASSWORD@",
                if password {
                    "raop.password = qualification-only"
                } else {
                    ""
                },
            );
        fs::write(sender.root.join("pipewire.conf"), config).unwrap();
        fs::write(sender.root.join("source.wav"), super::audio::wav()).unwrap();
        sender.daemon = Some(Process::spawn(
            sender
                .command("pipewire", "daemon")
                .arg("-c")
                .arg(sender.root.join("pipewire.conf")),
        ));
        tokio::time::timeout(Duration::from_secs(10), async {
            while !sender.root.join("pipewire-qualification").exists() {
                sender.daemon.as_mut().unwrap().assert_running();
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("PipeWire socket readiness");
        sender
    }

    fn workspace() -> Self {
        let root = std::env::temp_dir().join(format!(
            "shairplay-pw-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir(&root).unwrap();
        let sender = Self {
            root,
            daemon: None,
            player: None,
            sink_id: None,
        };
        fs::set_permissions(&sender.root, fs::Permissions::from_mode(0o700)).unwrap();
        sender
    }

    fn command(&self, binary: &str, log: &str) -> Command {
        let mut command = Command::new(binary);
        command
            .env("XDG_RUNTIME_DIR", &self.root)
            .env("PIPEWIRE_REMOTE", "pipewire-qualification")
            .env("PIPEWIRE_DEBUG", "2")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(File::create(self.root.join(format!("{log}.log"))).unwrap());
        command
    }

    async fn output(&self, binary: &str, args: &[&str]) -> Vec<u8> {
        let path = self.root.join("output.json");
        Process::spawn(
            self.command(binary, binary)
                .args(args)
                .stdout(File::create(&path).unwrap()),
        )
        .finish(5)
        .await;
        assert!(
            fs::metadata(&path).unwrap().len() <= 1024 * 1024,
            "oversized tool output"
        );
        fs::read(path).unwrap()
    }

    pub(super) async fn version() -> Value {
        let sender = Self::workspace();
        let version = String::from_utf8(sender.output("pipewire", &["--version"]).await).unwrap();
        let expected = std::env::var("PIPEWIRE_QUALIFICATION_VERSION").unwrap();
        assert!(
            version
                .lines()
                .any(|s| s == format!("Compiled with libpipewire {expected}"))
        );
        assert!(
            version
                .lines()
                .any(|s| s == format!("Linked with libpipewire {expected}"))
        );
        let packages = sender
            .output(
                "dpkg-query",
                &[
                    "-W",
                    "-f=${Package}=${Version}\n",
                    "libc6",
                    "libssl3",
                    "libsndfile1",
                    "libasound2",
                ],
            )
            .await;
        json!({"version_output": version.trim(),
            "commit": std::env::var("PIPEWIRE_QUALIFICATION_COMMIT").unwrap(),
            "archive_sha256": std::env::var("PIPEWIRE_QUALIFICATION_SHA256").unwrap(),
            "runtime_packages": String::from_utf8(packages).unwrap(),
            "rustc": String::from_utf8(sender.output("rustc", &["--version"]).await).unwrap().trim(),
            "kernel": String::from_utf8(sender.output("uname", &["-sr"]).await).unwrap().trim()})
    }

    async fn nodes(&self) -> [u64; 2] {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let dump: Vec<Value> =
                    serde_json::from_slice(&self.output("pw-dump", &[]).await).unwrap();
                let ids = ["qualification-source", "qualification-raop"].map(|name| {
                    dump.iter()
                        .find(|o| o["info"]["props"]["node.name"] == name)
                        .and_then(|o| o["id"].as_u64())
                });
                if let [Some(source), Some(sink)] = ids {
                    return [source, sink];
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("PipeWire node readiness")
    }

    async fn configure(&self, ids: [u64; 2], expect_audio: bool) {
        for (id, direction) in ids.into_iter().zip(["Output", "Input"]) {
            let params = format!(
                "{{ direction = {direction} mode = dsp format = {{ mediaType = audio mediaSubtype = raw format = F32P rate = 44100 channels = 2 position = [ FL FR ] }} }}"
            );
            Process::spawn(self.command("pw-cli", "configure").args([
                "set-param",
                &id.to_string(),
                "PortConfig",
                &params,
            ]))
            .finish(5)
            .await;
        }
        for channel in ["FL", "FR"] {
            Process::spawn(self.command("pw-link", "link").args([
                &format!("qualification-source:output_{channel}"),
                &format!("qualification-raop:send_{channel}"),
            ]))
            .finish(5)
            .await;
            // A rejected probe destroys the sink immediately after the first link.
            if !expect_audio {
                break;
            }
        }
    }

    pub(super) async fn play(&mut self, expect_audio: bool) {
        assert!(self.player.is_none());
        self.player = Some(Process::spawn(
            self.command("pw-cat", "player")
                .args([
                    "--playback",
                    "--target=0",
                    "--properties={ node.name = qualification-source }",
                ])
                .arg(self.root.join("source.wav")),
        ));
        let ids = self.nodes().await;
        self.sink_id = Some(ids[1]);
        self.configure(ids, expect_audio).await;
    }

    pub(super) async fn finish(&mut self) {
        self.player.as_mut().unwrap().finish(45).await;
        self.player = None;
        Process::spawn(self.command("pw-cli", "suspend").args([
            "send-command",
            &self.sink_id.unwrap().to_string(),
            "Suspend",
            "{}",
        ]))
        .finish(5)
        .await;
    }
}

impl Drop for Sender {
    fn drop(&mut self) {
        self.player = None;
        self.daemon = None;
        if std::thread::panicking() {
            for name in ["daemon", "player", "link", "configure", "suspend"] {
                if let Ok(file) = File::open(self.root.join(format!("{name}.log"))) {
                    let mut log = String::new();
                    let _ = file.take(16384).read_to_string(&mut log);
                    eprintln!("{name}: {log}");
                }
            }
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}
