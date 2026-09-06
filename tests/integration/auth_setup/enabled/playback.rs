use std::sync::Arc;

use shairplay::{AudioCodec, AudioFormat, AudioHandler, AudioSession};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

use super::*;

#[derive(Debug)]
enum Event {
    Init(AudioFormat),
    Samples(Vec<f32>),
    Stopped,
}

struct Capture(UnboundedSender<Event>);

impl AudioHandler for Capture {
    fn audio_init(&self, format: AudioFormat) -> Box<dyn AudioSession> {
        self.0.send(Event::Init(format)).unwrap();
        Box::new(Capture(self.0.clone()))
    }
}

impl AudioSession for Capture {
    fn audio_process(&mut self, samples: &[f32]) {
        self.0.send(Event::Samples(samples.to_vec())).unwrap();
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        let _ = self.0.send(Event::Stopped);
    }
}

async fn next_event(events: &mut UnboundedReceiver<Event>) -> Event {
    tokio::time::timeout(IO_TIMEOUT, events.recv())
        .await
        .unwrap()
        .unwrap()
}

enum AudioTransport {
    Udp(UdpSocket),
    Tcp(TcpStream),
}

impl AudioTransport {
    async fn connect(tcp: bool, port: u16) -> Self {
        if tcp {
            Self::Tcp(
                tokio::time::timeout(IO_TIMEOUT, TcpStream::connect(("127.0.0.1", port)))
                    .await
                    .unwrap()
                    .unwrap(),
            )
        } else {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            socket.connect(("127.0.0.1", port)).await.unwrap();
            Self::Udp(socket)
        }
    }

    async fn send(&mut self, sequence: u16, samples: &[i16]) {
        let mut packet = vec![0x80, 0x60];
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(&(u32::from(sequence) * 3).to_be_bytes());
        packet.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        for sample in samples {
            packet.extend_from_slice(&sample.to_be_bytes());
        }
        tokio::time::timeout(IO_TIMEOUT, async {
            match self {
                Self::Udp(socket) => assert_eq!(socket.send(&packet).await.unwrap(), packet.len()),
                Self::Tcp(stream) => {
                    let mut framed = vec![0x24, 0];
                    framed.extend_from_slice(&u16::try_from(packet.len()).unwrap().to_be_bytes());
                    framed.extend_from_slice(&packet);
                    stream.write_all(&framed).await.unwrap();
                }
            }
        })
        .await
        .unwrap();
    }
}

async fn start_audio(client: &mut BufReader<TcpStream>, tcp: bool) -> AudioTransport {
    let sdp = concat!(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=PipeWire simulated sender\r\n",
        "c=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 0 RTP/AVP 96\r\na=rtpmap:96 L16/44100/2\r\n",
    );
    write(
        client,
        &wire(
            "ANNOUNCE",
            "/stream",
            &format!(
                "Content-Type: application/sdp\r\nContent-Length: {}\r\n",
                sdp.len()
            ),
            sdp.as_bytes(),
        ),
    )
    .await;
    read_response(client).await.assert_empty(200, "1");
    let transport = if tcp {
        "RTP/AVP/TCP;unicast;interleaved=0-1;mode=record"
    } else {
        "RTP/AVP/UDP;unicast;mode=record;control_port=0;timing_port=0"
    };
    write(
        client,
        &wire(
            "SETUP",
            "/stream",
            &format!("Transport: {transport}\r\n"),
            &[],
        ),
    )
    .await;
    let setup = read_response(client).await;
    setup.assert_empty(200, "1");
    let port = setup
        .header("Transport")
        .unwrap()
        .split(';')
        .find_map(|item| item.strip_prefix("server_port="))
        .unwrap()
        .parse::<u16>()
        .unwrap();
    write(client, &wire("RECORD", "/stream", "", &[])).await;
    read_response(client).await.assert_empty(200, "1");
    AudioTransport::connect(tcp, port).await
}

async fn play_session(port: u16, tcp: bool, events: &mut UnboundedReceiver<Event>) {
    let mut client = connect(port).await;
    write(&mut client, &request(1, None)).await;
    let probe_reply = read_response(&mut client).await;
    probe_reply.assert_empty(200, "1");
    assert_eq!(probe_reply.header("Content-Length"), Some("0"));
    assert!(
        events.try_recv().is_err(),
        "probe must not start an audio session"
    );
    let mut audio = start_audio(&mut client, tcp).await;
    let Event::Init(format) = next_event(events).await else {
        panic!("expected audio init")
    };
    assert_eq!(
        (
            format.codec,
            format.sample_rate,
            format.channels,
            format.bits
        ),
        (AudioCodec::Pcm, 44100, 2, 32)
    );
    let samples = [i16::MIN, -16384, 0, 16384, i16::MAX, -1];
    for sequence in [10, 11] {
        audio.send(sequence, &samples).await;
        let Event::Samples(actual) = next_event(events).await else {
            panic!("expected decoded PCM")
        };
        let expected: Vec<f32> = samples
            .iter()
            .map(|sample| f32::from(*sample) / 32768.0)
            .collect();
        assert_eq!(actual, expected);
        // Repeating the probe must leave an already playing stream unchanged.
        write(&mut client, &request(2, None)).await;
        read_response(&mut client).await.assert_empty(200, "2");
    }
    write(&mut client, &wire("TEARDOWN", "/stream", "", &[])).await;
    read_response(&mut client).await.assert_empty(200, "1");
    assert_closed(&mut client).await;
    assert!(matches!(next_event(events).await, Event::Stopped));
}

#[tokio::test]
#[serial]
async fn simulated_sender_delivers_pcm_over_udp_and_tcp_after_probe_and_reconnect() {
    let (sender, mut events) = unbounded_channel();
    let mut server = builder().build(Arc::new(Capture(sender))).unwrap();
    server.start().await.unwrap();
    let before = server.service_info();
    for tcp in [false, true, false, true] {
        play_session(before.port, tcp, &mut events).await;
    }
    assert_eq!(server.service_info().raop_txt, before.raop_txt);
    assert_eq!(server.service_info().airplay_txt, before.airplay_txt);
    server.stop().await;
}
