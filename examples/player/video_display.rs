//! Video display for the example app — decodes H.264 NAL units and renders to a window.

use minifb::{Window, WindowOptions};
use openh264::decoder::Decoder;
use openh264::formats::YUVSource;
use shairplay::raop::video::{PacketKind, VideoHandler, VideoPacket, VideoSession};
use std::sync::{Arc, Mutex};

/// Shared frame buffer between the video session (producer) and the window loop (consumer).
pub struct FrameBuffer {
    /// RGBA pixel data.
    pixels: Vec<u32>,
    width: usize,
    height: usize,
    dirty: bool,
}

/// Video handler that creates display sessions.
pub struct DisplayVideoHandler {
    frame: Arc<Mutex<FrameBuffer>>,
}

impl DisplayVideoHandler {
    pub fn new() -> Self {
        let frame = Arc::new(Mutex::new(FrameBuffer {
            pixels: Vec::new(),
            width: 0,
            height: 0,
            dirty: false,
        }));

        Self { frame }
    }

    /// Returns a clone of the frame buffer for the window loop.
    /// Call `run_window` with this on the main thread (required on macOS).
    pub fn frame_buffer(&self) -> Arc<Mutex<FrameBuffer>> {
        self.frame.clone()
    }
}

impl VideoHandler for DisplayVideoHandler {
    fn video_init(&self) -> Box<dyn VideoSession> {
        eprintln!("📺 Video stream started");
        Box::new(DisplayVideoSession {
            decoder: Decoder::new().expect("failed to create H.264 decoder"),
            frame: self.frame.clone(),
            sps_pps: Vec::new(),
        })
    }
}

/// Per-stream video session that decodes H.264 and writes to the shared frame buffer.
struct DisplayVideoSession {
    decoder: Decoder,
    frame: Arc<Mutex<FrameBuffer>>,
    /// Cached SPS/PPS NAL units from AvcC config.
    sps_pps: Vec<u8>,
}

impl VideoSession for DisplayVideoSession {
    fn on_video(&mut self, packet: VideoPacket) {
        match packet.kind {
            PacketKind::AvcC => {
                // Parse AvcC box to extract SPS/PPS NAL units
                self.sps_pps = parse_avcc(&packet.payload);
                if !self.sps_pps.is_empty() {
                    // Feed SPS/PPS to decoder
                    let _ = self.decoder.decode(&self.sps_pps);
                    eprintln!("📺 H.264 config received ({} bytes)", self.sps_pps.len());
                }
            }
            PacketKind::Payload => {
                // Payload contains length-prefixed NAL units (4-byte big-endian length + NAL data)
                let annexb = length_to_annexb(&packet.payload);
                if annexb.is_empty() {
                    return;
                }

                // Prepend SPS/PPS before IDR keyframes so the decoder can initialize
                let nal_type = annexb.get(4).map(|b| b & 0x1F).unwrap_or(0);
                let decode_buf = if nal_type == 5 && !self.sps_pps.is_empty() {
                    let mut buf = self.sps_pps.clone();
                    buf.extend_from_slice(&annexb);
                    buf
                } else {
                    annexb
                };

                match self.decoder.decode(&decode_buf) {
                    Ok(Some(yuv)) => {
                        let (w, h) = yuv.dimensions();
                        let buf_size = w * h * 3;
                        let mut rgb = vec![0u8; buf_size];
                        // write_rgb8 can panic on padded frames — catch it
                        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            yuv.write_rgb8(&mut rgb);
                        }))
                        .is_err()
                        {
                            return;
                        }

                        // Convert RGB → u32 pixels for minifb
                        let pixels: Vec<u32> = rgb
                            .chunks_exact(3)
                            .map(|c| ((c[0] as u32) << 16) | ((c[1] as u32) << 8) | c[2] as u32)
                            .collect();

                        let mut fb = self.frame.lock().unwrap();
                        fb.width = w;
                        fb.height = h;
                        fb.pixels = pixels;
                        fb.dirty = true;
                    }
                    Ok(None) => {} // buffering
                    Err(e) => eprintln!("📺 H.264 decode error: {e}"),
                }
            }
            _ => {}
        }
    }
}

impl Drop for DisplayVideoSession {
    fn drop(&mut self) {
        eprintln!("📺 Video stream ended");
    }
}

/// Parse an AvcC (H.264 Decoder Configuration Record) into Annex B NAL units.
/// Returns concatenated [0x00 0x00 0x00 0x01 <NAL>] for each SPS and PPS.
fn parse_avcc(data: &[u8]) -> Vec<u8> {
    if data.len() < 8 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut pos = 5; // skip version, profile, compat, level, length_size

    // SPS
    let num_sps = (data.get(pos).copied().unwrap_or(0) & 0x1F) as usize;
    pos += 1;
    for _ in 0..num_sps {
        if pos + 2 > data.len() {
            break;
        }
        let len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if pos + len > data.len() {
            break;
        }
        out.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        out.extend_from_slice(&data[pos..pos + len]);
        pos += len;
    }

    // PPS
    let num_pps = data.get(pos).copied().unwrap_or(0) as usize;
    pos += 1;
    for _ in 0..num_pps {
        if pos + 2 > data.len() {
            break;
        }
        let len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if pos + len > data.len() {
            break;
        }
        out.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        out.extend_from_slice(&data[pos..pos + len]);
        pos += len;
    }

    out
}

/// Convert length-prefixed NAL units (AirPlay format) to Annex B start codes.
fn length_to_annexb(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut pos = 0;
    while pos + 4 <= data.len() {
        let len = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if pos + len > data.len() {
            break;
        }
        out.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        out.extend_from_slice(&data[pos..pos + len]);
        pos += len;
    }
    out
}

/// Window rendering loop — must run on the main thread on macOS.
pub fn run_window(frame: Arc<Mutex<FrameBuffer>>) {
    let mut window: Option<Window> = None;
    let mut win_w = 0usize;
    let mut win_h = 0usize;

    loop {
        let (pixels, w, h) = {
            let mut fb = frame.lock().unwrap();
            if !fb.dirty || fb.width == 0 {
                drop(fb);
                std::thread::sleep(std::time::Duration::from_millis(5));
                if let Some(ref mut win) = window {
                    if !win.is_open() {
                        break;
                    }
                    win.update();
                }
                continue;
            }
            fb.dirty = false;
            (fb.pixels.clone(), fb.width, fb.height)
        };

        // Create or resize window
        if window.is_none() || w != win_w || h != win_h {
            window = Window::new(
                "AirPlay Screen Mirror",
                w,
                h,
                WindowOptions {
                    resize: true,
                    ..WindowOptions::default()
                },
            )
            .ok();
            win_w = w;
            win_h = h;
            eprintln!("📺 Video window: {}x{}", w, h);
        }

        if let Some(ref mut win) = window {
            if !win.is_open() {
                break;
            }
            let _ = win.update_with_buffer(&pixels, w, h);
        }
    }
}
