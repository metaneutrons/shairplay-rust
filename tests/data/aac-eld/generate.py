#!/usr/bin/env python3
"""Generate the synthetic AAC-ELD access-unit fixture with Apple's encoder."""

from __future__ import annotations

import argparse
import hashlib
import math
import platform
import struct
# The generator invokes only the fixed Apple encoder with internally generated paths.
import subprocess  # nosec B404
import tempfile
import wave
from pathlib import Path


FIXTURE = Path(__file__).with_name("stereo-44100-512.aaceld")
MAGIC = b"RAOP-AAC-ELD\x01"
SAMPLE_RATE = 44_100
CHANNELS = 2
FRAME_SAMPLES = 512
BITRATE = 96_000
SOURCE_ACCESS_UNITS = 24
# Include the priming packet plus four following packets so tests can compare
# stateful decoding and packet reordering in playback order.
PACKET_INDICES = (0, 1, 2, 3, 4)


def synthesize_wave(path: Path) -> None:
    """Write a deterministic two-tone stereo signal with a second harmonic."""
    sample_count = SOURCE_ACCESS_UNITS * FRAME_SAMPLES
    pcm = bytearray()
    for n in range(sample_count):
        time = n / SAMPLE_RATE
        left = 0.55 * math.sin(2 * math.pi * 440 * time) + 0.08 * math.sin(
            2 * math.pi * 880 * time
        )
        right = 0.40 * math.sin(2 * math.pi * 659.25 * time + 0.2) + 0.07 * math.sin(
            2 * math.pi * 1318.5 * time
        )
        pcm.extend(struct.pack("<hh", round(left * 32767), round(right * 32767)))

    with wave.open(str(path), "wb") as output:
        output.setnchannels(CHANNELS)
        output.setsampwidth(2)
        output.setframerate(SAMPLE_RATE)
        output.writeframes(pcm)


def caf_chunks(path: Path) -> dict[bytes, bytes]:
    data = path.read_bytes()
    if data[:8] != b"caff\x00\x01\x00\x00":
        raise ValueError("encoder did not produce a CAF v1 file")
    chunks: dict[bytes, bytes] = {}
    offset = 8
    while offset < len(data):
        if offset + 12 > len(data):
            raise ValueError("truncated CAF chunk header")
        chunk_id = data[offset : offset + 4]
        chunk_size = struct.unpack_from(">q", data, offset + 4)[0]
        if chunk_size < 0 or offset + 12 + chunk_size > len(data):
            raise ValueError(f"invalid CAF chunk size in {chunk_id!r}")
        chunks[chunk_id] = data[offset + 12 : offset + 12 + chunk_size]
        offset += 12 + chunk_size
    return chunks


def packet_lengths(packet_table: bytes) -> list[int]:
    if len(packet_table) < 24:
        raise ValueError("CAF packet table is truncated")
    packet_count, _valid_frames, _priming, _remainder = struct.unpack_from(
        ">qqii", packet_table
    )
    if packet_count <= 0:
        raise ValueError("CAF packet table has no packets")
    offset = 24
    lengths: list[int] = []
    for _ in range(packet_count):
        value = 0
        while True:
            if offset >= len(packet_table):
                raise ValueError("CAF packet table ended inside a packet length")
            byte = packet_table[offset]
            offset += 1
            value = (value << 7) | (byte & 0x7F)
            if byte < 0x80:
                break
        if value <= 0:
            raise ValueError("CAF packet table contains an empty access unit")
        lengths.append(value)
    return lengths


def extract_access_units(caf_path: Path) -> list[bytes]:
    chunks = caf_chunks(caf_path)
    description = chunks[b"desc"]
    sample_rate = struct.unpack_from(">d", description)[0]
    codec = description[8:12]
    frames_per_packet = struct.unpack_from(">I", description, 20)[0]
    if (
        round(sample_rate) != SAMPLE_RATE
        or codec != b"aace"
        or frames_per_packet != FRAME_SAMPLES
        or struct.unpack_from(">I", description, 24)[0] != CHANNELS
    ):
        raise ValueError(
            "afconvert did not encode the expected stereo AAC-ELD format: "
            f"rate={sample_rate}, codec={codec!r}, frames/packet={frames_per_packet}, "
            f"channels={struct.unpack_from('>I', description, 24)[0]}"
        )

    table = chunks[b"pakt"]
    lengths = packet_lengths(table)
    payload = chunks[b"data"]
    if len(payload) < 4:
        raise ValueError("CAF data chunk is missing its edit count")
    packet_data = memoryview(payload)[4:]
    if sum(lengths) != len(packet_data):
        raise ValueError("CAF packet table does not cover its audio data")

    packets: list[bytes] = []
    offset = 0
    for length in lengths:
        packets.append(bytes(packet_data[offset : offset + length]))
        offset += length
    try:
        return [packets[index] for index in PACKET_INDICES]
    except IndexError as exc:
        raise ValueError("afconvert produced too few packets") from exc


def fixture_bytes(units: list[bytes]) -> bytes:
    encoded = bytearray(MAGIC + struct.pack(">H", len(units)))
    for unit in units:
        if len(unit) > 0xFFFF:
            raise ValueError("access unit does not fit in fixture length field")
        encoded.extend(struct.pack(">H", len(unit)))
        encoded.extend(unit)
    return bytes(encoded)


def generate() -> bytes:
    encoder = Path("/usr/bin/afconvert")
    if not encoder.exists():
        raise SystemExit("Apple afconvert is required to regenerate this fixture")
    with tempfile.TemporaryDirectory(prefix="shairplay-aac-eld-") as directory:
        temp = Path(directory)
        input_wave = temp / "synthetic.wav"
        encoded_caf = temp / "encoded.caf"
        synthesize_wave(input_wave)
        # The executable is fixed; both paths are created in our own temporary directory.
        subprocess.run(  # nosec B603
            [
                "/usr/bin/afconvert",
                "-f",
                "caff",
                "-d",
                "aace",
                "-b",
                str(BITRATE),
                "-s",
                "0",
                str(input_wave),
                str(encoded_caf),
            ],
            check=True,
        )
        return fixture_bytes(extract_access_units(encoded_caf))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="regenerate in a temporary directory and compare with the committed fixture",
    )
    parser.add_argument(
        "--output", type=Path, default=FIXTURE, help="fixture path when generating"
    )
    args = parser.parse_args()
    generated = generate()
    digest = hashlib.sha256(generated).hexdigest()
    if args.check:
        try:
            committed = args.output.read_bytes()
        except FileNotFoundError:
            raise SystemExit(f"fixture not found: {args.output}") from None
        committed_digest = hashlib.sha256(committed).hexdigest()
        print(f"generated sha256: {digest}")
        print(f"committed sha256: {committed_digest}")
        if generated != committed:
            raise SystemExit("fixture differs; afconvert output can vary by macOS version")
        print("fixture matches")
        return

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(generated)
    print(f"wrote {args.output} ({len(generated)} bytes)")
    print(f"sha256: {digest}")
    print(f"macOS: {platform.mac_ver()[0] or 'unknown'}")


if __name__ == "__main__":
    main()
