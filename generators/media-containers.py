#!/usr/bin/env python3
"""Regenerate the media-container audit fixtures using Python and FFmpeg."""

import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]


def encode_vint(value, width):
    return ((1 << (7 * width)) | value).to_bytes(width, "big")


def read_vint(data, offset):
    first = data[offset]
    width = 1
    mask = 0x80
    while not first & mask:
        mask >>= 1
        width += 1
    return int.from_bytes(data[offset:offset + width], "big") & ((1 << (7 * width)) - 1), width


def rewrite_ebml_sizes(data, root_width, document_width):
    size, width = read_vint(data, 4)
    offset = 4 + width
    end = offset + size
    header = bytearray()
    while offset < end:
        _, id_width = read_vint(data, offset)
        identifier = data[offset:offset + id_width]
        offset += id_width
        length, size_width = read_vint(data, offset)
        offset += size_width
        header.extend(identifier)
        header.extend(encode_vint(length, document_width if identifier == b"\x42\x82" else size_width))
        header.extend(data[offset:offset + length])
        offset += length
    return data[:4] + encode_vint(len(header), root_width) + header + data[end:]


def ogg_crc(data):
    value = 0
    for byte in data:
        value ^= byte << 24
        for _ in range(8):
            value = ((value << 1) ^ (0x04C11DB7 if value & 0x80000000 else 0)) & 0xFFFFFFFF
    return value


def extend_opus_header(data):
    """RFC 7845 permits additional header fields for compatible minor versions."""
    output = bytearray()
    offset = 0
    while offset < len(data):
        count = data[offset + 26]
        length = sum(data[offset + 27:offset + 27 + count])
        end = offset + 27 + count + length
        header = bytearray(data[offset:offset + 27])
        laces = data[offset + 27:offset + 27 + count]
        body = data[offset + 27 + count:end]
        if offset == 0:
            body = bytearray(body)
            body[8] = 2  # Compatible minor version with an extended ID header.
            body.extend(bytes(300 - len(body)))
            header[26] = 2
            laces = bytes([255, 45])
        header[14:18] = struct.pack("<I", 1)  # Deterministic stream serial number.
        header[22:26] = bytes(4)
        page = header + laces + body
        page[22:26] = struct.pack("<I", ogg_crc(page))
        output.extend(page)
        offset = end
    return output


def ffmpeg(output, arguments):
    subprocess.run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", *arguments,
                    "-fflags", "+bitexact", "-flags:a", "+bitexact", "-flags:v", "+bitexact", str(output)], check=True)


def main():
    entries = {}

    def record(name, data, generator):
        (ROOT / name).write_bytes(data)
        entries[name] = {"sha256": hashlib.sha256(data).hexdigest(), "generator": generator}

    with tempfile.TemporaryDirectory(prefix="mime-media-fixtures-") as temporary:
        directory = Path(temporary)
        audio = ["-f", "lavfi", "-i", "anullsrc=r=8000:cl=mono", "-t", "0.02"]
        for name, codec, container in [("fixture-minimal.caf", "pcm_s16be", "caf"),
                                       ("fixture-compressed.aifc", "pcm_s16le", "aiff")]:
            path = directory / name
            ffmpeg(path, [*audio, "-c:a", codec, "-f", container])
            record(name, path.read_bytes(), f"FFmpeg generated 20 ms mono silence, {codec}, {container}")

        path = directory / "base.opus"
        ffmpeg(path, ["-f", "lavfi", "-i", "anullsrc=r=48000:cl=mono", "-t", "0.1", "-c:a", "libopus"])
        record("fixture-extended-header.opus", extend_opus_header(path.read_bytes()),
               "FFmpeg libopus silence; compatible minor version 2 ID header extended to 300 bytes; Ogg CRCs recalculated")

        for name, codec, container, root_width, document_width in [
            ("fixture-variable-sizes.mkv", "ffv1", "matroska", 2, 8),
            ("fixture-variable-sizes.webm", "libvpx", "webm", 8, 2),
        ]:
            path = directory / name
            ffmpeg(path, ["-f", "lavfi", "-i", "color=c=black:s=2x2:r=1", "-frames:v", "1",
                          "-c:v", codec, "-f", container])
            record(name, rewrite_ebml_sizes(path.read_bytes(), root_width, document_width),
                   f"FFmpeg {codec} single black frame; EBML root size width {root_width}, DocType size width {document_width}")

    # RFC 4867 defines FT=15 as a complete no-data speech frame with no payload.
    record("fixture-no-data.awb", b"#!AMR-WB\n" + b"\x7C" * 10,
           "RFC 4867 single-channel AMR-WB file containing ten complete no-data frames")
    for name, magic in [("fixture-multichannel.amr", b"#!AMR_MC1.0\n"),
                         ("fixture-multichannel.awb", b"#!AMR-WB_MC1.0\n")]:
        record(name, magic + struct.pack(">I", 2) + b"\x7C" * 20,
               "RFC 4867 two-channel file containing ten complete no-data frame-blocks")

    manifest = ROOT / "signature-audit-fixtures.json"
    audit = json.loads(manifest.read_text())
    audit["fixtures"].update(entries)
    audit["references"].update({
        "ogg": "https://www.rfc-editor.org/rfc/rfc3533.html",
        "opus": "https://www.rfc-editor.org/rfc/rfc7845.html",
        "ebml": "https://www.rfc-editor.org/rfc/rfc8794.html",
        "amr": "https://www.rfc-editor.org/rfc/rfc4867.html",
        "caf": "https://developer.apple.com/library/archive/documentation/MusicAudio/Reference/CAFSpec/CAF_spec/CAF_spec.html",
    })
    manifest.write_text(json.dumps(audit, indent=2) + "\n")
    print(f"Generated {len(entries)} fixtures and updated provenance hashes.")


if __name__ == "__main__":
    main()
