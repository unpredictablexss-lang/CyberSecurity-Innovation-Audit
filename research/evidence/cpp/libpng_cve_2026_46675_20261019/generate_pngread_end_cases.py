"""Generate bounded local PNG controls for the GHSA-qvg3-h654-xq3j path."""

from __future__ import annotations

import binascii
import hashlib
import json
import struct
import zlib
from pathlib import Path


HERE = Path(__file__).resolve().parent


def chunk(kind: bytes, data: bytes) -> bytes:
    body = kind + data
    return struct.pack(">I", len(data)) + body + struct.pack(">I", binascii.crc32(body) & 0xFFFFFFFF)


def png(ztxt_data: bytes) -> bytes:
    signature = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0)
    # One-byte grayscale scanline (filter byte + pixel).
    idat = zlib.compress(b"\x00\x7f")
    return b"".join((
        signature,
        chunk(b"IHDR", ihdr),
        chunk(b"zTXt", b"Key\x00\x00" + ztxt_data),
        chunk(b"tEXt", b"LongText\x00" + b"A" * 4096),
        chunk(b"IDAT", idat),
        chunk(b"IEND", b""),
    ))


cases = {
    "trigger-invalid-zlib-window.png": png(bytes((0xF8, 0)) + bytes(range(256))),
    "control-valid-zlib-stream.png": png(zlib.compress(b"valid compressed text")),
}
report = {}
for name, data in cases.items():
    path = HERE / name
    path.write_bytes(data)
    report[name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
(HERE / "generated-pngs.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(json.dumps(report, indent=2))
