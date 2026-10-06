"""Generate deterministic sample calibration-evidence bundles.

Usage: python scripts/gen_bundles.py [output_dir] [count]
Prints the BUNDLE_<n>_SHA256 values to paste into docker-compose.yml.
"""
import hashlib
import sys
from pathlib import Path


def bundle_bytes(n: int, size: int = 4096) -> bytes:
    out = bytearray(f"CALIBRATION-EVIDENCE-BUNDLE/{n}\n".encode())
    block = hashlib.sha256(f"calibration-lab-bundle-{n}".encode()).digest()
    while len(out) < size:
        block = hashlib.sha256(block).digest()
        out += block
    return bytes(out[:size])


def main() -> None:
    out_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "bundles")
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 3
    out_dir.mkdir(parents=True, exist_ok=True)
    for n in range(1, count + 1):
        data = bundle_bytes(n)
        path = out_dir / f"bundle-{n}.bin"
        path.write_bytes(data)
        print(f"BUNDLE_{n}_SHA256={hashlib.sha256(data).hexdigest()}  # {path}")


if __name__ == "__main__":
    main()
