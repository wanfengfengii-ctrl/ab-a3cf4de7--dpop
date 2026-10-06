"""One-shot demo key generation.

Writes an ES256 issuer key pair and a demo partner DPoP key pair. Public keys
go to the public directory (mounted read-only into the app), private keys to
the private directory (mounted only into clients such as the verify service).
Idempotent: existing keys are left untouched so restarts do not rotate keys.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path

from client import mint

KEY_NAMES = ("issuer_es256", "dpop_es256")


def _write(path: Path, content: str, mode: int) -> None:
    path.write_text(content)
    os.chmod(path, mode)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="generate demo ES256 keys")
    parser.add_argument("--public-dir", required=True)
    parser.add_argument("--private-dir", required=True)
    args = parser.parse_args(argv)

    public_dir = Path(args.public_dir)
    private_dir = Path(args.private_dir)
    public_dir.mkdir(parents=True, exist_ok=True)
    private_dir.mkdir(parents=True, exist_ok=True)

    created: list[str] = []
    for name in KEY_NAMES:
        private_path = private_dir / f"{name}_private.pem"
        if private_path.exists():
            continue
        key = mint.generate_ec_key()
        public_pem = mint.public_key_to_pem(key.public_key())
        _write(private_path, mint.private_key_to_pem(key), 0o600)
        _write(private_dir / f"{name}_public.pem", public_pem, 0o644)
        _write(public_dir / f"{name}_public.pem", public_pem, 0o644)
        created.append(name)

    print("keygen: generated " + ", ".join(created) if created else "keygen: keys already present, nothing to do")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
