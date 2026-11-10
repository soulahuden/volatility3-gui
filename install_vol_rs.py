#!/usr/bin/env python3
"""Installs vol-rs, the Rust port of Volatility 3, into the bin folder.

The release is pinned and its checksum verified, so the binary that analyses
evidence is always the one that was tested with this GUI.  Only the standard
library is used.  Run it again with --force to replace an installed binary.
"""

import hashlib
import io
import platform
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

VERSION = "1.0.2"
BASE_URL = f"https://github.com/daffainfo/vol-rs/releases/download/v{VERSION}"
BIN_DIR = Path(__file__).resolve().parent / "bin"

# (operating system, machine) -> (release asset suffix, sha256)
RELEASES = {
    ("Linux", "x86_64"): (
        "linux-x86_64.tar.gz",
        "a3436f6042084eeb64a5d46f4933b1787a3d9eee6cef5e6d28570afd52540d10",
    ),
    ("Linux", "aarch64"): (
        "linux-arm64.tar.gz",
        "20a7ebb942ca2b07e716763e6c6c6c35af024ce8f9ce712a7f9aafe401dec133",
    ),
    ("Darwin", "x86_64"): (
        "macos-x86_64.tar.gz",
        "ebf8718e0c7df21a7c1962a3c45252542a198ec9161aeddf84b9e480f4e81f61",
    ),
    ("Darwin", "arm64"): (
        "macos-arm64.tar.gz",
        "fa9237fc7b8a13040683db90a46093dc516f2424740747b34fa743a84be0a128",
    ),
    ("Windows", "amd64"): (
        "windows-x86_64.zip",
        "5414ad0d9ff83fcfc4901b15887ec2fc10f403dcf020f8eab2022c81fa54cea3",
    ),
}


def read_member(archive: bytes, name: str) -> bytes:
    """Reads the file called name from a release archive, ignoring its folder."""
    stream = io.BytesIO(archive)
    if zipfile.is_zipfile(stream):
        with zipfile.ZipFile(stream) as package:
            member = next(
                item for item in package.namelist() if item.endswith("/" + name)
            )
            return package.read(member)
    stream.seek(0)
    with tarfile.open(fileobj=stream, mode="r:gz") as package:
        member = next(
            item for item in package.getmembers() if item.name.endswith("/" + name)
        )
        return package.extractfile(member).read()


def main() -> int:
    system, machine = platform.system(), platform.machine()
    release = RELEASES.get((system, machine.lower()))
    if release is None:
        print(
            f"vol-rs {VERSION} has no release for {system} {machine}", file=sys.stderr
        )
        return 1
    suffix, checksum = release

    binary = "vol-rs.exe" if system == "Windows" else "vol-rs"
    target = BIN_DIR / binary
    if target.exists() and "--force" not in sys.argv[1:]:
        print(f"{target} is already installed")
        return 0

    url = f"{BASE_URL}/vol-rs-v{VERSION}-{suffix}"
    print(f"Downloading {url}")
    try:
        with urllib.request.urlopen(url, timeout=120) as response:
            archive = response.read()
    except OSError as excp:
        print(f"Download failed: {excp}", file=sys.stderr)
        return 1
    actual = hashlib.sha256(archive).hexdigest()
    if actual != checksum:
        print(f"Checksum mismatch: expected {checksum}, got {actual}", file=sys.stderr)
        return 1

    BIN_DIR.mkdir(exist_ok=True)
    partial = target.with_name(target.name + ".part")
    partial.write_bytes(read_member(archive, binary))
    partial.chmod(0o755)
    partial.replace(target)
    print(f"Installed vol-rs {VERSION} to {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
