"""Shared environment config for the spec-fuzz experiment tools.

Centralizes the paths that were originally hardcoded to the ieng6 host so the
tools run on any machine (Linux x86_64, macOS arm64, ...). Override via env vars:

  TOCK_FLUX_REPO     path to the patched tock-flux checkout (contains kernel/ + fuzz/)
  SPEC_FUZZ_RESULTS  directory for result JSONs
  CARGO_TARGET_DIR   cargo target dir (default /tmp/fuzz-target; keep on LOCAL disk)

The host target triple is detected from the pinned toolchain, so the built
binaries are located under <CARGO_TARGET_DIR>/<host-triple>/release regardless
of platform.
"""
import os
import subprocess
from pathlib import Path

TOOLCHAIN = "nightly-2025-03-14"

_DEFAULT_REPO = "/home/linux/ieng6/students/985/xuz077/rust/tock-flux"
_DEFAULT_RESULTS = "/home/linux/ieng6/students/985/xuz077/rust/spec-fuzz/results"

REPO = Path(os.environ.get("TOCK_FLUX_REPO", _DEFAULT_REPO))
FUZZ = REPO / "fuzz"
RESULTS = Path(os.environ.get("SPEC_FUZZ_RESULTS", _DEFAULT_RESULTS))
CARGO_TARGET_DIR = os.environ.get("CARGO_TARGET_DIR", "/tmp/fuzz-target")


def host_triple():
    """Return the pinned toolchain's host target triple (e.g. aarch64-apple-darwin)."""
    try:
        out = subprocess.run(["rustc", f"+{TOOLCHAIN}", "-vV"],
                             capture_output=True, text=True).stdout
        for line in out.splitlines():
            if line.startswith("host: "):
                return line[len("host: "):].strip()
    except Exception:
        pass
    return "x86_64-unknown-linux-gnu"


HOST = host_triple()
TOOLCHAIN_BIN = Path.home() / f".rustup/toolchains/{TOOLCHAIN}-{HOST}/lib/rustlib/{HOST}/bin"
RELEASE_DIR = Path(CARGO_TARGET_DIR) / HOST / "release"


def make_env():
    """cargo/libFuzzer environment with PATH, CARGO_TARGET_DIR, and AR set up."""
    env = {
        **os.environ,
        "PATH": f"{Path.home()}/.cargo/bin:{os.environ.get('PATH', '')}",
        "CARGO_TARGET_DIR": CARGO_TARGET_DIR,
    }
    # The original ieng6 host's system `ar` segfaulted (SIGBUS), so it needed the
    # toolchain's llvm-ar; prefer it where present, else fall back to system ar
    # (e.g. macOS, where the system ar works fine).
    if (TOOLCHAIN_BIN / "llvm-ar").exists():
        env["AR"] = str(TOOLCHAIN_BIN / "llvm-ar")
    return env


ENV = make_env()
