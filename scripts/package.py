"""Build build/<name>.zip for each Lambda.

Each zip holds trustedhand/ (from src/trustedhand) and handler.py (from
lambdas/<name>/handler.py). The chat zip also holds system_prompt.md.
Zips are reproducible (fixed timestamps, sorted entries) so Terraform only
sees a change when the code changes.

Usage: python scripts/package.py [name ...]   (default: all six)
"""
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "build"
NAMES = ["tools", "interceptor", "hook", "chat", "approval", "notifier"]
EXTRA = {"chat": {"system_prompt.md": ROOT / "infra" / "system_prompt.md"}}
STAMP = (2026, 1, 1, 0, 0, 0)


def add(z: zipfile.ZipFile, arcname: str, data: bytes) -> None:
    info = zipfile.ZipInfo(arcname, STAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    z.writestr(info, data)


def build(name: str) -> Path:
    handler = ROOT / "lambdas" / name / "handler.py"
    if not handler.is_file():
        sys.exit(f"missing {handler.relative_to(ROOT)} (needed for th-{name})")
    pkg = ROOT / "src" / "trustedhand"
    files: dict[str, Path] = {"handler.py": handler}
    for p in sorted(pkg.rglob("*")):
        if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc":
            files[f"trustedhand/{p.relative_to(pkg).as_posix()}"] = p
    for arc, src in EXTRA.get(name, {}).items():
        if not src.is_file():
            sys.exit(f"missing {src.relative_to(ROOT)} (needed for th-{name})")
        files[arc] = src
    BUILD.mkdir(exist_ok=True)
    out = BUILD / f"{name}.zip"
    with zipfile.ZipFile(out, "w") as z:
        for arc in sorted(files):
            add(z, arc, files[arc].read_bytes())
    print(f"built {out.relative_to(ROOT)} ({out.stat().st_size // 1024} KB)")
    return out


if __name__ == "__main__":
    for n in sys.argv[1:] or NAMES:
        if n not in NAMES:
            sys.exit(f"unknown lambda {n}; choose from {NAMES}")
        build(n)
