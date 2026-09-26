#!/usr/bin/env python3
"""releasecheck -- preflight checks for a release folder.

Point it at a folder, get one verdict: PASS or FAIL, with reasons.

Design rules
    * standard library only; an external validator (for example EPUBCheck) is optional
    * no network unless --online is given
    * nothing is uploaded, nothing is sent anywhere
    * every report ends with "what this does not prove"

Usage
    python3 releasecheck.py check ./dist
    python3 releasecheck.py check ./dist -m releasecheck.json --json report.json --md report.md

Exit codes
    0 = PASS, 1 = FAIL, 2 = bad usage
"""
from __future__ import annotations

import argparse
import datetime as _dt
import fnmatch
import hashlib
import json
import re
import struct
import sys
import zipfile
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

TOOL = "releasecheck"
VERSION = "0.1.1"

SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules", ".cache", ".idea"}
TEXT_SUFFIXES = {
    ".md", ".markdown", ".txt", ".html", ".htm", ".xhtml", ".xml", ".opf", ".ncx",
    ".json", ".csv", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".css", ".js",
    ".py", ".sh", ".tex", ".rtf",
}
ARCHIVE_SUFFIXES = {".zip", ".epub", ".docx", ".xlsx", ".pptx", ".odt", ".jar"}
JUNK_NAMES = {".DS_Store", "Thumbs.db", "desktop.ini", ".localized"}
JUNK_PREFIXES = ("__MACOSX/", "._", "~$")
RAW_SCAN_LIMIT = 32 * 1024 * 1024

SECRET_PATTERNS = [
    ("private-key-block", re.compile(rb"-----BEGIN (?:OPENSSH |RSA |EC |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----")),
    ("github-token", re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{30,}")),
    ("github-fine-grained-token", re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{50,}")),
    ("aws-access-key-id", re.compile(rb"\bAKIA[0-9A-Z]{16}\b")),
    ("slack-token", re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("provider-key", re.compile(rb"\bsk-[A-Za-z0-9]{32,}\b")),
    ("assigned-secret", re.compile(
        rb"(?i)\b(?:api[_-]?key|apikey|secret|client[_-]?secret|password|passwd|token)"
        rb"\s*[:=]\s*[\"'][A-Za-z0-9_\-+/=]{16,}[\"']")),
]

PLACEHOLDER_PATTERNS = [
    ("todo", re.compile(rb"\bTODO\b|\bFIXME\b")),
    ("to-come", re.compile(rb"\bTBD\b|\bTK\b")),
    ("lorem-ipsum", re.compile(rb"(?i)lorem ipsum")),
    ("placeholder-word", re.compile(rb"\bREPLACE[_-]?ME\b|\bPLACEHOLDER\b|\bXXX\b")),
    ("unfilled-template", re.compile(rb"\{\{[^}\n]{1,80}\}\}|\[\[[^\]\n]{1,80}\]\]")),
]

LIMITS = [
    "It does not prove that a store, a printer or a client will accept the files.",
    "It does not prove that the content is true, legally safe, or free of third-party rights.",
    "It does not read the Git history: a secret committed and later deleted still lives there.",
    "It does not prove that a human read the result, or that anyone wants it.",
]


# ---------------------------------------------------------------- helpers

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def mask(match: bytes) -> str:
    """Never print a secret. Keeps the shape, hides the value."""
    text = match.decode("utf-8", "replace")
    if len(text) <= 8:
        return text[0] + "***"
    return f"{text[:4]}***{text[-2:]}"


def find_line(data: bytes, position: int) -> int:
    return data[:position].count(b"\n") + 1


def text_members(zf: zipfile.ZipFile):
    for info in zf.infolist():
        if info.is_dir():
            continue
        if Path(info.filename).suffix.lower() in TEXT_SUFFIXES and info.file_size <= 5 << 20:
            yield info


def image_size(data: bytes):
    """(width, height) for PNG/JPEG/GIF without any dependency."""
    if data[:8] == b"\x89PNG\r\n\x1a\n" and data[12:16] == b"IHDR":
        w, h = struct.unpack(">II", data[16:24])
        return w, h
    if data[:6] in (b"GIF87a", b"GIF89a"):
        w, h = struct.unpack("<HH", data[6:10])
        return w, h
    if data[:2] == b"\xff\xd8":
        i = 2
        while i + 9 < len(data):
            if data[i] != 0xFF:
                i += 1
                continue
            marker = data[i + 1]
            if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
                i += 2
                continue
            if i + 4 > len(data):
                break
            length = struct.unpack(">H", data[i + 2:i + 4])[0]
            if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB):
                h, w = struct.unpack(">HH", data[i + 5:i + 9])
                return w, h
            i += 2 + length
    return None


def pdf_info(data: bytes) -> dict:
    return {
        "header": data[:5] == b"%PDF-",
        "eof": b"%%EOF" in data[-2048:],
        "encrypted": b"/Encrypt" in data[:1 << 20],
        "pages_approx": len(re.findall(rb"/Type\s*/Page(?![s])", data)),
    }


def f(status: str, check: str, message: str, path: str | None = None) -> dict:
    return {"status": status, "check": check, "message": message, "path": path}


# ---------------------------------------------------------------- context

class Context:
    def __init__(self, folder: Path, manifest: dict, online: bool):
        self.folder = folder
        self.manifest = manifest
        self.online = bool(online or manifest.get("online_links"))
        self.artifacts = list(manifest.get("artifacts") or [])
        self.forbid = list(manifest.get("forbid") or [])
        self.hashes_name = manifest.get("hashes", "SHA256SUMS.txt")
        self.images = list(manifest.get("images") or [])
        self.ignore = set(manifest.get("ignore") or []) | {"releasecheck.json", "releasecheck-report.json",
                                                           "releasecheck-report.md", "SHA256SUMS.txt"}
        self.files: list[Path] = []
        for path in sorted(folder.rglob("*")):
            if path.is_dir() or any(part in SKIP_DIRS for part in path.parts):
                continue
            if path.name in self.ignore:
                continue
            self.files.append(path)

    def rel(self, path: Path) -> str:
        return str(path.relative_to(self.folder))

    def matches_artifacts(self, path: Path) -> bool:
        if not self.artifacts:
            return True
        rel = self.rel(path)
        return any(fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(path.name, pattern)
                   for pattern in self.artifacts)


# ---------------------------------------------------------------- checks

def check_files(ctx: Context) -> list[dict]:
    out = []
    for path in ctx.files:
        rel = ctx.rel(path)
        if path.stat().st_size == 0:
            out.append(f("fail", "files", "empty file (0 bytes)", rel))
        junk = path.name in JUNK_NAMES or rel.startswith(JUNK_PREFIXES)
        if junk:
            out.append(f("fail", "files", "junk file that should never ship (desktop metadata)", rel))
        if any(part.startswith("__MACOSX") for part in path.parts[:-1]):
            out.append(f("fail", "files", "sits inside an archive-metadata folder (__MACOSX)", rel))
        forbidden = any(fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(path.name, pattern)
                        for pattern in ctx.forbid)
        if forbidden:
            out.append(f("fail", "files", "matches a forbidden pattern from releasecheck.json", rel))
        if ctx.artifacts and not junk and not forbidden and not ctx.matches_artifacts(path):
            out.append(f("warn", "files", "not part of the artifact list -- stale or foreign file?", rel))
    if not out:
        out.append(f("pass", "files", f"{len(ctx.files)} files inspected; no empty, junk or foreign ones"))
    return out


def check_duplicates(ctx: Context) -> list[dict]:
    seen: dict[str, str] = {}
    dupes = []
    for path in ctx.files:
        digest = sha256_file(path)
        if digest in seen:
            dupes.append(f("warn", "duplicates", f"identical to {seen[digest]} (same bytes under two names)", ctx.rel(path)))
        else:
            seen[digest] = ctx.rel(path)
    if not dupes:
        return [f("pass", "duplicates", "no two files carry identical content")]
    return dupes


def check_archives(ctx: Context) -> list[dict]:
    out, count = [], 0
    for path in ctx.files:
        if path.suffix.lower() not in ARCHIVE_SUFFIXES:
            continue
        count += 1
        rel = ctx.rel(path)
        try:
            with zipfile.ZipFile(path) as zf:
                bad = zf.testzip()
                if bad:
                    out.append(f("fail", "archives", f"CRC check failed on member {bad}", rel))
                for info in zf.infolist():
                    name = info.filename
                    if name.startswith("/") or name.startswith("\\") or ".." in Path(name).parts:
                        out.append(f("fail", "archives", f"unsafe member path (zip-slip): {name}", rel))
                    if info.flag_bits & 0x1:
                        out.append(f("fail", "archives", f"encrypted member: {name}", rel))
                names = zf.namelist()
                if path.suffix.lower() == ".epub":
                    if not names or names[0] != "mimetype":
                        out.append(f("fail", "archives", "epub: 'mimetype' must be the first member", rel))
                    elif zf.getinfo("mimetype").compress_type != zipfile.ZIP_STORED:
                        out.append(f("fail", "archives", "epub: 'mimetype' must be stored uncompressed", rel))
                    if "META-INF/container.xml" not in names:
                        out.append(f("fail", "archives", "epub: META-INF/container.xml is missing", rel))
                if path.suffix.lower() == ".docx":
                    for needed in ("[Content_Types].xml", "word/document.xml"):
                        if needed not in names:
                            out.append(f("fail", "archives", f"docx: required member {needed} is missing", rel))
        except zipfile.BadZipFile:
            out.append(f("fail", "archives", "not a readable archive (truncated or corrupted)", rel))
        except Exception as exc:  # noqa: BLE001 - reported, never raised
            out.append(f("fail", "archives", f"could not be opened: {exc}", rel))
    if not out:
        out.append(f("pass", "archives", f"{count} archive(s) open, pass integrity and path checks"))
    return out


def check_metadata(ctx: Context) -> list[dict]:
    out, found = [], 0
    for path in ctx.files:
        if path.suffix.lower() != ".epub":
            continue
        found += 1
        rel = ctx.rel(path)
        try:
            with zipfile.ZipFile(path) as zf:
                container = zf.read("META-INF/container.xml").decode("utf-8", "replace")
                match = re.search(r'full-path="([^"]+)"', container)
                if not match:
                    out.append(f("fail", "metadata", "epub: no rootfile in container.xml", rel))
                    continue
                opf = zf.read(match.group(1)).decode("utf-8", "replace")
                for label, pattern in (("title", r"<dc:title[^>]*>([^<]*)</dc:title>"),
                                       ("creator", r"<dc:creator[^>]*>([^<]*)</dc:creator>"),
                                       ("language", r"<dc:language[^>]*>([^<]*)</dc:language>"),
                                       ("identifier", r"<dc:identifier[^>]*>([^<]*)</dc:identifier>")):
                    value = re.search(pattern, opf)
                    if not value or not value.group(1).strip():
                        out.append(f("fail", "metadata", f"epub: {label} is missing from the OPF", rel))
        except Exception as exc:  # noqa: BLE001
            out.append(f("fail", "metadata", f"epub metadata unreadable: {exc}", rel))
    if not out:
        out.append(f("pass", "metadata", f"{found} epub(s): title, creator, language, identifier present"))
    return out


def _scan_bytes(payload: bytes, label: str, patterns, check: str) -> list[dict]:
    """Report matches under one check name. Secret values are never printed."""
    out = []
    for name, pattern in patterns:
        for match in pattern.finditer(payload):
            line = find_line(payload, match.start())
            raw = match.group(0).decode("utf-8", "replace").strip("\"'")
            value = mask(raw.encode()) if check == "secrets" else raw[:40]
            out.append(f("fail", check, f"{name}: {value} (line {line})", label))
    return out


def _scan_targets(ctx: Context):
    for path in ctx.files:
        yield ctx.rel(path), path
        if path.suffix.lower() in ARCHIVE_SUFFIXES:
            try:
                with zipfile.ZipFile(path) as zf:
                    for info in text_members(zf):
                        yield f"{ctx.rel(path)}!{info.filename}", zf.read(info)
            except Exception:  # noqa: BLE001 - reported by check_archives
                continue


def check_secrets(ctx: Context) -> list[dict]:
    out, scanned = [], 0
    for label, source in _scan_targets(ctx):
        data = source if isinstance(source, bytes) else None
        if data is None:
            try:
                if source.stat().st_size > RAW_SCAN_LIMIT:
                    continue
                data = source.read_bytes()
            except OSError:
                continue
        scanned += 1
        out += _scan_bytes(data, label, SECRET_PATTERNS, "secrets")
    if not out:
        out.append(f("pass", "secrets", f"{scanned} payloads scanned (including text inside archives); no key shapes found"))
    return out


def check_placeholders(ctx: Context) -> list[dict]:
    out, scanned = [], 0
    for label, source in _scan_targets(ctx):
        if isinstance(source, Path):
            continue  # placeholders matter in shipped text files, not in binaries
        scanned += 1
        out += _scan_bytes(source, label, PLACEHOLDER_PATTERNS, "placeholders")
    if not out:
        out.append(f("pass", "placeholders", f"{scanned} text payloads scanned; no TODO/TBD/lorem/template markers"))
    return out


def check_hashes(ctx: Context) -> list[dict]:
    sums = ctx.folder / ctx.hashes_name
    if not sums.is_file():
        return [f("skip", "hashes", f"no {ctx.hashes_name} in the folder; written by the packaging step")]
    out, listed = [], set()
    for line in sums.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            out.append(f("fail", "hashes", "malformed line in the sums file", ctx.hashes_name))
            continue
        digest, name = parts[0].lower(), parts[1].strip()
        listed.add(name)
        target = (ctx.folder / name)
        if not target.is_file():
            out.append(f("fail", "hashes", f"listed file is missing: {name}", ctx.hashes_name))
            continue
        actual = sha256_file(target)
        if actual != digest:
            out.append(f("fail", "hashes", f"content changed after the sums file was written: {name}", ctx.hashes_name))
    unlisted = [ctx.rel(p) for p in ctx.files
                if ctx.rel(p) not in listed and p.suffix.lower() in ARCHIVE_SUFFIXES]
    for name in unlisted:
        out.append(f("warn", "hashes", f"archive not covered by the sums file: {name}", ctx.hashes_name))
    if not out:
        out.append(f("pass", "hashes", f"{len(listed)} file(s) verified against {ctx.hashes_name}"))
    return out


def check_images(ctx: Context) -> list[dict]:
    out, seen = [], 0
    specs = ctx.images
    for path in ctx.files:
        if path.suffix.lower() not in {".jpg", ".jpeg", ".png", ".gif", ".webp"}:
            continue
        size = image_size(path.read_bytes()[:1 << 20]) if path.suffix.lower().startswith((".png", ".gif")) \
            else image_size(path.read_bytes())
        if not size:
            out.append(f("warn", "images", "dimensions could not be read (unusual or progressive format)", ctx.rel(path)))
            continue
        seen += 1
        width, height = size
        for spec in specs:
            pattern = spec.get("path", "*")
            if not (fnmatch.fnmatch(ctx.rel(path), pattern) or fnmatch.fnmatch(path.name, pattern)):
                continue
            minimum = int(spec.get("min_long_side", 0))
            if minimum and max(width, height) < minimum:
                out.append(f("fail", "images",
                             f"{width}x{height} is below the required long side of {minimum}px", ctx.rel(path)))
    if not out:
        out.append(f("pass", "images", f"{seen} image(s) readable; all size rules met"))
    return out


def check_pdf(ctx: Context) -> list[dict]:
    out, seen = [], 0
    for path in ctx.files:
        if path.suffix.lower() != ".pdf":
            continue
        seen += 1
        rel = ctx.rel(path)
        info = pdf_info(path.read_bytes())
        if not info["header"]:
            out.append(f("fail", "pdf", "does not start with a %PDF- header", rel))
            continue
        if not info["eof"]:
            out.append(f("fail", "pdf", "no %%EOF marker: the file is probably truncated", rel))
        if info["encrypted"]:
            out.append(f("fail", "pdf", "carries an /Encrypt entry: stores and printers reject locked files", rel))
        if info["pages_approx"] == 0:
            out.append(f("warn", "pdf", "no page objects found; page count not confirmed", rel))
    if not out:
        out.append(f("pass", "pdf", f"{seen} pdf(s): header, end-of-file and lock checks passed"))
    return out


def check_links(ctx: Context) -> list[dict]:
    out, internal = [], 0
    external: list[str] = []
    for path in ctx.files:
        if path.suffix.lower() not in {".md", ".markdown", ".html", ".htm", ".xhtml"}:
            continue
        body = path.read_text(errors="replace")
        targets = re.findall(r"\[[^\]]*\]\(([^)\s]+)\)", body) + \
            re.findall(r'(?:href|src)="([^"]+)"', body)
        for target in targets:
            if target.startswith(("http://", "https://")):
                external.append(target)
                continue
            if target.startswith(("#", "mailto:", "data:", "tel:")):
                continue
            internal += 1
            clean = target.split("#")[0].split("?")[0]
            if not clean:
                continue
            if not (path.parent / clean).exists():
                out.append(f("fail", "links", f"relative link points nowhere: {target}", ctx.rel(path)))
    if not out:
        out.append(f("pass", "links", f"{internal} internal link(s) resolve; {len(external)} external link(s) found"))
    if external:
        if not ctx.online:
            out.append(f("skip", "links-online",
                         f"{len(external)} external link(s) not checked (offline mode; add --online)"))
        else:
            statuses = check_online(sorted(set(external)))
            bad = [row for row in statuses if not row["ok"]]
            for row in bad:
                out.append(f("warn", "links-online", f"HTTP {row['status']} -- {row['url']}", None))
            out.append(f("pass" if not bad else "warn", "links-online",
                         f"{len(statuses) - len(bad)}/{len(statuses)} external links answered on {_today()}"))
    return out


def check_online(urls: list[str]) -> list[dict]:
    rows = []
    for url in urls:
        row = {"url": url, "status": None, "ok": False}
        try:
            request = Request(url, headers={"User-Agent": f"{TOOL}/{VERSION} (+link check)"})
            with urlopen(request, timeout=20) as response:
                row["status"] = response.status
                row["ok"] = 200 <= response.status < 400
        except HTTPError as exc:
            row["status"] = exc.code
        except (URLError, OSError):
            row["status"] = "unreachable"
        rows.append(row)
    return rows


def _today() -> str:
    return _dt.datetime.now(_dt.timezone.utc).date().isoformat()


# ---------------------------------------------------------------- runner

CHECKS = [
    ("files", check_files),
    ("duplicates", check_duplicates),
    ("archives", check_archives),
    ("metadata", check_metadata),
    ("secrets", check_secrets),
    ("placeholders", check_placeholders),
    ("hashes", check_hashes),
    ("images", check_images),
    ("pdf", check_pdf),
    ("links", check_links),
]


def run(folder: Path, manifest: dict, online: bool) -> dict:
    ctx = Context(folder, manifest, online)
    findings: list[dict] = []
    for _, function in CHECKS:
        try:
            findings += function(ctx)
        except Exception as exc:  # noqa: BLE001 - a broken check must not hide the rest
            findings.append(f("fail", "tool", f"check crashed: {type(exc).__name__}: {exc}"))
    counts = {status: sum(item["status"] == status for item in findings)
              for status in ("fail", "warn", "pass", "skip")}
    manifest_files = [{"path": ctx.rel(p), "bytes": p.stat().st_size, "sha256": sha256_file(p)}
                      for p in ctx.files]
    return {
        "tool": TOOL,
        "version": VERSION,
        "folder": str(folder),
        "release": manifest.get("name", folder.name),
        "checked_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "status": "FAIL" if counts["fail"] else "PASS",
        "counts": counts,
        "findings": findings,
        "files": manifest_files,
        "limits": LIMITS + list(manifest.get("extra_limits") or []),
    }


def render_text(report: dict) -> str:
    lines = [f"{report['tool']} {report['version']} -- preflight check",
             f"release: {report['release']}   folder: {report['folder']}",
             f"files: {len(report['files'])}   checked: {report['checked_at']}", "",
             report["status"]]
    order = {"fail": 0, "warn": 1, "skip": 2, "pass": 3}
    for item in sorted(report["findings"], key=lambda i: (order[i["status"]], i["check"])):
        where = f" [{item['path']}]" if item.get("path") else ""
        lines.append(f"  {item['status'].upper():4} {item['check']}: {item['message']}{where}")
    c = report["counts"]
    lines += ["", f"counts: {c['fail']} fail, {c['warn']} warn, {c['pass']} pass, {c['skip']} skip", "",
              "What this does not prove:"]
    lines += [f"  - {limit}" for limit in report["limits"]]
    return "\n".join(lines) + "\n"


def render_md(report: dict) -> str:
    c = report["counts"]
    out = [f"# {report['tool']} report -- {report['status']}", "",
           f"- release: `{report['release']}`",
           f"- folder: `{report['folder']}`",
           f"- checked: {report['checked_at']}",
           f"- counts: {c['fail']} fail, {c['warn']} warn, {c['pass']} pass, {c['skip']} skip", "",
           "| status | check | detail | file |", "|---|---|---|---|"]
    for item in report["findings"]:
        out.append(f"| {item['status']} | {item['check']} | {item['message']} | {item.get('path') or ''} |")
    out += ["", "## What this does not prove", ""]
    out += [f"- {limit}" for limit in report["limits"]]
    return "\n".join(out) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog=TOOL, description="Preflight checks for a release folder.")
    parser.add_argument("--version", action="version", version=f"{TOOL} {VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check", help="check a release folder")
    check.add_argument("folder", nargs="?", default=".")
    check.add_argument("-m", "--manifest", help="path to releasecheck.json (default: inside the folder)")
    check.add_argument("--online", action="store_true", help="also check external links (network)")
    check.add_argument("--json", dest="json_out", help="write the machine-readable report here")
    check.add_argument("--md", dest="md_out", help="write a markdown report here")
    check.add_argument("--quiet", action="store_true", help="print only the verdict line")
    args = parser.parse_args(argv)

    folder = Path(args.folder).expanduser().resolve()
    if not folder.is_dir():
        print(f"{TOOL}: not a folder: {folder}", file=sys.stderr)
        return 2

    manifest_path = Path(args.manifest).expanduser() if args.manifest else folder / "releasecheck.json"
    manifest: dict = {}
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text())
        except json.JSONDecodeError as exc:
            print(f"{TOOL}: releasecheck.json is not valid JSON: {exc}", file=sys.stderr)
            return 2

    report = run(folder, manifest, args.online)

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(report, indent=2) + "\n")
    if args.md_out:
        Path(args.md_out).write_text(render_md(report))
    print(report["status"] if args.quiet else render_text(report), end="")
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
