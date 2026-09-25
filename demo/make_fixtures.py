#!/usr/bin/env python3
"""Build two fixture release folders for the releasecheck demo -- no network, no assets.

    python3 make_fixtures.py            # into ./_build
    python3 make_fixtures.py /tmp/x     # into another folder

The good folder passes. The broken folder fails on purpose, one realistic mistake
per check. Secret-looking values are assembled at runtime so that this repository
itself never contains a key-shaped literal.
"""
from __future__ import annotations

import hashlib
import struct
import sys
import zipfile
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_TARGET = HERE / "_build"


# ------------------------------------------------------------------ builders

def build_png(path: Path, width: int, height: int, rgb=(90, 120, 160)) -> None:
    """A real, fully valid PNG of one solid colour -- small on disk, exact on inspection."""
    raw = b"".join(b"\x00" + bytes(rgb) * width for _ in range(height))

    def chunk(tag: bytes, payload: bytes) -> bytes:
        return (struct.pack(">I", len(payload)) + tag + payload
                + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF))

    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    data = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header)
            + chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b""))
    path.write_bytes(data)


def build_pdf(path: Path, pages: int = 3, text: bytes = b"Fixture release") -> None:
    """A minimal but structurally valid PDF with a correct cross-reference table."""
    parts = [b"%PDF-1.4\n"]
    offsets: dict[int, int] = {}

    def add(number: int, body: bytes) -> None:
        offsets[number] = sum(len(part) for part in parts)
        parts.append(f"{number} 0 obj\n".encode() + body + b"\nendobj\n")

    kids = " ".join(f"{3 + i} 0 R" for i in range(pages))
    add(1, b"<< /Type /Catalog /Pages 2 0 R >>")
    add(2, f"<< /Type /Pages /Kids [{kids}] /Count {pages} >>".encode())
    for i in range(pages):
        add(3 + i, f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                   f"/Contents {3 + pages + i} 0 R >>".encode())
    stream = b"BT /F1 24 Tf 72 700 Td (" + text + b") Tj ET"
    for i in range(pages):
        add(3 + pages + i, f"<< /Length {len(stream)} >>\nstream\n".encode()
            + stream + b"\nendstream")
    total = 2 + 2 * pages
    xref_at = sum(len(part) for part in parts)
    parts.append(f"xref\n0 {total + 1}\n".encode())
    parts.append(b"0000000000 65535 f \n")
    for number in range(1, total + 1):
        parts.append(f"{offsets[number]:010d} 00000 n \n".encode())
    parts.append(f"trailer\n<< /Size {total + 1} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n".encode())
    path.write_bytes(b"".join(parts))


CONTAINER = """<?xml version="1.0"?>
<container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container">
  <rootfiles><rootfile full-path="OEBPS/content.opf"
    media-type="application/oebps-package+xml"/></rootfiles>
</container>
"""


def opf(title: str = "Fixture Book", creator: str = "Fixture Author",
        language: str = "en-US", identifier: str = "urn:uuid:fixture-0001",
        omit: tuple = ()) -> str:
    fields = {"title": f"<dc:title>{title}</dc:title>",
              "creator": f"<dc:creator>{creator}</dc:creator>",
              "language": f"<dc:language>{language}</dc:language>",
              "identifier": f'<dc:identifier id="bookid">{identifier}</dc:identifier>'}
    rows = "\n    ".join(value for name, value in fields.items() if name not in omit)
    return f"""<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://www.idpf.org/2007/opf" version="3.0" unique-identifier="bookid">
  <metadata xmlns:dc="http://purl.org/dc/elements/1.1/">
    {rows}
  </metadata>
  <manifest><item id="ch1" href="chapter.xhtml" media-type="application/xhtml+xml"/></manifest>
  <spine><itemref idref="ch1"/></spine>
</package>
"""


def chapter(body: str = "<p>Chapter one. Everything in this file is inspectable.</p>") -> str:
    return f"""<?xml version="1.0" encoding="utf-8"?>
<html xmlns="http://www.w3.org/1999/xhtml"><head><title>One</title></head>
<body>{body}</body></html>
"""


def build_epub(path: Path, *, title: str = "Fixture Book", mimetype_first: bool = True,
               body: str = chapter(), omit_metadata: tuple = ()) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        if mimetype_first:
            info = zipfile.ZipInfo("mimetype")
            info.compress_type = zipfile.ZIP_STORED
            zf.writestr(info, "application/epub+zip")
        zf.writestr("META-INF/container.xml", CONTAINER)
        zf.writestr("OEBPS/content.opf", opf(title=title, omit=omit_metadata))
        zf.writestr("OEBPS/chapter.xhtml", body)
        if not mimetype_first:
            zf.writestr("mimetype", "application/epub+zip")


def write_sums(folder: Path, names) -> None:
    lines = []
    for name in names:
        digest = hashlib.sha256((folder / name).read_bytes()).hexdigest()
        lines.append(f"{digest}  {name}\n")
    (folder / "SHA256SUMS.txt").write_text("".join(lines))


# ------------------------------------------------------------------ fixtures

MANIFEST_GOOD = """{
  "name": "fixture release 1.0",
  "artifacts": ["book.epub", "book.pdf", "cover.png"],
  "images": [{"path": "cover.png", "min_long_side": 1600}]
}
"""


def build_good(target: Path) -> Path:
    target.mkdir(parents=True, exist_ok=True)
    build_epub(target / "book.epub")
    build_pdf(target / "book.pdf", pages=3)
    build_png(target / "cover.png", 1600, 2560, rgb=(38, 70, 110))
    (target / "releasecheck.json").write_text(MANIFEST_GOOD)
    write_sums(target, ["book.epub", "book.pdf", "cover.png"])
    return target


def build_broken(target: Path) -> Path:
    target.mkdir(parents=True, exist_ok=True)
    # 1. epub whose mimetype is written last (a classic packaging mistake)
    build_epub(target / "book.epub", title="Broken Fixture", mimetype_first=False,
               omit_metadata=("creator",),
               body=chapter("<p>TODO: finish the last chapter before release.</p>"))
    # 2. truncated pdf: the end-of-file marker never made it
    build_pdf(target / "book.pdf", pages=3)
    data = (target / "book.pdf").read_bytes()
    (target / "book.pdf").write_bytes(data[: len(data) // 2])
    # 3. cover below the required size, plus a second identical copy (a real habit)
    build_png(target / "cover.png", 400, 600)
    (target / "cover-final.png").write_bytes((target / "cover.png").read_bytes())
    # 4. a file that carries a key shape; the literal is assembled here at runtime
    key_shape = "AKIA" + "IOSFODNN7" + "EXAMPLE"
    token_shape = "ghp_" + "Aa0Bb1Cc2Dd3Ee4Ff5Gg6Hh7Ii8Jj9Kk0Ll1"
    (target / "draft.txt").write_text(
        "notes for the release\n"
        f"backup_key = \"{key_shape}\"\n"
        "sync_token: '" + token_shape + "'\n")
    # 5. markdown with a link to a file that is not in the release
    (target / "notes.md").write_text(
        "# Release notes\n\nSee the [shipping checklist](checklist.md) and the "
        "[contract](missing-contract.pdf).\n")
    # 6. junk that should never ship
    (target / ".DS_Store").write_bytes(b"\x00\x00\x00\x01Bud1")
    # 7. an old artifact left in the folder from a previous release
    (target / "legacy").mkdir(exist_ok=True)
    build_epub(target / "legacy" / "book-v0.9.epub", title="Old Book")
    (target / "releasecheck.json").write_text("""{
  "name": "fixture release 1.0 (broken on purpose)",
  "artifacts": ["book.epub", "book.pdf", "cover.png", "draft.txt", "notes.md"],
  "images": [{"path": "cover.png", "min_long_side": 1600}]
}
""")
    # 8. the sums file was written before the last edit -- one hash no longer matches
    write_sums(target, ["book.epub", "book.pdf", "cover.png", "draft.txt", "notes.md"])
    (target / "notes.md").write_text((target / "notes.md").read_text() + "\nEdited after packaging.\n")
    return target


def main(argv=None) -> int:
    target = Path(argv[1]) if argv and len(argv) > 1 else DEFAULT_TARGET
    good = build_good(target / "good")
    broken = build_broken(target / "broken")
    for label, folder in (("good", good), ("broken", broken)):
        files = sorted(p.name for p in folder.rglob("*") if p.is_file())
        print(f"{label}: {folder}  ({len(files)} files: {', '.join(files)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
