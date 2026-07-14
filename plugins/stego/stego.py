from __future__ import annotations

import re
import subprocess
from pathlib import Path

from chimera.core.logging import get_logger
from chimera.core.models import Challenge, ChallengeCategory, PluginManifest
from chimera.plugins.base import BasePlugin

log = get_logger(__name__)

STEGO_EXTENSIONS = {
    ".png", ".bmp", ".jpg", ".jpeg", ".gif", ".tiff", ".tif",
    ".wav", ".au", ".aiff",
    ".mp3", ".mp4", ".avi", ".mov",
}

STEGO_KEYWORDS = [
    r"stego|steganography|hidden|embedded|lsb",
    r"least.?significant.?bit|metadata|exif",
    r"invisible|watermark|conceal|cover.?image",
    r"zsteg|steghide|stegsolve|binwalk",
]


class StegoPlugin(BasePlugin):
    manifest = PluginManifest(
        name="stego",
        categories=[ChallengeCategory.stego],
        tools=["stego"],
    )

    def detect(self, challenge: Challenge) -> float:
        score = 0.0
        text = f"{challenge.title} {challenge.description}"

        for pat in STEGO_KEYWORDS:
            if re.search(pat, text, re.IGNORECASE):
                score += 0.2

        for fpath in challenge.files:
            if not fpath.exists():
                continue
            if fpath.suffix.lower() in STEGO_EXTENSIONS:
                score += 0.25
            file_size = fpath.stat().st_size
            ext = fpath.suffix.lower()
            if ext in {".png", ".bmp"}:
                score += 0.1

        return min(score, 1.0)

    async def analyze(self, challenge: Challenge) -> Challenge:
        log.info("Stego analyzing: %s", challenge.id)
        findings: list[str] = []

        for fpath in challenge.files:
            if not fpath.exists():
                continue
            metadata = self._get_metadata(fpath)
            if metadata:
                findings.append(f"{fpath.name}: {metadata}")

            suspicious = self._check_lsb(fpath)
            if suspicious:
                findings.append(f"{fpath.name}: {suspicious}")

        if findings:
            challenge.description += "\n\n[Stego Analysis]\n" + "\n".join(findings)

        log.info("Stego analysis complete")
        return challenge

    async def solve(self, challenge: Challenge) -> Challenge:
        log.info("Stego solving: %s", challenge.id)

        for fpath in challenge.files:
            if not fpath.exists():
                continue
            ext = fpath.suffix.lower()

            if ext in {".png", ".bmp"}:
                flag = self._try_zsteg(fpath)
                if flag:
                    challenge.flag = flag
                    return challenge

            if ext in {".jpg", ".jpeg"}:
                flag = self._try_steghide(fpath)
                if flag:
                    challenge.flag = flag
                    return challenge

            flag = self._scan_for_flag(fpath)
            if flag:
                challenge.flag = flag
                return challenge

        return challenge

    async def verify(self, challenge: Challenge) -> bool:
        if not challenge.flag:
            return False
        f = challenge.flag.strip()
        return (f.startswith("flag{") and f.endswith("}")) or (
            f.startswith("CTF{") and f.endswith("}")
        )

    def _get_metadata(self, path: Path) -> str | None:
        try:
            result = subprocess.run(
                ["exiftool", "-b", str(path)],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()[:500]
        except FileNotFoundError:
            pass
        except Exception as e:
            log.debug("exiftool error: %s", e)
        return None

    def _check_lsb(self, path: Path) -> str | None:
        ext = path.suffix.lower()
        if ext not in {".png", ".bmp"}:
            return None
        try:
            result = subprocess.run(
                ["zsteg", str(path)],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0 and result.stdout.strip():
                return f"zsteg: {result.stdout.strip()[:300]}"
        except FileNotFoundError:
            pass
        except Exception as e:
            log.debug("zsteg error: %s", e)
        return None

    def _try_zsteg(self, path: Path) -> str | None:
        try:
            result = subprocess.run(
                ["zsteg", "--all", str(path)],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                match = re.search(
                    r"(flag|CTF)\{[^}]+\}", result.stdout, re.IGNORECASE
                )
                if match:
                    return match.group(0)
        except Exception:
            pass
        return None

    def _try_steghide(self, path: Path) -> str | None:
        try:
            result = subprocess.run(
                ["steghide", "extract", "-sf", str(path), "-p", "", "-f"],
                capture_output=True, text=True, timeout=15,
            )
            out_file = path.parent / f"{path.stem}.txt"
            if out_file.exists():
                content = out_file.read_text()
                match = re.search(
                    r"(flag|CTF)\{[^}]+\}", content, re.IGNORECASE
                )
                if match:
                    return match.group(0)
        except Exception:
            pass
        return None

    def _scan_for_flag(self, path: Path) -> str | None:
        try:
            text_content = path.read_bytes().decode("utf-8", errors="replace")
            match = re.search(
                r"(flag|CTF)\{[^}]+\}", text_content, re.IGNORECASE
            )
            if match:
                return match.group(0)
        except Exception:
            pass
        return None
