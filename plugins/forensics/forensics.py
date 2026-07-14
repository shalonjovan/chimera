from __future__ import annotations

import re
import subprocess
import zipfile
from pathlib import Path
from typing import Any

from chimera.core.logging import get_logger
from chimera.core.models import Challenge, ChallengeCategory, PluginManifest
from chimera.plugins.base import BasePlugin

log = get_logger(__name__)

FORENSICS_EXTENSIONS = {
    ".dd", ".img", ".iso", ".vhd", ".vmdk", ".qcow2",
    ".pcap", ".pcapng",
    ".log", ".evtx",
    ".raw", ".dmp",
    ".zip", ".rar", ".7z", ".tar", ".gz",
    ".docx", ".xlsx", ".pptx", ".pdf",
}

FORENSICS_KEYWORDS = [
    r"forensic|forensics|disk.?image|memory.?dump|memory.?analysis",
    r"pcap|packet.?capture|network.?trace|traffic",
    r"file.?carving|recover.?deleted|data.?recovery",
    r"volatility|binwalk|bulk.?extractor",
    r"registry|hive|prefetch|timeline|artifact",
]


class ForensicsPlugin(BasePlugin):
    manifest = PluginManifest(
        name="forensics",
        categories=[ChallengeCategory.forensics],
        tools=["forensics"],
    )

    def detect(self, challenge: Challenge) -> float:
        score = 0.0
        text = f"{challenge.title} {challenge.description}"

        for pat in FORENSICS_KEYWORDS:
            if re.search(pat, text, re.IGNORECASE):
                score += 0.2

        for fpath in challenge.files:
            if not fpath.exists():
                continue
            if fpath.suffix.lower() in FORENSICS_EXTENSIONS:
                score += 0.25
            if self._is_disk_image(fpath):
                score += 0.2
            if self._is_archive(fpath):
                score += 0.15

        return min(score, 1.0)

    async def analyze(self, challenge: Challenge) -> Challenge:
        log.info("Forensics analyzing: %s", challenge.id)
        findings: list[str] = []

        for fpath in challenge.files:
            if not fpath.exists():
                continue
            info = self._file_info(fpath)
            if info:
                findings.append(f"{fpath.name}: {info}")

            if self._is_disk_image(fpath):
                strings_found = self._extract_strings(fpath)
                if strings_found:
                    findings.append(f"Strings from {fpath.name}:\n{strings_found[:500]}")

            if self._is_archive(fpath):
                listing = self._list_archive(fpath)
                if listing:
                    findings.append(f"Archive contents ({fpath.name}):\n{listing}")

        if findings:
            challenge.description += "\n\n[Forensics Analysis]\n" + "\n\n".join(findings)

        log.info("Forensics analysis complete")
        return challenge

    async def solve(self, challenge: Challenge) -> Challenge:
        log.info("Forensics solving: %s", challenge.id)

        for fpath in challenge.files:
            if not fpath.exists():
                continue

            flag = self._scan_for_flag(fpath)
            if flag:
                challenge.flag = flag
                return challenge

            if self._is_archive(fpath):
                flag = self._extract_from_archive(fpath)
                if flag:
                    challenge.flag = flag
                    return challenge

            if self._is_disk_image(fpath):
                flag = self._scan_raw(fpath)
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

    def _is_disk_image(self, path: Path) -> bool:
        ext = path.suffix.lower()
        return ext in {".dd", ".img", ".iso", ".raw", ".dmp", ".vhd", ".vmdk"}

    def _is_archive(self, path: Path) -> bool:
        ext = path.suffix.lower()
        return ext in {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2"}

    def _file_info(self, path: Path) -> str | None:
        try:
            result = subprocess.run(
                ["file", "-b", str(path)],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return None

    def _extract_strings(self, path: Path, min_len: int = 6) -> str:
        try:
            result = subprocess.run(
                ["strings", "-n", str(min_len), str(path)],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
                return "\n".join(lines[:100])
        except Exception:
            pass
        return ""

    def _list_archive(self, path: Path) -> str | None:
        ext = path.suffix.lower()
        try:
            if ext == ".zip":
                with zipfile.ZipFile(path) as zf:
                    names = zf.namelist()
                return "\n".join(sorted(names)[:50])
            return None
        except Exception:
            try:
                result = subprocess.run(
                    ["tar", "tf", str(path)],
                    capture_output=True, text=True, timeout=15,
                )
                if result.returncode == 0:
                    lines = result.stdout.strip().splitlines()
                    return "\n".join(lines[:50])
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

    def _extract_from_archive(self, path: Path) -> str | None:
        ext = path.suffix.lower()
        try:
            if ext == ".zip":
                with zipfile.ZipFile(path) as zf:
                    for name in zf.namelist():
                        content = zf.read(name).decode("utf-8", errors="replace")
                        match = re.search(
                            r"(flag|CTF)\{[^}]+\}", content, re.IGNORECASE
                        )
                        if match:
                            return match.group(0)
        except Exception:
            pass
        return None

    def _scan_raw(self, path: Path) -> str | None:
        try:
            data = path.read_bytes()
            match = re.search(
                rb"(flag|CTF)\{[^}]+\}", data, re.IGNORECASE
            )
            if match:
                return match.group(0).decode()
        except Exception:
            pass
        return None
