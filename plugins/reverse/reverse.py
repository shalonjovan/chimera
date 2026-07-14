from __future__ import annotations

import re
import subprocess
from pathlib import Path

from chimera.core.logging import get_logger
from chimera.core.models import Challenge, ChallengeCategory, PluginManifest
from chimera.plugins.base import BasePlugin

log = get_logger(__name__)

REVERSE_SIGNATURES = {
    "ELF": b"\x7fELF",
    "PE": b"MZ",
    "Mach-O": b"\xfe\xed\xfa",
    "UPX packed": b"UPX",
    "stripped": b"stripped",
}


class ReversePlugin(BasePlugin):
    manifest = PluginManifest(
        name="reverse",
        categories=[ChallengeCategory.reverse],
        tools=["reverse"],
    )

    def detect(self, challenge: Challenge) -> float:
        score = 0.0
        text = f"{challenge.title} {challenge.description}"

        reverse_keywords = [
            r"reverse|reverse.?engineering|disassembl|decompil",
            r"crackme|keygen|license.?check|obfusc",
            r"\.exe|\.elf|\.bin|\.o\b|\.so\b|\.dll\b",
            r"arm|mips|x86|x64|shellcode|opcode",
            r"radare2|ghidra|gdb|angr|ida|holdec|binary.?ninja",
        ]
        for pat in reverse_keywords:
            if re.search(pat, text, re.IGNORECASE):
                score += 0.15

        for fpath in challenge.files:
            if not fpath.exists():
                continue
            header = fpath.read_bytes()[:64]
            for name, sig in REVERSE_SIGNATURES.items():
                if sig in header:
                    log.debug("Reverse detect: %s -> %s", fpath.name, name)
                    score += 0.25
            if fpath.suffix in {".exe", ".elf", ".o", ".so", ".dll", ".bin"}:
                score += 0.15

        return min(score, 1.0)

    async def analyze(self, challenge: Challenge) -> Challenge:
        log.info("Reverse analyzing: %s", challenge.id)
        findings: list[str] = []

        for fpath in challenge.files:
            if not fpath.exists():
                continue
            info = self._file_info(fpath)
            if info:
                findings.append(f"{fpath.name}: {info}")

            strings_out = self._extract_strings(fpath)
            if strings_out:
                findings.append(f"Strings in {fpath.name}:\n{strings_out}")

        if findings:
            challenge.description += "\n\n[Reverse Analysis]\n" + "\n\n".join(findings)

        log.info("Reverse analysis complete")
        return challenge

    async def solve(self, challenge: Challenge) -> Challenge:
        log.info("Reverse solving: %s", challenge.id)
        for fpath in challenge.files:
            if not fpath.exists():
                continue
            strings_out = self._extract_strings(fpath, min_len=8)
            flag_match = re.search(
                r"(flag|CTF|KEY|FLAG)\{[^}]+\}",
                strings_out,
                re.IGNORECASE,
            )
            if flag_match:
                challenge.flag = flag_match.group(0)
                log.info("Flag extracted from strings in %s", fpath.name)
                break
        return challenge

    async def verify(self, challenge: Challenge) -> bool:
        if not challenge.flag:
            return False
        f = challenge.flag.strip()
        return f.startswith("flag{") and f.endswith("}")

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

    def _extract_strings(self, path: Path, min_len: int = 4) -> str:
        try:
            result = subprocess.run(
                ["strings", "-n", str(min_len), str(path)],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                lines = [l for l in result.stdout.splitlines() if l.strip()]
                if lines:
                    return "\n".join(lines[:50])
        except Exception:
            pass
        return "<strings extraction unavailable>"
