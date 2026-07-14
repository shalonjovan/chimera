from __future__ import annotations

import re
import subprocess
from pathlib import Path

from chimera.core.logging import get_logger
from chimera.core.models import Challenge, ChallengeCategory, PluginManifest
from chimera.plugins.base import BasePlugin

log = get_logger(__name__)

PWN_KEYWORDS = [
    r"pwn|binary.?exploit|buffer.?overflow|bof|rop|return.?oriented",
    r"format.?string|fmtstr|arbitrary.?write|arbitrary.?read",
    r"shellcode|code.?exec|remote.?exec|privesc|privilege.?escalation",
    r"pwntools|checksec|gdb|radare2|one.?gadget|seccomp",
    r"aslr|nx|pie|relro|canary|stack.?protector",
    r"got|plt|ret2libc|ret2syscall|ret2shellcode",
]

PWN_KEYWORDS_LOWER = [
    "pwn", "rop", "got", "plt", "bof", "shellcode", "canary",
    "ret2libc", "ret2syscall", "fmtstr",
]


class PwnPlugin(BasePlugin):
    manifest = PluginManifest(
        name="pwn",
        categories=[ChallengeCategory.pwn],
        tools=["pwn"],
    )

    def detect(self, challenge: Challenge) -> float:
        score = 0.0
        text_lower = f"{challenge.title} {challenge.description}".lower()

        for pat in PWN_KEYWORDS:
            if re.search(pat, text_lower, re.IGNORECASE):
                score += 0.2

        for fpath in challenge.files:
            if not fpath.exists():
                continue
            if self._is_elf(fpath):
                score += 0.25
                protections = self._check_protections(fpath)
                if protections:
                    for prot in ["NX disabled", "Stack canary", "PIE"]:
                        if prot in protections:
                            score += 0.1
                    if "No RELRO" in protections or "Partial RELRO" in protections:
                        score += 0.1

        return min(score, 1.0)

    async def analyze(self, challenge: Challenge) -> Challenge:
        log.info("Pwn analyzing: %s", challenge.id)
        findings: list[str] = []

        for fpath in challenge.files:
            if not fpath.exists():
                continue
            if self._is_elf(fpath):
                prot = self._check_protections(fpath)
                if prot:
                    findings.append(f"{fpath.name} protections:\n{prot}")

                fmt = self._find_format_string(fpath)
                if fmt:
                    findings.append(f"Potential format string: {fmt[:200]}")

        if findings:
            challenge.description += "\n\n[Pwn Analysis]\n" + "\n\n".join(findings)

        log.info("Pwn analysis complete")
        return challenge

    async def solve(self, challenge: Challenge) -> Challenge:
        log.info("Pwn solving: %s", challenge.id)
        for fpath in challenge.files:
            if not fpath.exists():
                continue
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

    def _is_elf(self, path: Path) -> bool:
        try:
            return path.read_bytes()[:4] == b"\x7fELF"
        except Exception:
            return False

    def _check_protections(self, path: Path) -> str | None:
        try:
            result = subprocess.run(
                ["checksec", "--file=" + str(path)],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except FileNotFoundError:
            pass
        try:
            result = subprocess.run(
                ["readelf", "-l", str(path)],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                lines = []
                if "GNU_STACK" in result.stdout:
                    lines.append("NX: check with readelf")
                if "GNU_RELRO" in result.stdout:
                    lines.append("RELRO: present")
                return "\n".join(lines) if lines else None
        except FileNotFoundError:
            pass
        return None

    def _find_format_string(self, path: Path) -> str | None:
        try:
            data = path.read_bytes()
            text_section = data[data.find(b".text"):][:100000]
            matches = re.findall(
                rb"[\x01-\x7f]{2,}", text_section
            )
            fmt_strs = [m.decode() for m in matches if m.strip()]
            suspicious = [s for s in fmt_strs if "%" in s and re.search(r"%[ndsxp]", s)]
            return "\n".join(suspicious[:10]) if suspicious else None
        except Exception:
            return None

    def _scan_for_flag(self, path: Path) -> str | None:
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
