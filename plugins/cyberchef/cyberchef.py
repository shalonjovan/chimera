from __future__ import annotations

import re
from pathlib import Path

from chimera.core.logging import get_logger
from chimera.core.models import Challenge, ChallengeCategory, PluginManifest
from chimera.plugins.base import BasePlugin
from chimera.tools.cyberchef import bridge

log = get_logger(__name__)

SIGNATURES = {
    "base64": r"[A-Za-z0-9+/]{40,}={0,2}|base64|b64decode",
    "hex": r"[0-9a-fA-F]{32,}|hex|hexadecimal|0x[0-9a-fA-F]+",
    "binary": r"(?:[01]{8}\s*)+|binary",
    "ROT": r"\bROT\b|caesar|rot[0-9]+|shift",
    "XOR": r"\bXOR\b|xor_?key|single.?byte.?xor|repeating.?xor",
    "URL": r"%[0-9a-fA-F]{2}|url.?decode|percent.?encode",
    "encoded": r"encod|obfuscat|decode|scrambl|cipher",
}

ENCODED_PATTERNS = [
    (r"^[A-Za-z0-9+/=]+$", "base64"),
    (r"^[0-9a-fA-F]+$", "hex"),
    (r"^[01]+$", "binary"),
    (r"^%[0-9a-fA-F]{2}", "url"),
]

DECODE_LADDER = [
    {"op": "From Base64"},
    {"op": "From Hex"},
    {"op": "ROT13"},
    {"op": "URL Decode"},
]

FLAG_RE = re.compile(r"(flag|CTF)\{[^}]+\}", re.IGNORECASE)


class CyberchefPlugin(BasePlugin):
    manifest = PluginManifest(
        name="cyberchef",
        categories=[ChallengeCategory.crypto, ChallengeCategory.forensics, ChallengeCategory.misc],
        tools=["cyberchef"],
    )

    def detect(self, challenge: Challenge) -> float:
        score = 0.0
        text = f"{challenge.title} {challenge.description}"

        for kind, pattern in SIGNATURES.items():
            if re.search(pattern, text, re.IGNORECASE):
                log.debug("Cyberchef detect matched: %s", kind)
                score += 0.2

        for fpath in challenge.files:
            if not fpath.exists():
                continue
            content = fpath.read_text(encoding="utf-8", errors="replace")
            for kind, pattern in SIGNATURES.items():
                if re.search(pattern, content, re.IGNORECASE):
                    score += 0.15

            lines = [ln for ln in content.strip().splitlines() if ln.strip()]
            if len(lines) == 1:
                for pat, name in ENCODED_PATTERNS:
                    if re.match(pat, lines[0].strip()):
                        score += 0.25

        return min(score, 1.0)

    async def analyze(self, challenge: Challenge) -> Challenge:
        log.info("Cyberchef analyzing: %s", challenge.id)
        findings: list[str] = []

        for fpath in challenge.files:
            if not fpath.exists():
                continue
            content = fpath.read_text(encoding="utf-8", errors="replace").strip()
            if not content:
                continue

            decoded = await self._decode_ladder(content)
            if decoded and decoded != content:
                findings.append(
                    f"Decoded {fpath.name}: {self._snippet(decoded)}"
                )
                continue

            magic = await self._try_run([{"op": "Magic", "args": {"Depth": 1}}], content)
            if magic and magic != content:
                findings.append(
                    f"Magic auto-detection on {fpath.name}: {self._snippet(magic)}"
                )

        if findings:
            challenge.description += "\n\n[Cyberchef Analysis]\n" + "\n".join(findings)

        log.info("Cyberchef analysis complete: %d findings", len(findings))
        return challenge

    async def solve(self, challenge: Challenge) -> Challenge:
        log.info("Cyberchef solving: %s", challenge.id)
        for fpath in challenge.files:
            if not fpath.exists():
                continue
            content = fpath.read_text(encoding="utf-8", errors="replace").strip()
            if not content:
                continue

            flag = self._extract_flag(content)
            if flag:
                challenge.flag = flag
                return challenge

            decoded = await self._decode_ladder(content)
            if decoded:
                flag = self._extract_flag(decoded)
                if flag:
                    challenge.flag = flag
                    return challenge

            raw_b64 = await self._decode_raw_b64(content)
            if raw_b64:
                flag = self._extract_flag(self._b64_to_text(raw_b64))
                if flag:
                    challenge.flag = flag
                    return challenge
                xor = await self._try_run(
                    [{"op": "XOR Brute Force", "args": {"Key length": 1, "Sample length": 200}}],
                    None,
                    raw_b64,
                )
                if xor:
                    flag = self._extract_flag(xor)
                    if flag:
                        challenge.flag = flag
                        return challenge

            magic = await self._try_run([{"op": "Magic", "args": {"Depth": 1}}], content)
            if magic:
                flag = self._extract_flag(magic)
                if flag:
                    challenge.flag = flag
                    return challenge

        return challenge

    async def verify(self, challenge: Challenge) -> bool:
        if not challenge.flag:
            return False
        flag = challenge.flag.strip()
        return flag.startswith("flag{") and flag.endswith("}") or (
            flag.startswith("CTF{") and flag.endswith("}")
        )

    async def _decode_ladder(self, content: str) -> str | None:
        for step in DECODE_LADDER:
            try:
                result = await bridge.run_recipe([step], self._to_b64(content))
            except Exception as e:
                log.debug("Decode step %s failed: %s", step["op"], e)
                continue
            text = self._result_text(result)
            if text and self._is_plausible(text, content):
                return text
        return None

    async def _decode_raw_b64(self, content: str) -> str | None:
        """Decode base64/hex content to raw bytes (as b64) for binary
        ciphertext analysis such as XOR brute force."""
        for step in DECODE_LADDER[:2]:
            try:
                result = await bridge.run_recipe([step], self._to_b64(content))
            except Exception as e:
                log.debug("Raw decode step %s failed: %s", step["op"], e)
                continue
            raw = (
                result.get("outputBytesB64")
                or result.get("outputB64")
                or self._to_b64(self._result_text(result))
            )
            if raw and raw != self._to_b64(content):
                return raw
        return None

    async def _try_run(
        self, recipe: list[dict], content: str | None = None, input_b64: str | None = None
    ) -> str | None:
        try:
            payload = input_b64 if input_b64 is not None else (
                self._to_b64(content) if content is not None else None
            )
            result = await bridge.run_recipe(recipe, payload)
        except Exception as e:
            log.debug("Recipe %s failed: %s", recipe, e)
            return None
        return self._result_text(result)

    @staticmethod
    def _to_b64(text: str) -> str:
        import base64

        return base64.b64encode(text.encode("utf-8")).decode("ascii")

    @staticmethod
    def _b64_to_text(b64: str) -> str:
        import base64

        return base64.b64decode(b64).decode("utf-8", errors="replace")

    @staticmethod
    def _result_text(result: dict) -> str:
        text = result.get("outputText") or ""
        if text:
            return text
        return ""

    def _is_plausible(self, decoded: str, original: str) -> bool:
        if decoded == original:
            return False
        printable = sum(1 for ch in decoded if 32 <= ord(ch) <= 126 or ch in "\n\r\t")
        return printable / max(len(decoded), 1) > 0.8

    @staticmethod
    def _snippet(text: str, limit: int = 200) -> str:
        text = " ".join(text.split())
        return text[:limit] + ("..." if len(text) > limit else "")

    @staticmethod
    def _extract_flag(text: str) -> str | None:
        m = FLAG_RE.search(text)
        return m.group(0) if m else None
