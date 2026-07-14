from __future__ import annotations

import base64
import re
from pathlib import Path

from chimera.core.logging import get_logger
from chimera.core.models import Challenge, ChallengeCategory, PluginManifest
from chimera.plugins.base import BasePlugin

log = get_logger(__name__)

CRYPTO_SIGNATURES = {
    "RSA": r"\bRSA\b|rsa\.pub|private\.pem|public\.pem|-----BEGIN.*KEY-----",
    "AES": r"\bAES\b|aes_?256|aes_?128|iv\s*=|mode\s*=|ciphertext|plaintext",
    "XOR": r"\bXOR\b|xor_?key|single.?byte.?xor|repeating.?xor",
    "base64": r"[A-Za-z0-9+/=]{40,}|base64|b64decode",
    "hex": r"[0-9a-fA-F]{32,}|hex|hexadecimal",
    "Caesar/Rot": r"\bROT\b|caesar|shift.?cipher|rot[0-9]+",
    "Vigenere": r"vigen[eè]re|running.?key",
    "Hash": r"\bMD5\b|\bSHA[0-9]+\b|hash|digest|checksum",
    "ECC": r"ECC|elliptic.?curve|ecdsa|ecdh",
    "DES": r"\bDES\b|3DES|triple.?des|des_?cbc|des_?ecb",
}

ENCODED_PATTERNS = [
    (r"^[A-Za-z0-9+/=]+$", "base64"),
    (r"^[0-9a-fA-F]+$", "hex"),
    (r"^[01]+$", "binary"),
    (r"^[A-Za-z]+$", "alphabetic"),
]


class CryptoPlugin(BasePlugin):
    manifest = PluginManifest(
        name="crypto",
        categories=[ChallengeCategory.crypto],
        tools=["crypto"],
    )

    def detect(self, challenge: Challenge) -> float:
        score = 0.0
        text = f"{challenge.title} {challenge.description}"

        for algo, pattern in CRYPTO_SIGNATURES.items():
            if re.search(pattern, text, re.IGNORECASE):
                log.debug("Crypto detect matched: %s", algo)
                score += 0.2

        for fpath in challenge.files:
            if not fpath.exists():
                continue
            text_content = fpath.read_text(encoding="utf-8", errors="replace")
            for algo, pattern in CRYPTO_SIGNATURES.items():
                if re.search(pattern, text_content, re.IGNORECASE):
                    score += 0.15

            lines = text_content.strip().splitlines()
            if len(lines) == 1 and len(lines[0]) > 20:
                for pat, name in ENCODED_PATTERNS:
                    if re.match(pat, lines[0].strip()):
                        score += 0.2

        return min(score, 1.0)

    async def analyze(self, challenge: Challenge) -> Challenge:
        log.info("Crypto analyzing: %s", challenge.id)
        findings: list[str] = []

        for fpath in challenge.files:
            if not fpath.exists():
                continue
            content = fpath.read_text(encoding="utf-8", errors="replace")

            for enc_name in ["base64", "hex", "binary", "rot13"]:
                decoded = self._try_decode(content.strip(), enc_name)
                if decoded:
                    findings.append(f"Detected {enc_name} encoding in {fpath.name}")

            for algo in ["RSA", "AES", "XOR"]:
                if any(marker in content.lower() for marker in self._algo_markers(algo)):
                    findings.append(f"Detected {algo} artifacts in {fpath.name}")

        if findings:
            challenge.description += "\n\n[Crypto Analysis]\n" + "\n".join(findings)

        log.info("Crypto analysis complete: %d findings", len(findings))
        return challenge

    async def solve(self, challenge: Challenge) -> Challenge:
        log.info("Crypto solving: %s", challenge.id)
        for fpath in challenge.files:
            if not fpath.exists():
                continue
            content = fpath.read_text(encoding="utf-8", errors="replace").strip()

            decoded = self._try_decode(content, "base64")
            if decoded:
                challenge.flag = self._extract_flag(decoded)
                if challenge.flag:
                    return challenge

            decoded = self._try_decode(content, "hex")
            if decoded:
                flag = self._extract_flag(decoded)
                if flag:
                    challenge.flag = flag
                    return challenge

        return challenge

    async def verify(self, challenge: Challenge) -> bool:
        if not challenge.flag:
            return False
        flag = challenge.flag.strip()
        if flag.startswith("flag{") and flag.endswith("}"):
            return True
        if flag.startswith("CTF{") and flag.endswith("}"):
            return True
        return False

    def _try_decode(self, text: str, encoding: str) -> str | None:
        try:
            if encoding == "base64":
                return base64.b64decode(text).decode("utf-8", errors="replace")
            elif encoding == "hex":
                return bytes.fromhex(text).decode("utf-8", errors="replace")
            elif encoding == "rot13":
                return text.translate(str.maketrans(
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
                ))
        except Exception:
            return None
        return None

    def _extract_flag(self, text: str) -> str | None:
        m = re.search(r"(flag|CTF)\{[^}]+\}", text, re.IGNORECASE)
        return m.group(0) if m else None

    def _algo_markers(self, algo: str) -> list[str]:
        markers = {
            "RSA": ["n = ", "e = ", "d = ", "p = ", "q = ", "cipher", "rsa"],
            "AES": ["aes", "iv = ", "key = ", "cipher", "sbox"],
            "XOR": ["xor", "^ 0x", "keystream", "key = "],
        }
        return markers.get(algo, [])
