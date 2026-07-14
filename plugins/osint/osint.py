from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from chimera.core.logging import get_logger
from chimera.core.models import Challenge, ChallengeCategory, PluginManifest
from chimera.plugins.base import BasePlugin

log = get_logger(__name__)

OSINT_KEYWORDS = [
    r"osint|open.?source.?intell|recon|footprint",
    r"domain|dns|whois|subdomain|crt\.sh|certificate.?transparency",
    r"shodan|censys|searx|google.?dork|wayback.?machine",
    r"email|username|handle|social.?media|twitter|github|linkedin",
    r"ip.?address|geoip|whois|dns.?record|mx|txt.?record",
    r"metadata|exif|geolocation|gps|coordinates",
]

OSINT_DOMAIN_PATTERNS = [
    r"(?:https?://)?(?:www\.)?([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
]


class OSINTPlugin(BasePlugin):
    manifest = PluginManifest(
        name="osint",
        categories=[ChallengeCategory.osint],
        tools=["osint"],
    )

    def detect(self, challenge: Challenge) -> float:
        score = 0.0
        text = f"{challenge.title} {challenge.description}"

        for pat in OSINT_KEYWORDS:
            if re.search(pat, text, re.IGNORECASE):
                score += 0.2

        domains = set(re.findall(
            r"(?:https?://)?(?:www\.)?([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
            text,
        ))
        if domains:
            score += 0.15 * min(len(domains), 3)

        emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)
        if emails:
            score += 0.15 * min(len(emails), 3)

        return min(score, 1.0)

    async def analyze(self, challenge: Challenge) -> Challenge:
        log.info("OSINT analyzing: %s", challenge.id)
        findings: list[str] = []
        text = challenge.description

        domains = set(re.findall(
            r"(?:https?://)?(?:www\.)?([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
            text,
        ))

        for domain in list(domains)[:3]:
            dns_info = self._dns_lookup(domain)
            if dns_info:
                findings.append(f"DNS records for {domain}:\n{dns_info}")

            subdomains = self._crt_sh_lookup(domain)
            if subdomains:
                findings.append(f"Subdomains (crt.sh) for {domain}:\n{subdomains}")

        emails = re.findall(
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text
        )
        for email in emails[:3]:
            findings.append(f"Email found: {email}")

        if findings:
            challenge.description += "\n\n[OSINT Analysis]\n" + "\n".join(findings)

        log.info("OSINT analysis complete")
        return challenge

    async def solve(self, challenge: Challenge) -> Challenge:
        log.info("OSINT solving: %s", challenge.id)
        text = f"{challenge.title} {challenge.description}"
        match = re.search(r"(flag|CTF)\{[^}]+\}", text, re.IGNORECASE)
        if match:
            challenge.flag = match.group(0)
            return challenge

        for fpath in challenge.files:
            if not fpath.exists():
                continue
            content = fpath.read_text(encoding="utf-8", errors="replace")
            match = re.search(r"(flag|CTF)\{[^}]+\}", content, re.IGNORECASE)
            if match:
                challenge.flag = match.group(0)
                return challenge

        return challenge

    async def verify(self, challenge: Challenge) -> bool:
        if not challenge.flag:
            return False
        f = challenge.flag.strip()
        return (f.startswith("flag{") and f.endswith("}")) or (
            f.startswith("CTF{") and f.endswith("}")
        )

    def _dns_lookup(self, domain: str) -> str | None:
        records: list[str] = []
        for rtype in ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]:
            try:
                result = subprocess.run(
                    ["dig", "+short", domain, rtype],
                    capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0 and result.stdout.strip():
                    lines = result.stdout.strip().splitlines()
                    records.append(f"  {rtype}: {', '.join(lines[:3])}")
            except FileNotFoundError:
                break
            except Exception:
                continue
        return "\n".join(records) if records else None

    def _crt_sh_lookup(self, domain: str) -> str | None:
        try:
            result = subprocess.run(
                [
                    "curl", "-s",
                    f"https://crt.sh/?q=%25{domain}&output=json",
                    "--max-time", "15",
                ],
                capture_output=True, text=True, timeout=20,
            )
            if result.returncode == 0 and result.stdout.strip():
                try:
                    entries = json.loads(result.stdout)
                    names: set[str] = set()
                    for entry in entries[:20]:
                        name = entry.get("name_value", "")
                        for n in name.split("\n"):
                            if n.strip():
                                names.add(n.strip().lstrip("*."))
                    return "\n".join(sorted(names)[:15])
                except json.JSONDecodeError:
                    pass
        except FileNotFoundError:
            log.debug("curl not available")
        except Exception as e:
            log.debug("crt.sh lookup error: %s", e)
        return None
