from __future__ import annotations

import re
import subprocess
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from chimera.core.logging import get_logger
from chimera.core.models import Challenge, ChallengeCategory, PluginManifest
from chimera.plugins.base import BasePlugin

log = get_logger(__name__)

WEB_KEYWORDS = [
    r"web|http|https?://|url|endpoint|api",
    r"sqli|sql.?injection|xss|csrf|ssrf|lfi|rfi|command.?inject",
    r"jwt|session|cookie|token|oauth|auth[ez]?",
    r"burp|ffuf|sqlmap|gobuster|nikto|zap|playwright",
    r"php|asp|jsp|node|express|django|flask|wordpress",
    r"robots\.txt|sitemap|\.htaccess|source.?code|debug|admin",
    r"cors|x-frame|xss|content.?security|csp",
]

WEB_EXTENSIONS = {
    ".html", ".htm", ".php", ".asp", ".aspx", ".jsp",
    ".js", ".ts", ".json", ".xml",
    ".css", ".map",
}

COMMON_PATHS = [
    "/robots.txt", "/admin", "/flag", "/flag.txt",
    "/.git/config", "/.env", "/sitemap.xml",
    "/api/flag", "/debug", "/backup",
]


class WebPlugin(BasePlugin):
    manifest = PluginManifest(
        name="web",
        categories=[ChallengeCategory.web],
        tools=["web"],
    )

    def detect(self, challenge: Challenge) -> float:
        score = 0.0
        text = f"{challenge.title} {challenge.description}"

        for pat in WEB_KEYWORDS:
            if re.search(pat, text, re.IGNORECASE):
                score += 0.15

        for fpath in challenge.files:
            if not fpath.exists():
                continue
            if fpath.suffix.lower() in WEB_EXTENSIONS:
                score += 0.2

        urls = re.findall(r"https?://[^\s,;'\"]+", text)
        if urls:
            score += 0.2 * min(len(urls), 3)

        return min(score, 1.0)

    async def analyze(self, challenge: Challenge) -> Challenge:
        log.info("Web analyzing: %s", challenge.id)
        findings: list[str] = []
        urls = re.findall(r"https?://[^\s,;'\"]+", challenge.description)

        for url in urls:
            analysis = self._analyze_url(url)
            if analysis:
                findings.append(analysis)

            for path in COMMON_PATHS:
                resp = self._fetch_url(f"{url.rstrip('/')}{path}")
                if resp:
                    findings.append(f"Found accessible path: {path}")

            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query)
                for param in params:
                    sqli_test = self._test_sqli(url, param)
                    if sqli_test:
                        findings.append(sqli_test)

        for fpath in challenge.files:
            if not fpath.exists():
                continue
            content = fpath.read_text(encoding="utf-8", errors="replace")
            secrets = self._find_secrets(content, fpath.name)
            if secrets:
                findings.append(secrets)

        if findings:
            challenge.description += "\n\n[Web Analysis]\n" + "\n".join(findings)

        log.info("Web analysis complete, %d findings", len(findings))
        return challenge

    async def solve(self, challenge: Challenge) -> Challenge:
        log.info("Web solving: %s", challenge.id)

        for fpath in challenge.files:
            if not fpath.exists():
                continue
            flag = self._scan_for_flag(fpath)
            if flag:
                challenge.flag = flag
                return challenge

        urls = re.findall(r"https?://[^\s,;'\"]+", challenge.description)
        for url in urls:
            flag = self._fetch_flag_endpoint(url)
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

    def _analyze_url(self, url: str) -> str | None:
        resp = self._fetch_url(url)
        if resp is None:
            return f"{url} -> unreachable"

        findings: list[str] = []
        if "flag" in resp.lower():
            findings.append(f"Flag keyword in response body")
        if "sql" in resp.lower() or "mysql" in resp.lower():
            findings.append(f"SQL error disclosure detected")

        parts = []
        if findings:
            parts.append(f"URL: {url}")
            parts.extend(findings)
            return "\n".join(parts)
        return f"{url} -> accessible ({len(resp)} bytes)"

    def _fetch_url(self, url: str) -> str | None:
        try:
            result = subprocess.run(
                ["curl", "-s", "-L", "--max-time", "10", url],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0:
                return result.stdout
        except FileNotFoundError:
            log.debug("curl not available")
        except Exception as e:
            log.debug("curl error for %s: %s", url, e)
        return None

    def _test_sqli(self, url: str, param: str) -> str | None:
        payloads = ["'", '"', "' OR '1'='1", "' OR 1=1 --"]
        parsed = list(urlparse(url))
        for payload in payloads:
            new_query = f"{param}={payload}"
            if parsed[4]:
                parsed[4] = re.sub(
                    rf"{re.escape(param)}=[^&]*", new_query, parsed[4]
                )
            else:
                parsed[4] = new_query
            test_url = parsed[0] + "://" + parsed[1] + parsed[2] + "?" + parsed[4]
            resp = self._fetch_url(test_url)
            if resp and ("sql" in resp.lower() or "error" in resp.lower()):
                return f"Potential SQLi on param '{param}' with payload: {payload}"
        return None

    def _fetch_flag_endpoint(self, base_url: str) -> str | None:
        for path in ["/flag", "/flag.txt", "/api/flag", "/admin/flag"]:
            resp = self._fetch_url(f"{base_url.rstrip('/')}{path}")
            if resp:
                match = re.search(
                    r"(flag|CTF)\{[^}]+\}", resp, re.IGNORECASE
                )
                if match:
                    return match.group(0)
        return None

    def _find_secrets(self, content: str, filename: str) -> str | None:
        secrets = []
        patterns = [
            (r"flag\{[^}]+\}", "Flag"),
            (r"CTF\{[^}]+\}", "CTF flag"),
            (r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*['\"][^'\"]+['\"]", "API key/secret"),
            (r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]+['\"]", "Password"),
            (r"(?i)sk-[a-zA-Z0-9]{20,}", "Secret key"),
        ]
        for pat, name in patterns:
            matches = re.findall(pat, content)
            if matches:
                secrets.append(f"  {name}: {matches[0][:50]}")
        if secrets:
            return f"Secrets in {filename}:\n" + "\n".join(secrets)
        return None

    def _scan_for_flag(self, path: Path) -> str | None:
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            match = re.search(
                r"(flag|CTF)\{[^}]+\}", content, re.IGNORECASE
            )
            if match:
                return match.group(0)
        except Exception:
            pass
        return None
