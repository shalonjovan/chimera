import base64

import pytest
from pathlib import Path

from chimera.core.models import Challenge, ChallengeCategory
from chimera.plugins.loader import PluginLoader

pytestmark = pytest.mark.skipif(
    not Path("vendor/cyberchef-bridge/bridge.mjs").exists(),
    reason="CyberChef bridge unavailable (run scripts/setup_cyberchef.sh)",
)

PLUGINS = PluginLoader().discover(Path("plugins"))


def _challenge(tmp_path: Path, content: bytes, name: str = "flag.txt") -> Challenge:
    f = tmp_path / name
    f.write_bytes(content)
    return Challenge(
        id=f"t-{name}",
        title="decode me",
        description="extract the flag",
        category=ChallengeCategory.crypto,
        files=[f],
    )


@pytest.fixture(scope="module")
def cyberchef_plugin():
    return next(p for p in PLUGINS if p.name == "cyberchef")


@pytest.fixture(scope="module")
def crypto_plugin():
    return next(p for p in PLUGINS if p.name == "crypto")


@pytest.mark.asyncio
async def test_cyberchef_plugin_solves_base64(tmp_path, cyberchef_plugin):
    raw = b"the flag is flag{cyberchef_solves_it}"
    ch = _challenge(tmp_path, base64.b64encode(raw))
    ch = await cyberchef_plugin.solve(ch)
    assert ch.flag == "flag{cyberchef_solves_it}"
    assert await cyberchef_plugin.verify(ch)


@pytest.mark.asyncio
async def test_cyberchef_plugin_solves_hex(tmp_path, cyberchef_plugin):
    raw = b"flag{hex_via_cyberchef}"
    ch = _challenge(tmp_path, raw.hex().encode(), name="flag.hex")
    ch = await cyberchef_plugin.solve(ch)
    assert ch.flag == "flag{hex_via_cyberchef}"


@pytest.mark.asyncio
async def test_cyberchef_plugin_solves_xor(tmp_path, cyberchef_plugin):
    text = b"flag{single_byte_xor}"
    keyed = bytes(b ^ 0x2A for b in text)
    ch = _challenge(tmp_path, base64.b64encode(keyed), name="xor.b64")
    ch = await cyberchef_plugin.solve(ch)
    assert ch.flag == "flag{single_byte_xor}"


@pytest.mark.asyncio
async def test_cyberchef_plugin_analyze_records_finding(tmp_path, cyberchef_plugin):
    ch = _challenge(tmp_path, base64.b64encode(b"base64 content here"), name="data.b64")
    ch = await cyberchef_plugin.analyze(ch)
    assert "[Cyberchef Analysis]" in ch.description


def test_cyberchef_plugin_detect_scores(tmp_path, cyberchef_plugin):
    ch = _challenge(tmp_path, base64.b64encode(b"x" * 50), name="long.b64")
    assert cyberchef_plugin.detect(ch) > 0.5


def test_cyberchef_plugin_detect_ignores_plain(tmp_path, cyberchef_plugin):
    ch = _challenge(tmp_path, b"just some ordinary text here")
    assert cyberchef_plugin.detect(ch) < 0.4


@pytest.mark.asyncio
async def test_crypto_plugin_solves_via_bridge(tmp_path, crypto_plugin):
    ch = _challenge(tmp_path, base64.b64encode(b"flag{crypto_bridge}"), name="flag.b64")
    ch = await crypto_plugin.solve(ch)
    assert ch.flag == "flag{crypto_bridge}"
    assert await crypto_plugin.verify(ch)


@pytest.mark.asyncio
async def test_crypto_plugin_verify_rejects_plain_text(tmp_path, crypto_plugin):
    ch = _challenge(tmp_path, b"no flag here")
    assert await crypto_plugin.verify(ch) is False
