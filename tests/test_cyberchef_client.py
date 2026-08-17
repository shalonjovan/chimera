import base64

import pytest

from chimera.tools.cyberchef import (
    _format_output,
    _resolve_input,
    bridge,
)


@pytest.mark.asyncio
async def test_ping():
    version = await bridge.ping()
    assert version.startswith("cyberchef-")


@pytest.mark.asyncio
async def test_list_operations_contains_aes():
    ops = await bridge.list_operations()
    names = [o["name"] for o in ops]
    assert len(ops) > 400
    assert "AES Decrypt" in names
    assert "From Base64" in names


@pytest.mark.asyncio
async def test_get_operation_metadata():
    op = await bridge.get_operation("ROT13")
    assert op["name"] == "ROT13"
    assert any(a["name"] == "Amount" for a in op["args"])


@pytest.mark.asyncio
async def test_run_operation_from_base64():
    result = await bridge.run_operation(
        "From Base64", None, base64.b64encode(b"aGVsbG8gd29ybGQ=").decode()
    )
    assert result["outputText"] == "hello world"


@pytest.mark.asyncio
async def test_run_operation_aes_roundtrip():
    args = {
        "key": "000102030405060708090a0b0c0d0e0f",
        "iv": "101112131415161718191a1b1c1d1e1f",
        "mode": "CBC",
    }
    enc = await bridge.run_operation(
        "AES Encrypt", args, base64.b64encode(b"secret").decode()
    )
    cipher_hex = enc["outputText"]
    dec = await bridge.run_operation(
        "AES Decrypt", args, base64.b64encode(cipher_hex.encode()).decode()
    )
    assert dec["outputText"] == "secret"


@pytest.mark.asyncio
async def test_run_recipe_chain():
    result = await bridge.run_recipe(
        [{"op": "To Hex"}, {"op": "Reverse"}],
        base64.b64encode(b"abc").decode(),
    )
    assert result["outputText"] == "36 26 16"


@pytest.mark.asyncio
async def test_run_operation_unknown_name():
    with pytest.raises(Exception, match="Operation not found"):
        await bridge.run_operation("No Such Operation", None, None)


@pytest.mark.asyncio
async def test_bridge_recovers_after_error():
    with pytest.raises(Exception):
        await bridge.run_operation("No Such Operation", None, None)
    result = await bridge.run_operation(
        "From Base64", None, base64.b64encode(b"aGVsbG8gd29ybGQ=").decode()
    )
    assert result["outputText"] == "hello world"


def test_resolve_input_text():
    assert _resolve_input("hi", None) == base64.b64encode(b"hi").decode()


def test_resolve_input_b64_precedence():
    raw = base64.b64encode(b"hi").decode()
    assert _resolve_input("other", raw) == raw


def test_resolve_input_none():
    assert _resolve_input(None, None) is None


def test_format_output_omits_redundant_b64():
    result = {"outputType": "string", "outputText": "hello", "outputB64": base64.b64encode(b"hello").decode()}
    out = _format_output("x", result)
    assert "hello" in out
    assert "output_b64" not in out


def test_format_output_shows_different_b64():
    result = {"outputType": "string", "outputText": "text", "outputB64": "c29tZXRoaW5nZWxzZQ=="}
    out = _format_output("x", result)
    assert "c29tZXRoaW5nZWxzZQ==" in out
