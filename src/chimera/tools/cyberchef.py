from __future__ import annotations

import asyncio
import base64
import json
from typing import Any

from chimera.config.settings import settings
from chimera.core.exceptions import ToolExecutionError
from chimera.core.logging import get_logger

log = get_logger(__name__)


class CyberchefBridgeClient:
    """Line-delimited JSON-RPC client for vendor/cyberchef-bridge/bridge.mjs."""

    def __init__(self) -> None:
        self._proc: asyncio.subprocess.Process | None = None
        self._pending: dict[int, asyncio.Future[Any]] = {}
        self._reader_task: asyncio.Task[None] | None = None
        self._counter = 0
        self._lock = asyncio.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None

    async def _ensure_process(self) -> None:
        loop = asyncio.get_running_loop()
        # Subprocess transports are bound to the loop that spawned them.
        # Restart under the current loop if it changed (e.g. new event loop
        # per test, or a fork).
        if self._proc is not None and self._proc.returncode is None:
            if self._loop is loop:
                return
            self._kill_process()
        bridge = settings.cyberchef_bridge_path.resolve()
        if not bridge.exists():
            raise ToolExecutionError(
                f"CyberChef bridge not found: {bridge}. "
                "Run `bash scripts/setup_cyberchef.sh` to install it."
            )
        self._proc = await asyncio.create_subprocess_exec(
            settings.cyberchef_node_path,
            str(bridge),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            limit=16 * 1024 * 1024,
        )
        self._loop = loop
        self._pending = {}
        self._reader_task = asyncio.create_task(self._read_loop())
        log.debug("Started CyberChef bridge pid=%s", self._proc.pid)

    async def _read_loop(self) -> None:
        assert self._proc is not None and self._proc.stdout is not None
        while True:
            line = await self._proc.stdout.readline()
            if not line:
                error = ToolExecutionError("CyberChef bridge exited unexpectedly")
                for fut in self._pending.values():
                    if not fut.done():
                        fut.set_exception(error)
                self._pending.clear()
                return
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                log.warning("Discarded non-JSON bridge output: %r", line[:200])
                continue
            fut = self._pending.pop(msg.get("id"), None)
            if fut is None or fut.done():
                continue
            if msg.get("ok"):
                fut.set_result(msg.get("result"))
            else:
                fut.set_exception(
                    ToolExecutionError(msg.get("error") or "unknown bridge error")
                )

    async def _request(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> Any:
        timeout = timeout or settings.cyberchef_timeout
        async with self._lock:
            await self._ensure_process()
            self._counter += 1
            req_id = self._counter
            payload = json.dumps({"id": req_id, "method": method, "params": params or {}}) + "\n"
            loop = asyncio.get_running_loop()
            fut: asyncio.Future[Any] = loop.create_future()
            self._pending[req_id] = fut
            try:
                assert self._proc is not None and self._proc.stdin is not None
                self._proc.stdin.write(payload.encode("utf-8"))
                await self._proc.stdin.drain()
                return await asyncio.wait_for(fut, timeout)
            except asyncio.TimeoutError:
                self._pending.pop(req_id, None)
                raise ToolExecutionError(
                    f"CyberChef bridge timed out after {timeout}s ({method})"
                )
            except (BrokenPipeError, ConnectionResetError):
                await self._restart()
                raise ToolExecutionError("CyberChef bridge crashed during request")
            except Exception:
                self._pending.pop(req_id, None)
                raise

    async def _restart(self) -> None:
        self._kill_process()
        log.warning("Restarted CyberChef bridge")

    def _kill_process(self) -> None:
        if self._reader_task is not None:
            self._reader_task.cancel()
        if self._proc is not None and self._proc.returncode is None:
            self._proc.kill()
        self._proc = None
        self._reader_task = None
        self._loop = None

    async def ping(self) -> str:
        result = await self._request("ping")
        return str(result.get("version", "unknown"))

    async def list_operations(self) -> list[dict[str, Any]]:
        result = await self._request("list_operations")
        return result.get("operations", [])

    async def get_operation(self, name: str) -> dict[str, Any]:
        return await self._request("get_operation", {"name": name})

    async def run_operation(
        self,
        name: str,
        args: dict[str, Any] | None = None,
        input_b64: str | None = None,
    ) -> dict[str, Any]:
        return await self._request(
            "run_operation",
            {"name": name, "args": args, "inputB64": input_b64},
        )

    async def run_recipe(
        self,
        recipe: list[dict[str, Any]],
        input_b64: str | None = None,
    ) -> dict[str, Any]:
        return await self._request(
            "run_recipe",
            {"recipe": recipe, "inputB64": input_b64},
        )

    async def close(self) -> None:
        self._kill_process()


bridge = CyberchefBridgeClient()


def _resolve_input(input_text: str | None, input_b64: str | None) -> str | None:
    if input_b64 is not None:
        try:
            return input_b64
        except Exception as e:
            raise ToolExecutionError(f"Invalid input_b64: {e}")
    if input_text is not None:
        return base64.b64encode(input_text.encode("utf-8")).decode("ascii")
    return None


async def cyberchef_operations(query: str | None = None) -> str:
    """List all CyberChef operations (476 total), optionally filtered by a
    case-insensitive substring match on the operation name or description."""
    ops = await bridge.list_operations()
    if query:
        needle = query.lower()
        ops = [
            o
            for o in ops
            if needle in o["name"].lower()
            or needle in (o.get("description") or "").lower()
        ]
    if not ops:
        return f"No CyberChef operations match '{query}'. Use cyberchef_operations with a broader query."
    lines = [
        f"{o['name']} [{o.get('module')}] in={o.get('inputType')} out={o.get('outputType')}"
        for o in ops
    ]
    if len(lines) > 100:
        lines = lines[:100] + [f"... and {len(ops) - 100} more"]
    return "\n".join(lines)


async def cyberchef_operation(
    name: str,
    args: dict[str, Any] | None = None,
    input: str | None = None,
    input_b64: str | None = None,
) -> str:
    """Run a single CyberChef operation (e.g. FromBase64, AESDecrypt, ROT13,
    XORBruteForce). `input` is plain text; `input_b64` is base64 of the raw
    bytes (use when input is binary). Operation-specific arguments go in
    `args`; see cyberchef_operations for arg names and defaults."""
    payload = _resolve_input(input, input_b64)
    result = await bridge.run_operation(name, args, payload)
    return _format_output(name, result)


async def cyberchef_recipe(
    recipe: list[dict[str, Any]],
    input: str | None = None,
    input_b64: str | None = None,
) -> str:
    """Run a chain of CyberChef operations, e.g. [{"op": "FromBase64"},
    {"op": "XORBruteForce"}]. Each step is {"op": "<name>", "args": {...}};
    args are optional and default to the operation's defaults."""
    if not recipe or not isinstance(recipe, list):
        raise ToolExecutionError("recipe must be a non-empty list of {op, args} objects")
    payload = _resolve_input(input, input_b64)
    steps = []
    for step in recipe:
        if not isinstance(step, dict) or not step.get("op"):
            raise ToolExecutionError(f"Invalid recipe step: {step!r}")
        steps.append({"op": step["op"], "args": step.get("args") or {}})
    result = await bridge.run_recipe(steps, payload)
    return _format_output("recipe", result)


def _format_output(label: str, result: dict[str, Any]) -> str:
    lines = [f"[{label}] outputType={result.get('outputType')}"]
    text = result.get("outputText") or ""
    b64 = result.get("outputB64") or ""
    bytes_b64 = result.get("outputBytesB64")
    if text:
        lines.append(text)
    if b64 and b64 != base64.b64encode(text.encode("utf-8")).decode("ascii"):
        lines.append(f"output_b64: {b64}")
    if bytes_b64 and bytes_b64 != b64:
        lines.append(f"output_bytes_b64: {bytes_b64}")
    return "\n".join(lines)
