from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from chimera.config.settings import settings
from chimera.core.exceptions import SandboxError
from chimera.core.logging import get_logger

log = get_logger(__name__)


class Sandbox:
    def __init__(self) -> None:
        self._enabled = settings.sandbox_enabled
        self._image = settings.sandbox_image

    async def execute(
        self,
        command: str,
        files: list[Path] | None = None,
        timeout: int = 60,
    ) -> str:
        if not self._enabled:
            raise SandboxError("Sandbox is disabled. Enable with CHIMERA_SANDBOX_ENABLED=true")

        if not self._has_docker():
            raise SandboxError("Docker not available")

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            for f in (files or []):
                if f.exists():
                    dest = tmp / f.name
                    dest.write_bytes(f.read_bytes())

            cmd = [
                "docker", "run", "--rm",
                "--network", "none",
                "--memory", "256m",
                "--cpus", "1",
                "--read-only",
                "-v", f"{tmp}:/work:ro",
                "-w", "/work",
                self._image,
                "sh", "-c", command,
            ]

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
                output = result.stdout
                if result.stderr:
                    output += f"\n[stderr]\n{result.stderr}"
                if result.returncode != 0:
                    raise SandboxError(
                        f"Sandbox command exited {result.returncode}:\n{output}"
                    )
                return output
            except subprocess.TimeoutExpired:
                raise SandboxError(f"Sandbox command timed out ({timeout}s)")
            except SandboxError:
                raise
            except Exception as e:
                raise SandboxError(f"Sandbox execution error: {e}")

    def _has_docker(self) -> bool:
        try:
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True, text=True, timeout=10,
            )
            return result.returncode == 0
        except Exception:
            return False


sandbox = Sandbox()
