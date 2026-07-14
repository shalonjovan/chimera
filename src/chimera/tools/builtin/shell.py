from __future__ import annotations

import subprocess
from pathlib import Path

from chimera.core.exceptions import ToolExecutionError, ValidationError


def shell_exec(
    command: str,
    workdir: str | None = None,
    timeout: int = 30,
) -> str:
    if not command or not command.strip():
        raise ValidationError("Command cannot be empty")

    cwd = Path(workdir).resolve() if workdir else None
    if cwd and not cwd.is_dir():
        raise ValidationError(f"Working directory does not exist: {cwd}")

    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
        )
        output = ""
        if result.stdout:
            output += result.stdout
        if result.stderr:
            if output:
                output += "\n"
            output += result.stderr
        if result.returncode != 0:
            raise ToolExecutionError(
                f"Command exited with code {result.returncode}:\n{output}"
            )
        return output
    except subprocess.TimeoutExpired:
        raise ToolExecutionError(f"Command timed out after {timeout}s")
    except ToolExecutionError:
        raise
    except Exception as e:
        raise ToolExecutionError(f"Command execution failed: {e}")
