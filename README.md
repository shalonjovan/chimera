# chimera

An MCP (Model Context Protocol) server that autonomously analyzes and solves
Capture The Flag (CTF) challenges by orchestrating specialized security tools
through a plugin architecture — now powered by
[CyberChef](https://github.com/gchq/CyberChef) for decoding and transformation.

Chimera is designed to continuously expand its capabilities through new
plugins, reusable patterns, and accumulated experience rather than relying
solely on an LLM. The system grows by adding structured knowledge — not by
silently rewriting itself.

## Highlights

- **CyberChef integration**: all 476 operations and full recipe chaining
  (base64, hex, ROT, AES, XOR brute force, Magic auto-detection, ...) exposed
  as MCP tools through a Node sidecar bridge.
- **8 challenge plugins**: `crypto`, `cyberchef`, `reverse`, `stego`,
  `forensics`, `web`, `pwn`, `osint` — each implementing the
  `detect/analyze/solve/verify` contract.
- **Challenge lifecycle pipeline**: detect category → analyze → solve →
  verify → archive, with retries and confidence scoring.
- **Multi-agent planner**: concurrent per-plugin agents racing to solve
  (Semaphore-capped, up to 5 at once).
- **Learning & memory**: three-tier memory (short/medium/long-term), a
  per-challenge knowledge archive, a YAML pattern library, and a failure →
  pattern-suggestion learning pipeline.
- **Opt-in Docker sandbox**: run untrusted artifacts with no network, read-only
  rootfs, 256 MB RAM, 1 CPU.
- **Two surfaces**: MCP tools over stdio/SSE for LLM clients, plus a rich
  Click CLI for humans.

## Architecture

```
LLM client
   │  MCP protocol (JSON-RPC)
   ▼
ChimeraServer (FastMCP) ── src/chimera/core/server.py
   │
   ├── Tools (MCP-exposed API)
   │    ├─ solve_challenge / search_knowledge / list_plugins
   │    ├─ shell_exec / filesystem_read|write|search
   │    └─ cyberchef_operations / cyberchef_operation / cyberchef_recipe
   │
   ├── ChallengePipeline        core/pipeline.py
   ├── Planner                  core/planner.py
   ├── MultiAgentPlanner        core/multi_agent.py
   ├── Plugin system            plugins/ (base, loader, registry)
   ├── ToolDispatcher           tools/dispatcher.py
   ├── MemoryEngine             memory/engine.py      (3 tiers)
   ├── KnowledgeSystem          knowledge/system.py   (per-challenge artifacts)
   ├── PatternLibrary           patterns/library.py   (YAML patterns)
   ├── LearningPipeline         core/learning.py      (failures → patterns)
   ├── Sandbox                  core/sandbox.py       (Docker, opt-in)
   └── Metrics                  core/metrics.py
```

CyberChef sidecar:

```
tools/cyberchef.py (Python asyncio JSON-RPC client)
   │  line-delimited JSON over stdio
   ▼
vendor/cyberchef-bridge/bridge.mjs (Node sidecar)
   │  imports generated node API
   ▼
vendor/cyberchef (git submodule, pinned to v10.24.0 — 476 operations)
```

## MCP tools

| Tool | Description |
|---|---|
| `solve_challenge(challenge_id, title, description, files?)` | Run the full lifecycle on a challenge; returns the Challenge as JSON |
| `search_knowledge(query)` | Search archived challenge knowledge (title/reasoning substring) |
| `list_plugins()` | List registered plugins and their categories |
| `cyberchef_operations [query]` | List/search operations with metadata (name, module, in/out types) |
| `cyberchef_operation <name> [args] [input] [input_b64]` | Run a single operation |
| `cyberchef_recipe <steps> [input] [input_b64]` | Chain operations, e.g. `[{"op": "From Base64"}, {"op": "XORBruteForce"}]` |
| `shell_exec(command, workdir?, timeout?)` | Run a shell command |
| `filesystem_read/write/search` | Read, write, and glob files |

## Challenge lifecycle

```
import → detect (category via plugin detection scores)
       → analyze (planner: hypotheses per plugin, sorted by confidence, ≤3 retries)
       → solve   (highest-confidence plugin attempts flag extraction)
       → verify  (plugin checks flag format)
       → archive (session JSON + long-term knowledge entry + reasoning/mistakes files)
```

The multi-agent planner is an alternative path: one agent per plugin-category
pair, all run concurrently; the challenge is solved if any agent succeeds.

## Plugin system

Plugins live in `plugins/<name>/` with a `manifest.yaml` plus a module named
after the plugin. Each plugin subclasses `BasePlugin`
(`src/chimera/plugins/base.py`) and implements:

- `detect(challenge) -> float` — score how likely this plugin applies (used for
  category detection and hypothesis ordering)
- `async analyze(challenge) -> Challenge` — append findings to `description`
- `async solve(challenge) -> Challenge` — attempt to set `challenge.flag`
- `async verify(challenge) -> bool` — validate a submitted flag

Example manifest:

```yaml
name: myplugin
version: 0.1.0
author: you
description: Does a thing
tools:
  - myplugin
dependencies: []
categories:
  - crypto
```

New plugins can be installed by dropping a directory into `plugins/` — no core
changes required. The loader dynamically imports the module and instantiates
the first `BasePlugin` subclass found.

### Built-in plugins

| Plugin | Categories | Approach |
|---|---|---|
| `cyberchef` | crypto, forensics, misc | decode ladder (base64 → hex → ROT13 → URL), XOR brute force, Magic auto-detection, flag extraction |
| `crypto` | crypto | encoding/cipher-signature detection, base64/hex decode → flag |
| `reverse` | reverse | magic-byte detection (ELF/PE/Mach-O/UPX), `file`/`strings` analysis |
| `web` | web | URL probing, common path discovery, SQLi payload testing, secret scanning |
| `stego` | stego | stego keyword detection, toolchain-driven analysis |
| `forensics` | forensics | forensics artifact detection, `file`/`binwalk`/`strings` |
| `pwn` | pwn | exploitation keyword detection |
| `osint` | osint | OSINT keyword detection, curl/dig based |

## Memory, knowledge, patterns

- **Short-term memory** — in-process dict keyed by challenge id.
- **Medium-term memory** — JSON session files in `data/sessions/`.
- **Long-term memory** — `data/chimera.db` (JSON file) holding knowledge
  entries, patterns, and failure records, loaded at startup and persisted on
  every mutation.
- **Knowledge archive** — `knowledge/<challenge_id>/` with
  `challenge.json`, `tools_used.json`, `reasoning.md`, `mistakes.md` written by
  the pipeline.
- **Pattern library** — `patterns/*.yaml`; matched by keyword conditions
  against challenge title/description, scored by matched-fraction × confidence.
  Pre-shipped examples: Base64 Encoded Flag, Håstad Broadcast, Format String
  Vulnerability, LSB Steganography.

## Setup

Requirements: Python 3.12+ (uv), Node.js 20+.

```bash
uv sync                        # install Python deps
bash scripts/setup_cyberchef.sh    # submodule, npm ci, Node 22+ patch, index regen, bridge ping check
.venv/bin/python -m pytest tests/  # run the test suite
```

The setup script patches CyberChef's `assert {type: "json"}` imports to
`with {type: "json"}` (required on Node 22+) and regenerates the node API index
(not committed upstream). Re-run it after any fresh submodule checkout.

## Configuration

Environment variables, prefix `CHIMERA_`, `.env` file supported.

| Variable | Default | Description |
|---|---|---|
| `CHIMERA_MCP_TRANSPORT` | `stdio` | Transport: `stdio` or `sse` |
| `CHIMERA_MCP_HOST` | `127.0.0.1` | SSE bind host |
| `CHIMERA_MCP_PORT` | `8100` | SSE bind port |
| `CHIMERA_CYBERCHEF_ENABLED` | `true` | Enable cyberchef tools |
| `CHIMERA_CYBERCHEF_NODE_PATH` | `node` | Node executable |
| `CHIMERA_CYBERCHEF_BRIDGE_PATH` | `vendor/cyberchef-bridge/bridge.mjs` | Bridge entry |
| `CHIMERA_CYBERCHEF_TIMEOUT` | `30.0` | Seconds per bridge request |
| `CHIMERA_SANDBOX_ENABLED` | `false` | Enable Docker sandbox |
| `CHIMERA_SANDBOX_IMAGE` | `python:3.12-slim` | Sandbox image |
| `CHIMERA_DATA_DIR` | `data` | Sessions + long-term db |
| `CHIMERA_PLUGINS_DIR` | `plugins` | Plugin directory |
| `CHIMERA_KNOWLEDGE_DIR` | `knowledge` | Knowledge archive |
| `CHIMERA_PATTERNS_DIR` | `patterns` | Pattern library |
| `CHIMERA_LOG_LEVEL` | `INFO` | Logging level |

## Running

```bash
.venv/bin/python -m chimera        # stdio transport (default) — MCP server for LLM clients
CHIMERA_MCP_TRANSPORT=sse .venv/bin/python -m chimera   # SSE on 127.0.0.1:8100
```

CLI:

```bash
chimera-cli solve <id> <title> <description> [--files f] [--category c]  # full pipeline
chimera-cli status        # metrics report (solve rate, failures, patterns...)
chimera-cli plugins       # list registered plugins
chimera-cli search <q>    # search archived knowledge
chimera-cli patterns      # list pattern library
chimera-cli show <id>     # show archived knowledge for a challenge
chimera-cli add_pattern <name> <conditions...> [--confidence 0.5] [--category c]
```

## CyberChef usage notes

- Recipe steps are `{"op": "Name", "args": {}}` objects; op names are
  case-insensitive. Use `cyberchef_operations` to discover names and args.
- `input_b64` is base64 of the raw input bytes — prefer it for binary data.
  Text inputs go in `input`.
- For binary results `outputBytesB64` carries the exact bytes; `outputText` may
  be lossy.
- Some ops are slow by design (`XOR Brute Force` with large samples, `Magic`
  with deep recursion) — tune their args or `CHIMERA_CYBERCHEF_TIMEOUT`.
- The bridge is a line-delimited JSON-RPC daemon; the Python client
  auto-restarts it on crash and when the event loop changes (it binds to the
  spawning loop).

## Project layout

```
src/chimera/
  __main__.py         server entry point (stdlib/SSE)
  cli/app.py          Click + rich CLI
  config/settings.py  pydantic-settings, CHIMERA_* env
  core/
    server.py         FastMCP wrapper
    tools.py          MCP tool registration (solve/search/plugins)
    pipeline.py       challenge lifecycle
    planner.py        hypothesis planning + retries + verify
    multi_agent.py    concurrent agent planner
    learning.py       failure → pattern suggestion pipeline
    sandbox.py        Docker sandbox
    metrics.py        metrics report
    models.py         pydantic models (Challenge, Hypothesis, Pattern, ...)
    exceptions.py
    logging.py
  memory/engine.py    short/medium/long-term memory
  knowledge/system.py per-challenge knowledge archive
  patterns/library.py YAML pattern matching
  plugins/            base, loader, registry
  tools/
    dispatcher.py     routes to builtins or plugins
    cyberchef.py      bridge client + MCP tools
    builtin/          shell_exec, filesystem tools
plugins/              challenge plugins (crypto, cyberchef, reverse, ...)
vendor/
  cyberchef-bridge/   Node JSON-RPC bridge daemon
  cyberchef/          git submodule (v10.24.0)
data/                 sessions + chimera.db (long-term memory)
knowledge/            per-challenge archives
patterns/             YAML pattern library
tests/                pytest suite (bridge round-trips, plugin end-to-end solves)
scripts/setup_cyberchef.sh
```

## Testing

```bash
.venv/bin/python -m pytest tests/
```

Covers: bridge protocol (ping, operation listing, AES round-trip, recipe
chaining, crash recovery), input/output serialization, and end-to-end plugin
solves (base64, hex, single-byte XOR). Plugin tests skip if the bridge is not
installed. The suite exercises the real Node bridge, which is why the Python
client restarts the bridge when the event loop changes (pytest-asyncio).

## Status / roadmap

Implemented across 5 phases (see git history):

- **Phase 1**: MCP server, planner, builtin shell/filesystem tools, challenge
  lifecycle
- **Phase 2**: crypto, reverse, stego, forensics plugins
- **Phase 3**: web, pwn, osint plugins
- **Phase 4**: knowledge system, pattern library, autonomous learning pipeline
- **Phase 5**: Docker sandbox, multi-agent planner, metrics & CLI

Not yet done: distributed solving, automated benchmark suite, LLM-driven
planning (LLM settings exist but the planner is heuristic-only), real flag
server verification, plugin marketplace.