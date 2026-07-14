# PRD --- Autonomous CTF Solver MCP Server

**Project Name:** Chimera (working title)

## 1. Vision

Build a modular MCP server that can autonomously analyze, reason about,
and solve Capture The Flag (CTF) challenges across all major categories
by orchestrating specialized cybersecurity tools.

The system is designed to continuously expand its capabilities through
new plugins, reusable patterns, and accumulated experience rather than
relying solely on an LLM.

------------------------------------------------------------------------

# 2. Goals

-   Solve challenges from multiple CTF domains.
-   Use LLMs primarily for planning and orchestration.
-   Execute specialized security tools automatically.
-   Support human-in-the-loop workflows.
-   Learn from solved and failed challenges.
-   Allow new tools to be added without modifying core code.
-   Maintain reproducible execution.

------------------------------------------------------------------------

# 3. Non-Goals

-   Guarantee solving every challenge.
-   Automatically modify trusted production code.
-   Replace professional penetration testing.

------------------------------------------------------------------------

# 4. High-Level Architecture

``` text
                    Client
                       │
                 MCP Server
                       │
      ┌────────────────┴──────────────┐
      │                               │
 Planner / Coordinator           Memory Engine
      │                               │
      └──────────────┬────────────────┘
                     │
              Tool Dispatcher
                     │
 ┌────────────────────────────────────────────┐
 │ Crypto │ Reverse │ Web │ Pwn │ OSINT │ ... │
 └────────────────────────────────────────────┘
```

------------------------------------------------------------------------

# 5. Core Components

## Planner

Responsible for: - Hypothesis generation - Tool selection - Execution
planning - Confidence scoring - Retry strategy

## Tool Dispatcher

Responsibilities: - Discover plugins - Validate arguments - Execute
tools - Collect outputs - Normalize responses

## Memory Engine

Three levels:

### Short-term

Current challenge context.

### Medium-term

Competition/session knowledge.

### Long-term

Patterns, heuristics, playbooks and benchmarks.

------------------------------------------------------------------------

# 6. Supported Domains

-   Cryptography
-   Reverse Engineering
-   Binary Exploitation
-   Web Exploitation
-   Forensics
-   Steganography
-   OSINT
-   Mobile
-   Blockchain
-   Hardware
-   Wireless
-   Miscellaneous

------------------------------------------------------------------------

# 7. Plugin System

Directory:

``` text
plugins/
    crypto/
    reverse/
    web/
    pwn/
    osint/
    forensics/
```

Each plugin exposes:

-   detect()
-   analyze()
-   solve()
-   verify()

Manifest:

``` yaml
name:
version:
author:
tools:
dependencies:
categories:
```

------------------------------------------------------------------------

# 8. Knowledge System

Every challenge creates:

``` text
knowledge/
    challenge_id/
        challenge.json
        reasoning.md
        commands.log
        tools_used.json
        artifacts/
        mistakes.md
        patterns.json
```

------------------------------------------------------------------------

# 9. Pattern Library

Patterns stored as YAML.

Example:

``` yaml
name: Hastad Broadcast
conditions:
  - rsa
  - e=3
confidence: 0.94
required_tools:
  - sage
```

------------------------------------------------------------------------

# 10. Failure Database

Store: - Failed hypotheses - Failed commands - Tool limitations - False
positives - Lessons learned

------------------------------------------------------------------------

# 11. Autonomous Learning

Pipeline:

1.  Detect failure
2.  Search references
3.  Suggest new pattern/tool
4.  Human review
5.  Test
6.  Merge into knowledge/plugin repository

The system grows by adding structured knowledge---not by silently
rewriting itself.

------------------------------------------------------------------------

# 12. Challenge Lifecycle

1.  Import challenge
2.  Detect challenge type
3.  Generate hypotheses
4.  Execute tools
5.  Evaluate evidence
6.  Iterate
7.  Verify flag
8.  Archive knowledge

------------------------------------------------------------------------

# 13. Execution Sandbox

Execute binaries and untrusted artifacts inside isolated environments.

Preferred: - Docker - Podman - Firecracker (future)

------------------------------------------------------------------------

# 14. Suggested Tooling

## Reverse

-   Ghidra
-   Cutter
-   radare2
-   rizin
-   gdb
-   pwndbg
-   angr

## Crypto

-   SageMath
-   PyCryptodome
-   SymPy
-   RsaCtfTool
-   z3

## Web

-   ffuf
-   sqlmap
-   Burp
-   curl
-   Playwright

## OSINT

-   SearXNG
-   crt.sh
-   WHOIS
-   Shodan
-   Censys
-   Wayback Machine

## Forensics

-   binwalk
-   exiftool
-   foremost
-   bulk_extractor
-   volatility

## Stego

-   zsteg
-   steghide
-   stegsolve

------------------------------------------------------------------------

# 15. Metrics

-   Solve rate
-   Time to first hypothesis
-   Tool success rate
-   False positive rate
-   Pattern reuse rate
-   Human interventions
-   Knowledge growth
-   Plugin count

------------------------------------------------------------------------

# 16. Roadmap

## Phase 1

-   MCP server
-   Planner
-   Python
-   Shell
-   Filesystem

## Phase 2

-   Crypto
-   Reverse
-   Stego
-   Forensics

## Phase 3

-   Web
-   Pwn
-   OSINT

## Phase 4

-   Multi-agent planning
-   Long-term memory
-   Knowledge retrieval

## Phase 5

-   Distributed solving
-   Automated benchmarking

------------------------------------------------------------------------

# 17. Future Ideas

-   Multi-agent specialization
-   Vision-assisted solving
-   Retrieval over public writeups
-   Automatic benchmark suite
-   Community plugin marketplace
-   Challenge similarity search
-   Local model support
-   Cloud execution workers

------------------------------------------------------------------------

# 18. Success Criteria

The project is successful when:

-   New plugins can be installed without modifying the core.
-   Solved challenges improve future performance through reusable
    knowledge.
-   Every execution is reproducible and reviewable.
-   The planner orchestrates tools instead of hardcoding solutions.
-   The platform remains modular, secure, and extensible.
