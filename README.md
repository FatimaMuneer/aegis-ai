# AEGIS.AI

Accountability Layer for Autonomous AI Agents.

AEGIS sits between autonomous AI agents and the tools they invoke (SQL databases, shell/DevOps operations, SOC workflows, and MCP proxies). It evaluates proposed actions against YAML security policies, enforces safeguards, routes high-impact actions to human-in-the-loop review, and records every decision in a tamper-evident audit log.

---

## Key Features

- **Policy-Based Action Governance:** Evaluates SQL, shell/DevOps, SOC, and sandbox actions against configurable YAML policies (`database.yaml`, `devops.yaml`, `soc.yaml`, `general.yaml`, `learned.yaml`).
- **Domain-Specific Guards:** Dedicated guards for database queries (`db_guard.py`), operational/shell commands (`ops_guard.py`), security operations (`soc_guard.py`), sandbox execution (`sandbox_guard.py`), and MCP tool calls (`mcp_proxy.py`).
- **Tamper-Evident Audit Trail:** Records all evaluations, verdicts (`ALLOW`, `BLOCK`, `REVIEW`, `CORRECT`), and risk classifications with cryptographic chain verification (`/audit/verify`).
- **Human-in-the-Loop Review Queue:** Holds high-risk actions for explicit human approval or rejection via authenticated bearer token (`AEGIS_REVIEW_TOKEN`).
- **Real-Time Operations Dashboard:** Built-in FastAPI dashboard (`aegis/dashboard/operations.html`) featuring an interactive floating agent topology graph, live telemetry, decision intelligence charts, expandable module views, and a human review queue.
- **React + Vite Control Interface:** Standalone TypeScript/React frontend (`frontend/`) with ECharts visualizations and live event streaming.
- **Groq-Powered Accountability Analyst:** Conversational AI assistant (`aegis/assistant.py`, `aegis/intent.py`, `aegis/chat.py`) for querying governance decisions, audit records, and pending reviews.
- **Simulated Agent Suite:** Built-in Database, DevOps, and SOC agents (`agents/`) for end-to-end testing and live dashboard demonstrations.

---

## Repository Structure

```text
aegis-ai/
├── aegis/                      # Core Python backend package
│   ├── api.py                  # FastAPI application and dashboard server
│   ├── engine.py               # Core policy evaluation engine
│   ├── audit.py                # Tamper-evident audit log and integrity verification
│   ├── approvals.py            # Human-in-the-loop approval store
│   ├── agent_monitor.py        # Live status registry for simulated agents
│   ├── assistant.py            # Groq-powered conversational assistant
│   ├── chat.py                 # Chat routing and natural-language handling
│   ├── intent.py               # Natural-language intent classification
│   ├── cli.py                  # Command-line interface
│   ├── db_guard.py             # SQL query guard
│   ├── ops_guard.py            # Shell/DevOps command guard
│   ├── soc_guard.py            # Security operations guard
│   ├── sandbox.py              # Isolated sandbox execution
│   ├── sandbox_guard.py        # Sandbox policy enforcement
│   ├── mcp_proxy.py            # Model Context Protocol (MCP) security proxy
│   ├── risk.py                 # Risk classification and optional AI second opinion
│   ├── policy.py               # Policy loader
│   ├── policies/               # YAML policy definitions
│   └── dashboard/              # Built-in Operations Dashboard (operations.html, index.html, style.css)
├── agents/                     # Simulated agents (database, soc, devops, run_all.py)
├── frontend/                   # React + TypeScript + Vite web interface
├── scripts/                    # Demo data generators, evaluation harnesses, and simulators
├── tests/                      # Pytest unit and integration test suite
├── data/                       # Test cases and demo database location
├── results/                    # Guard and engine evaluation CSV outputs
└── requirements.txt            # Python dependencies
