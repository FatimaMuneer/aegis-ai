# AEGIS simulated agents

These are local demonstration agents, not production integrations.

## Start
Start the AEGIS API in one terminal:
`python -m uvicorn aegis.api:app --reload`

Start all three independent agent processes in another:
`python -m agents.run_all`

## Stop
Press Ctrl+C in the agent terminal.

## Safety boundaries
- Database agent uses only agents/data/database_demo.sqlite3.
- SOC agent uses synthetic events and local records only.
- DevOps agent never executes shell commands.
- All proposals are evaluated by POST /evaluate.
- REVIEW and BLOCK proposals are not simulated.
- If the API is unavailable, agents fail closed.
- ALLOW/CORRECT never authorizes real-world execution.

Runtime state and logs are stored under agents/data/.
