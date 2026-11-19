"""DevOps agent: evaluates commands but never invokes a shell."""
from agents.common import evaluate, record_simulation, run_loop

AGENT = "devops-agent"

PROPOSALS = [
    "docker ps",
    "docker logs demo-api",
    "deploy demo-api",
]


def cycle(count):
    command = PROPOSALS[(count - 1) % len(PROPOSALS)]
    decision = evaluate(AGENT, command, "shell")
    verdict = decision.get("verdict")

    if verdict == "ALLOW":
        record_simulation(
            AGENT,
            f"Recorded simulated observation for proposal: {command}. No command was executed."
        )
        print(f"[{AGENT}] ALLOW: simulated service observation.", flush=True)
    else:
        print(f"[{AGENT}] {verdict}: operation not executed.", flush=True)


if __name__ == "__main__":
    run_loop(AGENT, cycle)
