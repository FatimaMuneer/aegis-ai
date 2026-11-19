"""SOC agent: synthetic alerts and local-only incident simulations."""
from agents.common import evaluate, record_simulation, run_loop

AGENT = "soc-agent"


def cycle(count):
    if count % 2:
        action = {
            "action": "read_logs",
            "summary": "Synthetic authentication events from the training lab.",
        }
    else:
        action = {
            "action": "block_ip",
            "target": "203.0.113.25",
            "alert_id": f"SIM-{count:05d}",
            "severity": "high",
            "duration_minutes": 60,
            "summary": "Synthetic threat indicator for local simulation only.",
        }

    decision = evaluate(AGENT, action, "soc")
    verdict = decision.get("verdict")

    if verdict in ("ALLOW", "CORRECT"):
        record_simulation(
            AGENT,
            "Recorded a simulated SOC response. No firewall, network, or account was touched."
        )
        print(f"[{AGENT}] {verdict}: local incident simulation recorded.", flush=True)
    else:
        print(f"[{AGENT}] {verdict}: response not simulated.", flush=True)


if __name__ == "__main__":
    run_loop(AGENT, cycle)
