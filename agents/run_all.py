"""Launch the three simulated agents as separate Python processes."""
import subprocess
import sys
import time

MODULES = [
    "agents.database_agent",
    "agents.soc_agent",
    "agents.devops_agent",
]


def main():
    processes = []
    try:
        for module in MODULES:
            print(f"[AEGIS] Launching {module}", flush=True)
            processes.append(
                subprocess.Popen([sys.executable, "-m", module])
            )
        print("[AEGIS] Three agent processes started. Press Ctrl+C to stop.", flush=True)
        while True:
            for process in processes:
                if process.poll() is not None:
                    print(
                        f"[AEGIS] Agent process exited with code {process.returncode}.",
                        flush=True,
                    )
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[AEGIS] Stopping agent processes...", flush=True)
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        print("[AEGIS] Process manager stopped.", flush=True)


if __name__ == "__main__":
    main()
