import multiprocessing
from pathlib import Path

from aegis.audit import AuditLog


def _append_records(path, worker_id, count, errors):
    try:
        audit = AuditLog(path)
        for number in range(count):
            audit.append({
                "agent": f"worker-{worker_id}",
                "action": f"simulated-action-{number}",
                "verdict": "ALLOW",
            })
    except Exception as exc:
        errors.put(f"worker-{worker_id}: {type(exc).__name__}: {exc}")


def test_concurrent_processes_append_without_breaking_chain(tmp_path):
    path = str(tmp_path / "concurrent_audit.jsonl")
    worker_count = 4
    records_per_worker = 15

    context = multiprocessing.get_context("spawn")
    errors = context.Queue()
    processes = [
        context.Process(
            target=_append_records,
            args=(path, worker_id, records_per_worker, errors),
        )
        for worker_id in range(worker_count)
    ]

    for process in processes:
        process.start()

    for process in processes:
        process.join(timeout=30)

    for process in processes:
        if process.is_alive():
            process.terminate()
            process.join()
            raise AssertionError("A writer process timed out")

    failures = []
    while not errors.empty():
        failures.append(errors.get())

    assert all(process.exitcode == 0 for process in processes), (
        f"Writer process failed: {[p.exitcode for p in processes]}"
    )
    assert not failures, failures

    audit = AuditLog(path)
    entries = audit.read_all()

    assert len(entries) == worker_count * records_per_worker
    assert [entry["seq"] for entry in entries] == list(
        range(1, worker_count * records_per_worker + 1)
    )
    assert audit.verify() == (True, "log is intact")
