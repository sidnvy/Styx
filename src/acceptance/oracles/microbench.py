"""Observer-cost micro-measurement only; no product/IPC/executor performance claim."""
import argparse
import json
import math
import os
from pathlib import Path
import platform
import sys
import time
from oracles import linux_process_identity


def measure(samples=1000):
    if type(samples) is not int or not 20 <= samples <= 10000:
        raise ValueError("samples_20_to_10000_required")
    timings = []
    for _ in range(20):
        linux_process_identity(os.getpid())
    for _ in range(samples):
        start = time.monotonic_ns()
        observed = linux_process_identity(os.getpid())
        timings.append(time.monotonic_ns() - start)
        if observed["status"] != "OBSERVED":
            return {"status": "UNSUPPORTED", "reason": "native_kernel_observer_unavailable"}
    ordered = sorted(timings)
    return {"status": "MEASURED_ONLY", "workload": "observer-self-kernel-identity-v1",
            "scope": "observer overhead; NOT Styx, executor, IPC, cold login or release performance",
            "python": sys.version.split()[0], "os": platform.system(), "arch": platform.machine(),
            "clock": "monotonic_ns", "warmup": 20, "concurrency": 1,
            "samples_ns": timings, "median_ns": ordered[len(ordered)//2],
            "p95_nearest_rank_ns": ordered[math.ceil(0.95*len(ordered))-1],
            "max_ns": max(ordered), "product_performance": "NOT_RUN"}

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", type=int, default=1000)
    args = parser.parse_args()
    print(json.dumps(measure(args.samples), indent=2))
