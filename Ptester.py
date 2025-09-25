
#!/usr/bin/env python3
"""
Batching proxy tester (Ubuntu / Windows compatible)

- DEFAULT_IP_COUNT = 100 per batch
- Repeats batches until overall timeout (default 6h40m = 24000s)
- Appends results to results/* files (does NOT remove old results)
- Loads previous ALL_WORKING to avoid duplicates across runs
"""

import os
import threading
import argparse
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import shutil
import platform
import sys
import time
from datetime import datetime

# ---------- Config / defaults ----------
DEFAULT_IP_COUNT = 100           # changed to 100 per your request
DEFAULT_TIMEOUT = 3              # curl timeout per request
DEFAULT_MAX_WORKERS = 200         # concurrency (reduce for CI)
DEFAULT_OVERALL_TIMEOUT = 24000  # 6h40m in seconds (6*3600 + 40*60 = 24000)

RESULTS_DIR = "results"

OUT_FILES = {
    "http": os.path.join(RESULTS_DIR, "HTTP.txt"),
    "https": os.path.join(RESULTS_DIR, "HTTPS.txt"),
    "socks4": os.path.join(RESULTS_DIR, "SOCKS4.txt"),
    "socks5": os.path.join(RESULTS_DIR, "SOCKS5.txt"),
}
ALL_WORKING_FILE = os.path.join(RESULTS_DIR, "ALL_WORKING.txt")
SUMMARY_FILE = os.path.join(RESULTS_DIR, "summary.txt")

# --- Port Lists (same as before) ---
COMMON_PROXY_PORTS = [80, 8080, 3128, 1080, 9050, 8888, 8118, 8000]
ALT_HTTP_PORTS = [
    81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 591, 7080, 7081, 7088, 7090, 7443, 8001,
    8002, 8008, 8010, 8020, 8030, 8040, 8050, 8060, 8070, 8090, 8091, 8100, 8111,
    8123, 8180, 8181, 8200, 8222, 8250, 8280, 8282, 8300, 8310, 8333, 8380, 8400,
    8443, 8484, 8500, 8530, 8600, 8686, 8700, 8800, 8801, 8880, 8890, 8899, 8989,
    9001, 9080, 9090, 9100, 9191, 9200, 9300, 9443, 9500, 9530, 9555, 9600, 9700,
    9800, 9888, 9898, 9910, 9920, 9943, 9950, 9988
]
ALT_SOCKS_PORTS = [
    1081, 1085, 1090, 1099, 1100, 1111, 1145, 1180, 1181, 1185, 1188, 1189, 1194,
    4000, 4145, 4146, 4200, 4321, 4444, 4500, 5000, 5001, 5002, 5050, 5060, 5555,
    5656, 6000, 60088, 6080, 6100, 6200, 6666, 6667, 7000, 7070, 7300, 7444, 7500,
    7777, 7788, 7900, 8009, 8118, 8201, 8281, 8388, 8444, 8688, 8808, 8881, 9002,
    9091, 9101, 9300, 9998
]
ALL_COMMON_PORTS = sorted(list(set(COMMON_PROXY_PORTS + ALT_HTTP_PORTS + ALT_SOCKS_PORTS)))

lock = threading.Lock()
unique_proxies_found = set()  # loaded from existing ALL_WORKING at start

# ---------- Platform / curl detection ----------
IS_WINDOWS = platform.system().lower().startswith("windows")
CURL_CANDIDATES = ["curl", "curl.exe"]
curl_exe = None
for c in CURL_CANDIDATES:
    path = shutil.which(c)
    if path:
        curl_exe = path
        break

if not curl_exe:
    print("Error: curl not found on PATH. Please install curl on the runner (e.g. apt-get install -y curl).", file=sys.stderr)
    sys.exit(2)

# ---------- Helpers ----------
def ensure_results_dir():
    os.makedirs(RESULTS_DIR, exist_ok=True)

def load_existing_proxies():
    """Load previously-found proxies to avoid duplicates across runs."""
    ensure_results_dir()
    if os.path.exists(ALL_WORKING_FILE):
        try:
            with open(ALL_WORKING_FILE, "r", encoding="utf-8") as fh:
                for ln in fh:
                    ln = ln.strip()
                    if ln:
                        unique_proxies_found.add(ln)
        except Exception:
            pass

def save_working(proxy_str, proto_key):
    """Append proxy_str to corresponding output file (thread-safe)."""
    with lock:
        if proxy_str not in unique_proxies_found:
            # Append to ALL_WORKING
            with open(ALL_WORKING_FILE, "a", encoding="utf-8") as fh:
                fh.write(proxy_str + "\n")
            unique_proxies_found.add(proxy_str)

        # Append to protocol-specific file (duplicate prevention at ALL_WORKING level)
        fname = OUT_FILES[proto_key]
        with open(fname, "a", encoding="utf-8") as fh:
            fh.write(proxy_str + "\n")

def run_curl(args, timeout):
    """Run curl command, return True if successful (exit 0 and stdout)."""
    try:
        kwargs = dict(capture_output=True, text=True, timeout=timeout, check=False)
        if IS_WINDOWS:
            try:
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                kwargs["startupinfo"] = si
            except Exception:
                pass
        result = subprocess.run(args, **kwargs)
        return result.returncode == 0 and bool(result.stdout and result.stdout.strip())
    except Exception:
        return False

def test_http_proxy(proxy_str, timeout):
    args = [curl_exe, "-x", f"http://{proxy_str}", "-s", "-m", str(timeout), "http://httpbin.org/ip"]
    return run_curl(args, timeout)

def test_https_proxy(proxy_str, timeout):
    args = [curl_exe, "-x", f"http://{proxy_str}", "-s", "-m", str(timeout), "https://httpbin.org/ip"]
    return run_curl(args, timeout)

def test_socks4_proxy(proxy_str, timeout):
    args = [curl_exe, "--socks4", proxy_str, "-s", "-m", str(timeout), "https://httpbin.org/ip"]
    return run_curl(args, timeout)

def test_socks5_proxy(proxy_str, timeout):
    args = [curl_exe, "--socks5-hostname", proxy_str, "-s", "-m", str(timeout), "https://httpbin.org/ip"]
    return run_curl(args, timeout)

# ---------- IP generation ----------
def random_public_ipv4(rng):
    while True:
        a = rng.randint(1, 223)
        b = rng.randint(0, 255)
        c = rng.randint(0, 255)
        d = rng.randint(1, 254)
        if a == 10: continue
        if a == 127: continue
        if a == 169 and b == 254: continue
        if a == 172 and 16 <= b <= 31: continue
        if a == 192 and b == 168: continue
        if a >= 224: continue
        return f"{a}.{b}.{c}.{d}"

# ---------- Worker ----------
def worker_test(proxy_str, timeout):
    result = {"proxy": proxy_str, "http": False, "https": False, "socks4": False, "socks5": False}
    if test_http_proxy(proxy_str, timeout):
        result["http"] = True
        save_working(proxy_str, "http")
    if test_https_proxy(proxy_str, timeout):
        result["https"] = True
        save_working(proxy_str, "https")
    if test_socks4_proxy(proxy_str, timeout):
        result["socks4"] = True
        save_working(proxy_str, "socks4")
    if test_socks5_proxy(proxy_str, timeout):
        result["socks5"] = True
        save_working(proxy_str, "socks5")
    return result

# ---------- Batch run (single batch) ----------
def run_one_batch(batch_id, count, ports_to_test, timeout, max_workers, seed):
    rng = random.Random(seed)
    ips = [random_public_ipv4(rng) for _ in range(count)]
    proxies_to_test = [f"{ip}:{port}" for ip in ips for port in ports_to_test]
    rng.shuffle(proxies_to_test)

    total_combinations = len(proxies_to_test)
    print(f"[Batch {batch_id}] Total combinations: {total_combinations} (count={count})")

    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(worker_test, p, timeout): p for p in proxies_to_test}
        for i, fut in enumerate(as_completed(futures)):
            p = futures[fut]
            try:
                res = fut.result()
                results.append(res)
                ok = [k.upper() for k, v in res.items() if k != "proxy" and v]
                progress = f"[{i+1}/{total_combinations}]"
                if ok:
                    print(f"{progress} {p:<21} -> SUCCESS: {', '.join(ok)}")
            except Exception as exc:
                print(f"{p} generated exception: {exc}")

    # summary for this batch (append to summary file)
    good = sum(1 for r in results if any(v for k, v in r.items() if k != "proxy"))
    with lock:
        with open(SUMMARY_FILE, "a", encoding="utf-8") as sf:
            sf.write(f"Batch {batch_id} | {datetime.utcnow().isoformat()}Z | tested={len(results)} | good={good}\n")

    return len(results), good

# ---------- Main (loop batches until overall timeout) ----------
def main():
    parser = argparse.ArgumentParser(description="Batching proxy tester using curl")
    parser.add_argument("--count", type=int, default=DEFAULT_IP_COUNT, help="IPs per batch (default 100)")
    parser.add_argument("--max-workers", type=int, default=DEFAULT_MAX_WORKERS, help="Max concurrent workers")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Curl timeout in seconds")
    parser.add_argument("--port-list", choices=['common', 'all', 'custom'], default='common')
    parser.add_argument("--ports", type=str, help="Comma-separated custom ports (when --port-list=custom)")
    parser.add_argument("--seed", type=int, help="RNG seed (optional)")
    parser.add_argument("--overall-timeout", type=int, default=DEFAULT_OVERALL_TIMEOUT, help="Overall timeout in seconds (default 24000 = 6h40m)")
    parser.add_argument("--max-batches", type=int, default=0, help="Optional: maximum number of batches (0 = unlimited until timeout)")
    args = parser.parse_args()

    if args.port_list == 'custom' and not args.ports:
        parser.error("--ports required with --port-list=custom")

    # choose port set
    if args.port_list == 'common':
        ports_to_test = COMMON_PROXY_PORTS
    elif args.port_list == 'all':
        ports_to_test = ALL_COMMON_PORTS
    else:
        try:
            ports_to_test = [int(p.strip()) for p in args.ports.split(',') if p.strip()]
        except Exception:
            print("Error: --ports must be comma-separated integers", file=sys.stderr)
            return

    ensure_results_dir()
    load_existing_proxies()  # do not remove previous results; avoid duplicates
    print(f"Starting batch-run; existing unique proxies loaded: {len(unique_proxies_found)}")
    print(f"Using curl executable: {curl_exe}")
    start_time = time.time()
    batch_id = 0
    total_tested = 0
    total_good = 0

    try:
        while True:
            batch_id += 1
            batch_start = time.time()

            # Run a single batch
            tested, good = run_one_batch(batch_id, args.count, ports_to_test, args.timeout, args.max_workers, args.seed)
            total_tested += tested
            total_good += good

            elapsed = time.time() - start_time
            batch_elapsed = time.time() - batch_start
            remaining = args.overall_timeout - elapsed

            print(f"[Batch {batch_id}] finished in {int(batch_elapsed)}s; total elapsed {int(elapsed)}s; remaining {int(remaining)}s")
            # If max_batches set and reached -> stop
            if args.max_batches and batch_id >= args.max_batches:
                print(f"Reached max_batches={args.max_batches}; stopping.")
                break

            # If no time left, stop
            if remaining <= 0:
                print("Overall timeout reached; stopping further batches.")
                break

            # If we don't have enough remaining time for another reasonable batch,
            # stop. (We allow a small safety margin of 30s.)
            # Decision: if remaining <= 30s, break.
            if remaining <= 30:
                print("Not enough time remaining for another batch; stopping.")
                break

            # Otherwise, continue to next batch (immediately)
            print(f"Starting next batch (batch {batch_id+1})...")

    except KeyboardInterrupt:
        print("KeyboardInterrupt received — exiting gracefully.")

    # Overall summary
    elapsed_total = time.time() - start_time
    print("\nOverall run complete.")
    print(f"Total batches: {batch_id}")
    print(f"Total tested combos: {total_tested}")
    print(f"Total good proxies found (unique): {len(unique_proxies_found)}")
    print(f"Elapsed time: {int(elapsed_total)}s")

    with open(SUMMARY_FILE, "a", encoding="utf-8") as sf:
        sf.write(f"Overall | {datetime.utcnow().isoformat()}Z | batches={batch_id} | tested={total_tested} | unique_good={len(unique_proxies_found)} | elapsed_s={int(elapsed_total)}\n")

if __name__ == "__main__":
    main()
