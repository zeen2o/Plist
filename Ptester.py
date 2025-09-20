#!/usr/bin/env python3
"""
Cross-platform proxy tester using curl (works on Windows and Ubuntu/GitHub Actions).

Writes outputs into the `results/` folder:
  results/HTTP.txt
  results/HTTPS.txt
  results/SOCKS4.txt
  results/SOCKS5.txt
  results/ALL_WORKING.txt
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

# ---------- Config / defaults ----------
DEFAULT_IP_COUNT = 200
DEFAULT_TIMEOUT = 3
# Lowered default a bit for CI runners (adjust as needed)
DEFAULT_MAX_WORKERS = 50

RESULTS_DIR = "results"

OUT_FILES = {
    "http": os.path.join(RESULTS_DIR, "HTTP.txt"),
    "https": os.path.join(RESULTS_DIR, "HTTPS.txt"),
    "socks4": os.path.join(RESULTS_DIR, "SOCKS4.txt"),
    "socks5": os.path.join(RESULTS_DIR, "SOCKS5.txt"),
}
ALL_WORKING_FILE = os.path.join(RESULTS_DIR, "ALL_WORKING.txt")

# --- Port Lists ---
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
unique_proxies_found = set()

# ---------- Platform / curl detection ----------
IS_WINDOWS = platform.system().lower().startswith("windows")
# prefer native curl if available
CURL_CANDIDATES = ["curl", "curl.exe"]
curl_exe = None
for c in CURL_CANDIDATES:
    path = shutil.which(c)
    if path:
        curl_exe = path
        break

if not curl_exe:
    print("Error: curl not found on PATH. Please install curl on the runner (e.g. apt-get install -y curl).", file=sys.stderr)
    # Exit non-zero so CI shows failure — user can change this behavior
    sys.exit(2)

# ---------- Helpers ----------
def ensure_results_dir():
    os.makedirs(RESULTS_DIR, exist_ok=True)

def clear_output_files():
    ensure_results_dir()
    for f in OUT_FILES.values():
        open(f, "w", encoding="utf-8").close()
    open(ALL_WORKING_FILE, "w", encoding="utf-8").close()

def save_working(proxy_str, proto_key):
    """Append proxy_str to corresponding output file (thread-safe)."""
    with lock:
        # Avoid writing duplicates to the ALL_WORKING file
        if proxy_str not in unique_proxies_found:
            with open(ALL_WORKING_FILE, "a", encoding="utf-8") as fh:
                fh.write(proxy_str + "\n")
            unique_proxies_found.add(proxy_str)

        fname = OUT_FILES[proto_key]
        with open(fname, "a", encoding="utf-8") as fh:
            fh.write(proxy_str + "\n")

def run_curl(args, timeout):
    """Run curl command, return True if successful (exit 0 and stdout)."""
    try:
        # On Windows you might use STARTUPINFO to hide console; on Linux it's not needed.
        # We will not set startupinfo on non-Windows to keep compatibility.
        kwargs = dict(capture_output=True, text=True, timeout=timeout, check=False)
        if IS_WINDOWS:
            try:
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                kwargs["startupinfo"] = si
            except Exception:
                # If STARTUPINFO isn't available for any reason, ignore it.
                pass

        result = subprocess.run(args, **kwargs)
        return result.returncode == 0 and bool(result.stdout)
    except Exception:
        return False

def test_http_proxy(proxy_str, timeout):
    # -x proxy, using http scheme
    args = [curl_exe, "-x", f"http://{proxy_str}", "-s", "-m", str(timeout), "http://httpbin.org/ip"]
    return run_curl(args, timeout)

def test_https_proxy(proxy_str, timeout):
    args = [curl_exe, "-x", f"http://{proxy_str}", "-s", "-m", str(timeout), "https://httpbin.org/ip"]
    return run_curl(args, timeout)

def test_socks4_proxy(proxy_str, timeout):
    # --socks4 uses socks4 proxy
    args = [curl_exe, "--socks4", proxy_str, "-s", "-m", str(timeout), "https://httpbin.org/ip"]
    return run_curl(args, timeout)

def test_socks5_proxy(proxy_str, timeout):
    # --socks5-hostname resolves via proxy which often matches desired behavior
    args = [curl_exe, "--socks5-hostname", proxy_str, "-s", "-m", str(timeout), "https://httpbin.org/ip"]
    return run_curl(args, timeout)

# ---------- IP generation (avoid private/multicast/reserved ranges) ----------
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
    """Tests a single proxy_str against all protocols and returns results."""
    result = {"proxy": proxy_str, "http": False, "https": False, "socks4": False, "socks5": False}
    
    # Test protocols, save if working
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

# ---------- Main ----------
def main():
    parser = argparse.ArgumentParser(description="Generate random IPs and test multiple ports on each with curl")
    parser.add_argument("--count", type=int, default=DEFAULT_IP_COUNT, help="Number of random IP addresses to generate and test")
    parser.add_argument("--max-workers", type=int, default=DEFAULT_MAX_WORKERS, help="Max concurrent workers")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Curl timeout in seconds")
    parser.add_argument("--port-list", choices=['common', 'all', 'custom'], default='common', help="Which list of ports to test against each IP. Use 'custom' with the --ports argument.")
    parser.add_argument("--ports", type=str, help="Comma-separated list of ports to test (required if --port-list=custom)")
    parser.add_argument("--seed", type=int, help="Optional RNG seed for reproducible IP generation")
    args = parser.parse_args()

    # --- Validate arguments ---
    if args.port_list == 'custom' and not args.ports:
        parser.error("--ports is required when using --port-list=custom")

    # --- Determine port list ---
    ports_to_test = []
    if args.port_list == 'common':
        ports_to_test = COMMON_PROXY_PORTS
    elif args.port_list == 'all':
        ports_to_test = ALL_COMMON_PORTS
    elif args.port_list == 'custom':
        try:
            ports_to_test = [int(p.strip()) for p in args.ports.split(',') if p.strip()]
        except ValueError:
            print("Error: --ports must be a comma-separated list of numbers.", file=sys.stderr)
            return

    rng = random.Random(args.seed)

    # --- Generate IPs and create all test combinations ---
    print(f"Using curl executable: {curl_exe}")
    print(f"Generating {args.count} random IPs and testing against {len(ports_to_test)} ports each.")
    ips = [random_public_ipv4(rng) for _ in range(args.count)]
    proxies_to_test = [f"{ip}:{port}" for ip in ips for port in ports_to_test]
    
    # Shuffle to distribute requests across different IPs
    rng.shuffle(proxies_to_test)
    
    total_combinations = len(proxies_to_test)
    print(f"Total combinations to test: {total_combinations}")
    print(f"Using max_workers={args.max_workers}, timeout={args.timeout}s, seed={args.seed}")

    clear_output_files()

    results = []
    try:
        with ThreadPoolExecutor(max_workers=args.max_workers) as ex:
            futures = {ex.submit(worker_test, p, args.timeout): p for p in proxies_to_test}
            
            for i, fut in enumerate(as_completed(futures)):
                p = futures[fut]
                try:
                    res = fut.result()
                    results.append(res)
                    ok = [k.upper() for k, v in res.items() if k != "proxy" and v]
                    
                    # Show progress and result
                    progress = f"[{i+1}/{total_combinations}]"
                    if ok:
                        print(f"{progress} {p:<21} -> SUCCESS: {', '.join(ok)}")

                except Exception as exc:
                    print(f"{p} generated exception: {exc}")
    except KeyboardInterrupt:
        print("KeyboardInterrupt received — shutting down workers...")

    # --- Summary ---
    total_tested = len(results)
    good = sum(1 for r in results if any(v for k, v in r.items() if k != "proxy"))
    print(f"\nTest complete. Tested {total_tested} IP:port combinations.")
    print(f"Found {good} working proxy connections from {len(unique_proxies_found)} unique IPs.")

    for proto, fname in OUT_FILES.items():
        try:
            with open(fname, "r", encoding="utf-8") as fh:
                count = sum(1 for _ in fh)
            print(f"  {proto.upper():6}: {count} saved -> {fname}")
        except Exception:
            print(f"  {proto.upper():6}: error reading {fname}")

if __name__ == "__main__":
    main()
