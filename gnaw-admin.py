#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import contextlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time

STATE_DIR_SYS = "/run/gnaw"
LOG_DIR_SYS = "/var/log/gnaw"

def ensure_dir(path):
    try:
        os.makedirs(path, exist_ok=True)
        return True
    except Exception:
        return False

def choose_state_dir():
    if ensure_dir(STATE_DIR_SYS):
        return STATE_DIR_SYS
    tmp = "/tmp/gnaw"
    ensure_dir(tmp)
    return tmp

def choose_log_path():
    if ensure_dir(LOG_DIR_SYS):
        return os.path.join(LOG_DIR_SYS, "gnaw.log")
    tmp = "/tmp/gnaw.log"
    return tmp

STATE_DIR = choose_state_dir()
PID_FILE = os.path.join(STATE_DIR, "gnaw.pid")
STATE_FILE = os.path.join(STATE_DIR, "state.json")
LOG_PATH = choose_log_path()

def must_root():
    if os.geteuid() != 0:
        print("This helper must run as root (use pkexec).", file=sys.stderr)
        sys.exit(1)

def read_pid():
    try:
        with open(PID_FILE, "r", encoding="utf-8") as f:
            return int(f.read().strip())
    except Exception:
        return None

def proc_alive(pid):
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except Exception:
        return False

def kill_group(pid):
    try:
        os.killpg(pid, signal.SIGTERM)
    except Exception:
        pass
    time.sleep(0.3)
    try:
        os.killpg(pid, signal.SIGKILL)
    except Exception:
        pass

def write_state(d):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=2)

def resolve_gnaw_bin():
    # System install path
    for name in ("gnaw", "/usr/bin/gnaw"):
        if shutil.which(name):
            return shutil.which(name) or name
        if os.path.isfile(name) and os.access(name, os.X_OK):
            return name
    # Local fallback (same dir as this helper)
    here = os.path.dirname(os.path.abspath(__file__))
    for name in ("gnaw.py", "gnaw"):
        p = os.path.join(here, name)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    # Try current directory
    for name in ("./gnaw.py", "./gnaw"):
        if os.path.isfile(name) and os.access(name, os.X_OK):
            return os.path.abspath(name)
    return None

def start_mim(outer_ep, outer_bind, inner_ep, inner_bind, register_inner=False, warp_check=False, udp_over_tcp=False):
    gnaw = resolve_gnaw_bin()
    if not gnaw:
        print("gnaw not found. Install it or place gnaw.py next to gnaw_admin.py.", file=sys.stderr)
        sys.exit(1)

    pid = read_pid()
    if proc_alive(pid):
        print("already running")
        return

    # Open log file (append)
    try:
        lf = open(LOG_PATH, "a", buffering=1)
    except Exception:
        lf = open("/tmp/gnaw.log", "a", buffering=1)

    cmd = [
        gnaw,
        "--mim-run",
        "--endpoint", outer_ep, "--bind", outer_bind,
        "--mim-inner-endpoint", inner_ep, "--mim-inner-bind", inner_bind,
        "--mim-tun4", "172.19.0.1/30",
    ]
    if register_inner: cmd.append("--mim-register-inner")
    if warp_check: cmd.append("--mim-warp-check")
    if udp_over_tcp: cmd.append("--mim-udp-over-tcp")

    env = os.environ.copy()
    p = subprocess.Popen(
        cmd,
        stdout=lf,
        stderr=lf,
        start_new_session=True,  # new pgid for clean stop
        env=env,
    )
    with open(PID_FILE, "w", encoding="utf-8") as f:
        f.write(str(p.pid))
    write_state({
        "pid": p.pid,
        "cmd": cmd,
        "log": LOG_PATH,
        "t": int(time.time()),
        "mode": "mim",
        "outer_bind": outer_bind,
        "inner_bind": inner_bind,
        "outer_ep": outer_ep,
        "inner_ep": inner_ep,
        "udp_over_tcp": bool(udp_over_tcp),
        "register_inner": bool(register_inner),
    })
    print("started")

def stop_all():
    pid = read_pid()
    if not proc_alive(pid):
        print("not running")
        with contextlib.suppress(Exception): os.remove(PID_FILE)
        return
    kill_group(pid)
    with contextlib.suppress(Exception): os.remove(PID_FILE)
    print("stopped")

def status():
    pid = read_pid()
    if proc_alive(pid):
        print("running")
        return 0
    print("stopped")
    return 3

def main():
    must_root()
    ap = argparse.ArgumentParser(description="gnaw admin helper")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("start")
    s.add_argument("--outer-endpoint", required=True)
    s.add_argument("--outer-bind", required=True)
    s.add_argument("--inner-endpoint", required=True)
    s.add_argument("--inner-bind", required=True)
    s.add_argument("--register-inner", action="store_true")
    s.add_argument("--warp-check", action="store_true")
    s.add_argument("--udp-over-tcp", action="store_true")

    sub.add_parser("stop")
    sub.add_parser("status")

    args = ap.parse_args()
    if args.cmd == "start":
        start_mim(
            args.outer_endpoint, args.outer_bind,
            args.inner_endpoint, args.inner_bind,
            register_inner=args.register_inner,
            warp_check=args.warp_check,
            udp_over_tcp=args.udp_over_tcp,
        )
    elif args.cmd == "stop":
        stop_all()
    elif args.cmd == "status":
        rc = status()
        sys.exit(rc)

if __name__ == "__main__":
    main()
