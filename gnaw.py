#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
gnaw — MASQUE wrapper + MiM + admin helper + GTK GUI (single file)

Modes:
- CLI (default): same flags as original gnaw.py, including --mim-run
- admin: root helper with subcommands start|stop|status (invoked by GUI via pkexec)
- --gui or gui: GTK4 toggle app calling admin via pkexec

Fixes and improvements:
- GUI:
  - Do not pass stray "gui" arg to Gtk. Handles file-open events to avoid "This application can not open files."
  - Refuse to run GUI as root (run as user; pkexec elevates only when needed).
  - Optional "Open Log" button (uses xdg-open) and clearer status messaging.
- Security:
  - Sensitive configs written with 0600 permissions.
  - Avoid logging secrets; redact password.
- Reliability:
  - Robust process startup/shutdown; kill process group on stop.
  - Better endpoint resolution/bypass logic; race-resistant port checks.
- Convenience:
  - Rootless TUN capability check (--priv-check).
  - .desktop instructions included in comments.
- Packaging:
  - One executable (gnaw). Desktop entry can Exec=gnaw --gui; Terminal=false.

Requirements:
- Linux for MiM/TUN
- usque/tusque and sing-box installed (or supply paths via flags)
- GUI requires GTK4 Python bindings (gi) and a polkit authentication agent for pkexec
- Optional: requests[socks] for inner WARP trace
"""

from __future__ import annotations

import argparse
import contextlib
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ------------------------------------------------------------
# Shared constants and defaults
# ------------------------------------------------------------

APP_NAME = "Gnaw"
APP_ID = "dev.gnaw.Gui"

# CLI defaults
DEFAULT_BIND = "127.0.0.1:1080"
DEFAULT_CONFIG_FILE = "./config.json"
DEFAULT_OUTER_CONFIG = "./config_outer.json"
DEFAULT_INNER_CONFIG = "./config_inner.json"
DEFAULT_SBOX_CONFIG = "./singbox_mim.json"
DEFAULT_TEST_URL = "https://connectivity.cloudflareclient.com/cdn-cgi/trace"
DEFAULT_SNI = "consumer-masque.cloudflareclient.com"
DEFAULT_CONNECT_TIMEOUT = "15m"

# usque defaults
CONNECT_PORT = 443
DNS_STR = ""
DNS_TIMEOUT = "2s"
INITIAL_PACKET_SIZE = 1242
KEEPALIVE_PERIOD = "30s"
LOCAL_DNS = False
MTU = 1280
NO_TUNNEL_IPV4 = False
NO_TUNNEL_IPV6 = False
PASSWORD = ""
USERNAME = ""
RECONNECT_DELAY = "1s"
SNI = DEFAULT_SNI
USE_IPV6 = False

# Admin helper paths and files
STATE_DIR_SYS = "/run/gnaw"
LOG_DIR_SYS = "/var/log/gnaw"

# GUI config
XDG_CFG_DIR = Path(os.environ.get("XDG_CONFIG_HOME", f"{Path.home()}/.config")) / "gnaw"
GUI_CFG_FILE = XDG_CFG_DIR / "gui.json"
GUI_DEFAULTS = {
    "outer_endpoint": "162.159.198.2:443",
    "outer_bind": "127.0.0.1:2080",
    "inner_endpoint": "162.159.198.1:443",
    "inner_bind": "127.0.0.1:2081",
    "register_inner": False,
    "warp_check": False,
    "udp_over_tcp": False,
}

# ------------------------------------------------------------
# Logging
# ------------------------------------------------------------

def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())

def log_msg(level: str, msg: str, fields: Optional[Dict[str, str]] = None):
    out = {"ts": now_iso(), "level": level, "msg": msg}
    if fields:
        out.update(fields)
    try:
        print(json.dumps(out, ensure_ascii=False), flush=True)
    except Exception:
        print(f"[{out.get('level')}] {out.get('msg')}", flush=True)

def log_info(msg: str, fields: Optional[Dict[str, str]] = None):
    log_msg("INFO", msg, fields)

def log_warn(msg: str, fields: Optional[Dict[str, str]] = None):
    log_msg("WARN", msg, fields)

def log_error(msg: str, fields: Optional[Dict[str, str]] = None):
    log_msg("ERROR", msg, fields)

def log_error_and_exit(msg: str):
    log_error(msg)
    sys.exit(1)

# ------------------------------------------------------------
# Utilities
# ------------------------------------------------------------

DURATION_RE = re.compile(r"^\s*(\d+)(ms|s|m|h)?\s*$", re.I)

def parse_duration_to_seconds(s: str) -> float:
    if isinstance(s, (int, float)):
        return float(s)
    m = DURATION_RE.match(str(s))
    if not m:
        raise ValueError(f"invalid duration: {s!r}")
    val = int(m.group(1))
    unit = (m.group(2) or "s").lower()
    if unit == "ms":
        return val / 1000.0
    if unit == "s":
        return float(val)
    if unit == "m":
        return val * 60.0
    if unit == "h":
        return val * 3600.0
    raise ValueError(f"invalid duration unit: {s!r}")

def split_csv(s: str) -> List[str]:
    return [p.strip() for p in s.split(",") if p.strip()]

def validate_port(port: str):
    try:
        n = int(port)
        if not (1 <= n <= 65535):
            raise ValueError
    except Exception:
        raise ValueError(f"invalid port {port!r}")

def split_bind(b: str) -> Tuple[str, str]:
    parts = b.split(":")
    if len(parts) != 2:
        raise ValueError("--bind must be in format IP:Port")
    validate_port(parts[1])
    return parts[0], parts[1]

def must_split_bind(b: str) -> Tuple[str, str]:
    try:
        return split_bind(b)
    except Exception as e:
        log_error_and_exit(str(e))
        raise

def is_ip(s: str) -> bool:
    with contextlib.suppress(ValueError):
        ipaddress.ip_address(s)
        return True
    return False

def parse_endpoint(ep: str) -> Tuple[str, str]:
    if not ep:
        raise ValueError("empty endpoint")
    if ep.startswith("["):
        end = ep.rfind("]")
        if end == -1:
            raise ValueError("invalid IPv6 format")
        host = ep[1:end]
        port = ""
        if len(ep) > end + 1 and ep[end + 1] == ":":
            port = ep[end + 2 :]
    else:
        if ":" in ep:
            host, port = ep.rsplit(":", 1)
        else:
            host, port = ep, ""
    if port:
        validate_port(port)
    return host, port

def secure_write_json(path: str, cfg: dict):
    data = json.dumps(cfg, indent=2)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(data)
    with contextlib.suppress(Exception):
        os.chmod(path, 0o600)

def need_register(config_file: str, renew: bool) -> bool:
    if renew:
        return True
    return not os.path.exists(config_file)

def choose_dns_servers(dns_csv: str) -> List[str]:
    out = []
    for d in split_csv(dns_csv):
        if not is_ip(d):
            log_info(f"warning: invalid DNS server {d!r}; ignoring")
            continue
        out.append(d)
    return out

def log_config(endpoint: str, bind_ip: str, bind_port: str, sni: str, connect_port: int, use_ipv6: bool):
    fields = {
        "endpoint": endpoint,
        "bind": f"{bind_ip}:{bind_port}",
        "sni": sni,
        "connect-port": str(connect_port),
        "ipv6": str(use_ipv6),
        "dns": DNS_STR,
        "dns-timeout": DNS_TIMEOUT,
        "mtu": str(MTU),
        "keepalive": KEEPALIVE_PERIOD,
    }
    if USERNAME or PASSWORD:
        fields["username"] = USERNAME
        fields["password"] = "[set]" if PASSWORD else ""
    log_info("starting usque with configuration", fields)

def add_endpoint_to_config(cfg: dict, endpoint: str, use_ipv6_flag: bool) -> Tuple[str, int, bool]:
    if not endpoint:
        return "", 0, False
    host, port = parse_endpoint(endpoint)
    if not port:
        port = "443"
    if is_ip(host):
        ip = ipaddress.ip_address(host)
        if ip.version == 4:
            cfg["endpoint_v4"] = host
            cfg["endpoint_v4_port"] = port
            log_info("using IPv4 endpoint")
            return host, int(port), False
        else:
            cfg["endpoint_v6"] = host
            cfg["endpoint_v6_port"] = port
            log_info("using IPv6 endpoint")
            return host, int(port), True

    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except Exception as e:
        log_error_and_exit(f"failed to resolve {host}: {e}")
        return "", 0, False

    v4s = [addr[4][0] for addr in infos if ":" not in addr[4][0]]
    v6s = [addr[4][0] for addr in infos if ":" in addr[4][0]]

    prefer_v6 = use_ipv6_flag
    chosen_ip = v6s[0] if (prefer_v6 and v6s) else (v4s[0] if v4s else (v6s[0] if v6s else None))
    if not chosen_ip:
        log_error_and_exit(f"no IPs for {host}")
        return "", 0, False

    is_v6 = ":" in chosen_ip
    version = "v6" if is_v6 else "v4"
    cfg[f"endpoint_{version}"] = chosen_ip
    cfg[f"endpoint_{version}_port"] = port
    log_info(f"using resolved IPv{'6' if is_v6 else '4'} endpoint for {host}")
    return chosen_ip, int(port), is_v6

# ------------------------------------------------------------
# Binary discovery and privilege checks
# ------------------------------------------------------------

def find_usque(path_arg: Optional[str]) -> str:
    candidates: List[str] = []
    if path_arg:
        candidates.append(path_arg)
    for name in ("usque", "tusque"):
        p = shutil.which(name)
        if p:
            candidates.append(p)
        local = os.path.join(os.getcwd(), name)
        if os.path.isfile(local):
            candidates.append(local)
    candidates.append("./usque")
    for p in candidates:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    raise FileNotFoundError("Could not find usque/tusque binary. Pass --usque-path, or ensure it is in PATH.")

def find_singbox(path_arg: Optional[str]) -> str:
    if path_arg and os.path.isfile(path_arg) and os.access(path_arg, os.X_OK):
        return path_arg
    p = shutil.which("sing-box")
    if p:
        return p
    local = os.path.join(os.getcwd(), "sing-box")
    if os.path.isfile(local) and os.access(local, os.X_OK):
        return local
    raise FileNotFoundError("Could not find sing-box. Pass --sing-box-path or install sing-box-bin.")

def has_cap_net_admin(singbox_path: str) -> bool:
    """Best-effort: check file capabilities for CAP_NET_ADMIN or CAP_NET_RAW."""
    try:
        p = subprocess.run(["getcap", singbox_path], capture_output=True, text=True, timeout=2)
        out = p.stdout.strip()
        return "cap_net_admin" in out or "cap_net_raw" in out
    except Exception:
        return False

def can_run_mim_rootless(singbox_path: str) -> bool:
    return has_cap_net_admin(singbox_path)

# ------------------------------------------------------------
# Process state scanning (usque)
# ------------------------------------------------------------

@dataclass
class ProcState:
    connected: bool = False
    private_key_err: bool = False
    endpoint_err: bool = False
    handshake_fail: bool = False
    serve_addr_shown: bool = False
    tunnel_fail_cnt: int = 0
    mu: threading.Lock = field(default_factory=threading.Lock)

def handle_scanner(stream, bind: str, st: ProcState, proc: subprocess.Popen, log_child: bool, tunnel_fail_limit: int):
    if tunnel_fail_limit <= 0:
        tunnel_fail_limit = 1
    skip_keywords = [
        "server: not support version",
        "server: writeto tcp",
        "server: readfrom tcp",
        "server: failed to resolve destination",
        "wsarecv: an established connection was",
        "wsasend: an established connection was",
        "datagram frame too large",
    ]
    for raw in iter(stream.readline, b""):
        try:
            line = raw.decode("utf-8", errors="replace").rstrip("\n")
        except Exception:
            continue
        lower = line.lower()
        if any(kw in lower for kw in skip_keywords):
            continue
        if log_child:
            log_info(line)
        with st.mu:
            if "Connected to MASQUE server" in line:
                if not st.serve_addr_shown:
                    log_info("serving proxy", {"address": bind})
                    st.serve_addr_shown = True
                st.connected = True
            elif ("tls: handshake" in lower) or ("handshake failure" in lower) or ("crypto_error" in lower) or ("remote error" in lower):
                st.handshake_fail = True
                with contextlib.suppress(Exception):
                    proc.kill()
            elif ("invalid endpoint" in lower) or ("invalid sni" in lower) or ("dns resolution failed" in lower):
                st.endpoint_err = True
                with contextlib.suppress(Exception):
                    proc.kill()
            elif "login failed!" in lower:
                with contextlib.suppress(Exception):
                    proc.kill()
            elif "failed to connect tunnel" in lower:
                st.tunnel_fail_cnt += 1
                if st.tunnel_fail_cnt >= tunnel_fail_limit:
                    with contextlib.suppress(Exception):
                        proc.kill()
            elif "failed to get private key" in lower:
                st.private_key_err = True
                with contextlib.suppress(Exception):
                    proc.kill()

# ------------------------------------------------------------
# usque integration
# ------------------------------------------------------------

def run_register(usque_path: str) -> int:
    cmd = [usque_path, "register", "-n", "masque-plus"]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def reader(stream, is_err=False):
        for raw in iter(stream.readline, b""):
            try:
                line = raw.decode("utf-8", errors="replace").rstrip("\n")
            except Exception:
                continue
            (print if not is_err else (lambda s: print(s, file=sys.stderr)))(line)

    t1 = threading.Thread(target=reader, args=(proc.stdout, False), daemon=True)
    t2 = threading.Thread(target=reader, args=(proc.stderr, True), daemon=True)
    t1.start(); t2.start()

    def writer():
        time.sleep(0.1)
        try:
            if proc.stdin:
                proc.stdin.write(b"y\n")
                proc.stdin.flush()
                time.sleep(0.1)
                proc.stdin.write(b"y\n")
                proc.stdin.flush()
                proc.stdin.close()
        except Exception:
            pass

    threading.Thread(target=writer, daemon=True).start()
    return proc.wait()

def create_usque_cmd(usque_path: str, config: str, bind_ip: str, bind_port: str, masque_port: int, use_v6: bool) -> List[str]:
    args = [
        usque_path, "socks",
        "--config", config,
        "-b", bind_ip,
        "-p", bind_port,
        "-P", str(masque_port),
        "-s", SNI,
    ]
    if use_v6:
        args.append("-6")
    for d in choose_dns_servers(DNS_STR):
        args.extend(["-d", d])
    args.extend(["-t", DNS_TIMEOUT])
    args.extend(["-i", str(INITIAL_PACKET_SIZE)])
    args.extend(["-k", KEEPALIVE_PERIOD])
    if LOCAL_DNS:
        args.append("-l")
    args.extend(["-m", str(MTU)])
    if NO_TUNNEL_IPV4:
        args.append("-F")
    if NO_TUNNEL_IPV6:
        args.append("-S")
    if USERNAME and PASSWORD:
        args.extend(["-u", USERNAME, "-w", PASSWORD])
    elif (USERNAME and not PASSWORD) or (PASSWORD and not USERNAME):
        log_info("warning: both --username and --password must be provided for authentication; ignoring")
    args.extend(["-r", RECONNECT_DELAY])
    return args

def start_usque(usque_path: str, config: str, bind_ip: str, bind_port: str, masque_port: int, use_v6: bool, connect_timeout_s: float, log_child=True) -> subprocess.Popen:
    args = create_usque_cmd(usque_path, config, bind_ip, bind_port, masque_port, use_v6)
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    st = ProcState()
    threading.Thread(target=handle_scanner, args=(proc.stdout, f"{bind_ip}:{bind_port}", st, proc, log_child, 3), daemon=True).start()
    threading.Thread(target=handle_scanner, args=(proc.stderr, f"{bind_ip}:{bind_port}", st, proc, log_child, 3), daemon=True).start()

    start = time.time()
    while True:
        ret = proc.poll()
        if ret is not None:
            with st.mu:
                if st.private_key_err:
                    raise RuntimeError("failed to get private key")
                if st.endpoint_err:
                    raise RuntimeError("failed to set endpoint")
                if st.handshake_fail:
                    raise RuntimeError("handshake failure")
            raise RuntimeError(f"usque exited: {ret}")

        with st.mu:
            if st.connected:
                log_info("usque connected; proxy serving", {"bind": f"{bind_ip}:{bind_port}"})
                break

        if time.time() - start > connect_timeout_s:
            with contextlib.suppress(Exception):
                proc.kill()
            raise TimeoutError(f"connect timeout after {connect_timeout_s}s")
        time.sleep(0.2)

    return proc

# ------------------------------------------------------------
# HTTP trace over SOCKS
# ------------------------------------------------------------

def fetch_cf_trace_over_socks(bind: str, timeout_s: float) -> Tuple[Dict[str, str], Optional[str]]:
    try:
        import requests  # type: ignore
    except Exception as e:
        return {}, f"requests not available: {e}"
    url = DEFAULT_TEST_URL
    proxies = {"http": f"socks5h://{bind}", "https": f"socks5h://{bind}"}
    try:
        r = requests.get(url, timeout=timeout_s, proxies=proxies, verify=False)
        if r.status_code != 200:
            return {}, f"status {r.status_code}"
        lines = (r.text or "").splitlines()
        kv = {}
        for ln in lines:
            if "=" in ln:
                k, v = ln.split("=", 1)
                kv[k.strip()] = v.strip()
        return kv, None
    except Exception as e:
        return {}, str(e)

# ------------------------------------------------------------
# sing-box MiM
# ------------------------------------------------------------

def require_root_for_tun(singbox_path: Optional[str] = None):
    if os.geteuid() == 0:
        return
    if singbox_path and can_run_mim_rootless(singbox_path):
        return
    log_error_and_exit("Masque-in-Masque requires root (or sing-box with CAP_NET_ADMIN/CAP_NET_RAW). Use pkexec/sudo, or setcap on sing-box.")

def build_singbox_mim_config(
    outer_socks_ip: str,
    outer_socks_port: int,
    bypass_dest_ips: List[str],
    tun4: str,
    tun6: Optional[str],
    tun_mtu: int,
    udp_over_tcp: bool,
) -> dict:
    addresses = [tun4]
    if tun6:
        addresses.append(tun6)
    rules = [
        {"ip_cidr": ["127.0.0.0/8", "::1/128"], "outbound": "direct"},
        {"ip_cidr": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "fe80::/10"], "outbound": "direct"},
    ]
    if bypass_dest_ips:
        rules.append({"ip_cidr": [f"{ip}/32" if ":" not in ip else f"{ip}/128" for ip in bypass_dest_ips], "outbound": "direct"})
    cfg = {
        "log": {"level": "info"},
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "mtu": tun_mtu,
                "address": addresses,
                "auto_route": True,
                "strict_route": True,
                "stack": "system"
            }
        ],
        "outbounds": [
            {
                "type": "socks",
                "tag": "out-socks",
                "server": outer_socks_ip,
                "server_port": outer_socks_port,
                "version": "5",
                "udp_over_tcp": udp_over_tcp
            },
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"}
        ],
        "route": {
            "auto_detect_interface": True,
            "rules": rules,
            "final": "out-socks"
        }
    }
    return cfg

def run_singbox(singbox_path: str, config_path: str) -> subprocess.Popen:
    args = [singbox_path, "run", "-c", config_path]
    env = os.environ.copy()
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    def log_stream(stream, is_err=False):
        for raw in iter(stream.readline, b""):
            try:
                line = raw.decode("utf-8", errors="replace").rstrip("\n")
            except Exception:
                continue
            (log_info if not is_err else log_warn)(f"[sing-box] {line}")
    threading.Thread(target=log_stream, args=(proc.stdout, False), daemon=True).start()
    threading.Thread(target=log_stream, args=(proc.stderr, True), daemon=True).start()
    time.sleep(0.8)
    rc = proc.poll()
    if rc is not None:
        raise RuntimeError(f"sing-box exited immediately (rc={rc}). See logs above.")
    return proc

# ------------------------------------------------------------
# Identity juggling for inner
# ------------------------------------------------------------

def backup(path: str) -> Optional[str]:
    if not os.path.exists(path):
        return None
    b = path + ".bak_" + str(int(time.time()))
    shutil.move(path, b)
    return b

def restore(backup_path: Optional[str], dst: str):
    if not backup_path:
        return
    with contextlib.suppress(Exception):
        if os.path.exists(dst):
            os.remove(dst)
        shutil.move(backup_path, dst)

def register_new_identity_to(usque_path: str, target_path: str) -> None:
    bk = backup(DEFAULT_CONFIG_FILE)
    try:
        rc = run_register(usque_path)
        if rc != 0:
            raise RuntimeError(f"register failed rc={rc}")
        if not os.path.exists(DEFAULT_CONFIG_FILE):
            raise RuntimeError("register completed but config.json not found")
        if os.path.exists(target_path):
            os.remove(target_path)
        shutil.move(DEFAULT_CONFIG_FILE, target_path)
        with contextlib.suppress(Exception):
            os.chmod(target_path, 0o600)
    finally:
        restore(bk, DEFAULT_CONFIG_FILE)

# ------------------------------------------------------------
# CLI main (original gnaw.py behavior)
# ------------------------------------------------------------

def cli_main(argv: Optional[List[str]] = None):
    global CONNECT_PORT, DNS_STR, DNS_TIMEOUT, INITIAL_PACKET_SIZE, KEEPALIVE_PERIOD
    global LOCAL_DNS, MTU, NO_TUNNEL_IPV4, NO_TUNNEL_IPV6, PASSWORD, USERNAME
    global RECONNECT_DELAY, SNI, USE_IPV6

    p = argparse.ArgumentParser(description="MASQUE wrapper with Masque-in-Masque")
    p.add_argument("--endpoint", default="", help="Outer MASQUE endpoint (host[:port] or [v6]:port)")
    p.add_argument("--bind", default=DEFAULT_BIND, help="Outer SOCKS bind IP:Port")
    p.add_argument("--connect-timeout", default=DEFAULT_CONNECT_TIMEOUT, help="Connect timeout, e.g. 30s, 5m")
    p.add_argument("--test-url", default=DEFAULT_TEST_URL, help="WARP test URL")
    p.add_argument("--renew", action="store_true", help="Force register even if config exists")
    p.add_argument("--usque-path", default=None, help="Path to usque/tusque binary")
    p.add_argument("--sing-box-path", default=None, help="Path to sing-box binary")
    p.add_argument("--ipv6", dest="use_ipv6", action="store_true", help="Use IPv6 for MASQUE connection")
    p.add_argument("--sni", default=DEFAULT_SNI, help="SNI for MASQUE")
    # usque extra
    p.add_argument("--connect-port", type=int, default=CONNECT_PORT)
    p.add_argument("--dns", default=DNS_STR)
    p.add_argument("--dns-timeout", default=DNS_TIMEOUT)
    p.add_argument("--initial-packet-size", type=int, default=INITIAL_PACKET_SIZE)
    p.add_argument("--keepalive-period", default=KEEPALIVE_PERIOD)
    p.add_argument("--local-dns", action="store_true")
    p.add_argument("--mtu", type=int, default=MTU)
    p.add_argument("--no-tunnel-ipv4", action="store_true")
    p.add_argument("--no-tunnel-ipv6", action="store_true")
    p.add_argument("--password", default=PASSWORD)
    p.add_argument("--username", default=USERNAME)
    p.add_argument("--reconnect-delay", default=RECONNECT_DELAY)

    # MiM flags
    p.add_argument("--mim-run", action="store_true", help="Run Masque-in-Masque: outer + sing-box TUN + inner")
    p.add_argument("--mim-inner-endpoint", default="", help="Inner MASQUE endpoint")
    p.add_argument("--mim-inner-bind", default="127.0.0.1:1081", help="Inner SOCKS bind IP:Port")
    p.add_argument("--mim-outer-config", default=DEFAULT_OUTER_CONFIG)
    p.add_argument("--mim-inner-config", default=DEFAULT_INNER_CONFIG)
    p.add_argument("--mim-sbox-config", default=DEFAULT_SBOX_CONFIG)
    p.add_argument("--mim-tun4", default="172.19.0.1/30", help="TUN IPv4 address/prefix")
    p.add_argument("--mim-tun6", default="", help="TUN IPv6 address/prefix, optional")
    p.add_argument("--mim-tun-mtu", type=int, default=1500)
    p.add_argument("--mim-warp-check", action="store_true", help="Show inner CF trace (warp/ip/loc/colo) via inner SOCKS")
    p.add_argument("--mim-keep-config", action="store_true", help="Do not delete MiM configs on exit")
    p.add_argument("--mim-udp-over-tcp", action="store_true", help="Use SOCKS UDP-over-TCP for sing-box outbound (compat mode)")
    p.add_argument("--mim-register-inner", action="store_true", help="Register a separate inner CF identity (after TUN is up)")

    # Tools
    p.add_argument("--priv-check", action="store_true", help="Check if MiM can run without root (sing-box capabilities)")

    args = p.parse_args(argv)

    # Map args to globals
    CONNECT_PORT = args.connect_port
    DNS_STR = args.dns or ""
    DNS_TIMEOUT = args.dns_timeout
    INITIAL_PACKET_SIZE = args.initial_packet_size
    KEEPALIVE_PERIOD = args.keepalive_period
    LOCAL_DNS = args.local_dns
    MTU = args.mtu
    NO_TUNNEL_IPV4 = args.no_tunnel_ipv4
    NO_TUNNEL_IPV6 = args.no_tunnel_ipv6
    PASSWORD = args.password or ""
    USERNAME = args.username or ""
    RECONNECT_DELAY = args.reconnect_delay
    SNI = args.sni or DEFAULT_SNI
    USE_IPV6 = args.use_ipv6

    # Priv check if requested
    if args.priv_check:
        try:
            sb = find_singbox(args.sing_box_path)
            ok = can_run_mim_rootless(sb)
            msg = "yes (capabilities present)" if ok else "no (needs root or setcap on sing-box)"
            print(f"Rootless MiM possible: {msg}")
        except Exception as e:
            print(f"Rootless MiM check failed: {e}")
        return

    usque_path = find_usque(args.usque_path)
    log_info("using usque binary", {"path": usque_path})
    log_info("running in masque mode")

    if not args.mim_run:
        if not args.endpoint:
            log_error_and_exit("--endpoint is required (or use --mim-run)")
        bind_ip, bind_port = must_split_bind(args.bind)
        if need_register(DEFAULT_CONFIG_FILE, args.renew):
            rc = run_register(usque_path)
            if rc != 0:
                log_error_and_exit(f"failed to register: exit={rc}")
        log_info("successfully loaded masque identity")
        cfg = {}
        if os.path.exists(DEFAULT_CONFIG_FILE):
            with contextlib.suppress(Exception):
                cfg = json.load(open(DEFAULT_CONFIG_FILE, "r", encoding="utf-8")) or {}
        add_endpoint_to_config(cfg, args.endpoint, USE_IPV6)
        secure_write_json(DEFAULT_CONFIG_FILE, cfg)
        log_config(args.endpoint, bind_ip, bind_port, SNI, CONNECT_PORT, USE_IPV6)
        try:
            proc = start_usque(usque_path, DEFAULT_CONFIG_FILE, bind_ip, bind_port, CONNECT_PORT, USE_IPV6, parse_duration_to_seconds(args.connect_timeout))
        except Exception as e:
            log_error_and_exit(f"SOCKS start failed: {e}")
        def stop(_sig, _frm):
            with contextlib.suppress(Exception): proc.terminate()
        signal.signal(signal.SIGINT, stop)
        signal.signal(signal.SIGTERM, stop)
        proc.wait()
        return

    # ---------- Masque-in-Masque ----------
    singbox_path = find_singbox(args.sing_box_path)
    require_root_for_tun(singbox_path)
    log_info("using sing-box binary", {"path": singbox_path})

    if not args.endpoint:
        log_error_and_exit("--endpoint (outer) is required with --mim-run")
    if not args.mim_inner_endpoint:
        log_error_and_exit("--mim-inner-endpoint is required with --mim-run")

    outer_bind_ip, outer_bind_port = must_split_bind(args.bind)
    inner_bind_ip, inner_bind_port = must_split_bind(args.mim_inner_bind)

    # 1) Ensure outer identity exists
    if need_register(DEFAULT_CONFIG_FILE, args.renew):
        rc = run_register(usque_path)
        if rc != 0:
            log_error_and_exit(f"failed to register: exit={rc}")
    log_info("successfully loaded masque identity")

    # 2) Prepare outer config
    try:
        base_cfg = {}
        if os.path.exists(DEFAULT_CONFIG_FILE):
            with contextlib.suppress(Exception):
                base_cfg = json.load(open(DEFAULT_CONFIG_FILE, "r", encoding="utf-8")) or {}
        cfg_outer = dict(base_cfg)
        add_endpoint_to_config(cfg_outer, args.endpoint, USE_IPV6)
        secure_write_json(args.mim_outer_config, cfg_outer)
        log_info("wrote outer config", {"path": args.mim_outer_config})
    except Exception as e:
        log_error_and_exit(f"failed to write outer config: {e}")

    # 3) Start outer usque
    log_config(args.endpoint, outer_bind_ip, outer_bind_port, SNI, CONNECT_PORT, USE_IPV6)
    try:
        proc_outer = start_usque(usque_path, args.mim_outer_config, outer_bind_ip, outer_bind_port, CONNECT_PORT, USE_IPV6, parse_duration_to_seconds(args.connect_timeout))
    except Exception as e:
        log_error_and_exit(f"outer usque failed: {e}")

    # 4) Bring up sing-box TUN routing via outer SOCKS
    outer_host, _ = parse_endpoint(args.endpoint)
    bypass_ips = []
    if is_ip(outer_host):
        bypass_ips = [outer_host]
    else:
        try:
            infos = socket.getaddrinfo(outer_host, None)
            for a in infos:
                ip_ = a[4][0]
                if ip_ not in bypass_ips:
                    bypass_ips.append(ip_)
        except Exception:
            pass

    sbox_cfg = build_singbox_mim_config(
        outer_socks_ip=outer_bind_ip,
        outer_socks_port=int(outer_bind_port),
        bypass_dest_ips=bypass_ips,
        tun4=args.mim_tun4,
        tun6=args.mim_tun6 or None,
        tun_mtu=args.mim_tun_mtu,
        udp_over_tcp=args.mim_udp_over_tcp,
    )
    try:
        secure_write_json(args.mim_sbox_config, sbox_cfg)
    except Exception as e:
        log_error_and_exit(f"failed to write sing-box config: {e}")
    log_info("wrote sing-box config", {"path": args.mim_sbox_config})

    try:
        proc_sbox = run_singbox(singbox_path, args.mim_sbox_config)
    except Exception as e:
        with contextlib.suppress(Exception):
            proc_outer.terminate()
        log_error_and_exit(f"failed to start sing-box: {e}")

    # 5) Optionally register a separate inner identity NOW (after TUN is up)
    if args.mim_register_inner:
        try:
            register_new_identity_to(usque_path, args.mim_inner_config)
            log_info("registered new inner identity", {"path": args.mim_inner_config})
        except Exception as e:
            with contextlib.suppress(Exception):
                proc_sbox.terminate()
                proc_outer.terminate()
            log_error_and_exit(f"failed to register inner identity: {e}")

    # If no separate identity requested, base inner on current identity snapshot
    if not args.mim_register_inner:
        try:
            base_cfg2 = {}
            if os.path.exists(DEFAULT_CONFIG_FILE):
                with contextlib.suppress(Exception):
                    base_cfg2 = json.load(open(DEFAULT_CONFIG_FILE, "r", encoding="utf-8")) or {}
            secure_write_json(args.mim_inner_config, dict(base_cfg2))
        except Exception as e:
            with contextlib.suppress(Exception):
                proc_sbox.terminate()
                proc_outer.terminate()
            log_error_and_exit(f"failed to prep inner config: {e}")

    # 6) Add inner endpoint to inner config and start inner usque
    try:
        cfg_inner = json.load(open(args.mim_inner_config, "r", encoding="utf-8")) if os.path.exists(args.mim_inner_config) else {}
        add_endpoint_to_config(cfg_inner, args.mim_inner_endpoint, USE_IPV6)
        secure_write_json(args.mim_inner_config, cfg_inner)
        log_info("wrote inner config", {"path": args.mim_inner_config})
    except Exception as e:
        with contextlib.suppress(Exception):
            proc_sbox.terminate()
            proc_outer.terminate()
        log_error_and_exit(f"failed to write inner config: {e}")

    log_config(args.mim_inner_endpoint, inner_bind_ip, inner_bind_port, SNI, CONNECT_PORT, USE_IPV6)
    try:
        proc_inner = start_usque(usque_path, args.mim_inner_config, inner_bind_ip, inner_bind_port, CONNECT_PORT, USE_IPV6, parse_duration_to_seconds(args.connect_timeout))
    except Exception as e:
        with contextlib.suppress(Exception):
            proc_sbox.terminate()
            proc_outer.terminate()
        log_error_and_exit(f"inner usque failed: {e}")

    # 7) Optional inner WARP/trace
    if args.mim_warp_check:
        kv, err = fetch_cf_trace_over_socks(f"{inner_bind_ip}:{inner_bind_port}", 6.0)
        if err:
            log_warn("inner trace error", {"error": err})
        else:
            log_info("inner trace", {k: kv.get(k, "") for k in ("warp", "ip", "loc", "colo")})

    # 8) Foreground and cleanup
    procs = [("inner", proc_inner), ("sing-box", proc_sbox), ("outer", proc_outer)]
    def shutdown(_sig=None, _frm=None):
        log_info("shutting down MiM")
        for name, pr in procs:
            with contextlib.suppress(Exception):
                pr.terminate()
        time.sleep(0.5)
        for name, pr in procs:
            with contextlib.suppress(Exception):
                pr.kill()
        if not args.mim_keep_config:
            with contextlib.suppress(Exception): os.remove(args.mim_outer_config)
            with contextlib.suppress(Exception): os.remove(args.mim_inner_config)
            with contextlib.suppress(Exception): os.remove(args.mim_sbox_config)
        sys.exit(0)
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        while True:
            for name, pr in procs:
                rc = pr.poll()
                if rc is not None:
                    log_warn(f"{name} exited", {"code": str(rc)})
                    shutdown()
            time.sleep(0.5)
    except KeyboardInterrupt:
        shutdown()

# ------------------------------------------------------------
# Admin helper (root) — start|stop|status
# ------------------------------------------------------------

def _ensure_dir(path):
    try:
        os.makedirs(path, exist_ok=True)
        return True
    except Exception:
        return False

def _choose_state_dir():
    if _ensure_dir(STATE_DIR_SYS):
        return STATE_DIR_SYS
    tmp = "/tmp/gnaw"
    _ensure_dir(tmp)
    return tmp

def _choose_log_path():
    if _ensure_dir(LOG_DIR_SYS):
        return os.path.join(LOG_DIR_SYS, "gnaw.log")
    return "/tmp/gnaw.log"

STATE_DIR = _choose_state_dir()
PID_FILE = os.path.join(STATE_DIR, "gnaw.pid")
STATE_FILE = os.path.join(STATE_DIR, "state.json")
LOG_PATH = _choose_log_path()

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

def self_path() -> str:
    return os.path.abspath(__file__)

def admin_start(outer_ep, outer_bind, inner_ep, inner_bind, register_inner=False, warp_check=False, udp_over_tcp=False):
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
        sys.executable, self_path(),
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

def admin_stop():
    pid = read_pid()
    if not proc_alive(pid):
        print("not running")
        with contextlib.suppress(Exception): os.remove(PID_FILE)
        return
    kill_group(pid)
    with contextlib.suppress(Exception): os.remove(PID_FILE)
    print("stopped")

def admin_status():
    pid = read_pid()
    if proc_alive(pid):
        print("running")
        return 0
    print("stopped")
    return 3

def admin_main(argv: Optional[List[str]] = None):
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

    args = ap.parse_args(argv)
    if args.cmd == "start":
        admin_start(
            args.outer_endpoint, args.outer_bind,
            args.inner_endpoint, args.inner_bind,
            register_inner=args.register_inner,
            warp_check=args.warp_check,
            udp_over_tcp=args.udp_over_tcp,
        )
    elif args.cmd == "stop":
        admin_stop()
    elif args.cmd == "status":
        rc = admin_status()
        sys.exit(rc)

# ------------------------------------------------------------
# GUI (GTK4) — runs as user, calls admin via pkexec
# ------------------------------------------------------------

def gui_main(argv: Optional[List[str]] = None):
    # Lazy import GTK dependencies
    import gi
    gi.require_version("Gtk", "4.0")
    from gi.repository import Gtk, GLib, Gio

    if os.geteuid() == 0:
        print("Please run the GUI as a regular user. It will elevate via pkexec only when needed.")
        sys.exit(1)

    XDG_CFG_DIR.mkdir(parents=True, exist_ok=True)

    def load_gui_cfg():
        try:
            if GUI_CFG_FILE.is_file():
                return {**GUI_DEFAULTS, **json.loads(GUI_CFG_FILE.read_text())}
        except Exception:
            pass
        return GUI_DEFAULTS.copy()

    def save_gui_cfg(d):
        try:
            GUI_CFG_FILE.write_text(json.dumps(d, indent=2))
        except Exception:
            pass

    def pkexec_run(args):
        """
        Run pkexec with our own script as admin helper. Non-blocking.
        """
        cmd = ["pkexec", sys.executable, self_path(), "admin"] + args
        try:
            return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except FileNotFoundError:
            # pkexec missing or not in PATH
            raise RuntimeError("pkexec not found. Install polkit and ensure a polkit agent is running.")

    def quick_check_port(bind):
        try:
            host, port = bind.split(":")
            with socket.create_connection((host, int(port)), timeout=0.5):
                return True
        except Exception:
            return False

    def open_logs():
        # Try to open the log path reported by admin in state.json; else fallback /var/log or /tmp
        state_file = Path(STATE_FILE)
        logp = Path(LOG_PATH)
        try:
            if state_file.exists():
                data = json.loads(state_file.read_text())
                if "log" in data:
                    logp = Path(data["log"])
        except Exception:
            pass
        # Use xdg-open, gio open, or print path
        for opener in (["xdg-open", str(logp)], ["gio", "open", str(logp)]):
            try:
                if shutil.which(opener[0]):
                    subprocess.Popen(opener)
                    return
            except Exception:
                pass
        # No opener found; print to stderr
        print(f"Log file: {logp}", file=sys.stderr)

    class App(Gtk.Application):
        def __init__(self):
            super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.HANDLES_OPEN)
            self.running = False
            self.cfg = load_gui_cfg()

        # Accept and ignore file-open events to avoid "can not open files" warnings
        def do_open(self, files, n_files, hint):
            self.activate()

        def do_activate(self):
            win = Gtk.ApplicationWindow(application=self)
            win.set_title(APP_NAME)
            win.set_default_size(420, 200)

            hb = Gtk.HeaderBar()
            win.set_titlebar(hb)

            self.switch = Gtk.Switch()
            self.switch.set_valign(Gtk.Align.CENTER)
            self.switch.connect("notify::active", self.on_toggle)
            hb.pack_end(self.switch)

            gear = Gtk.Button.new_from_icon_name("emblem-system-symbolic")
            gear.set_tooltip_text("Settings")
            gear.connect("clicked", self.on_settings)
            hb.pack_start(gear)

            # Body
            outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10,
                            margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
            win.set_child(outer)

            self.status_main = Gtk.Label(label="Off", xalign=0)
            self.status_sub = Gtk.Label(label="", xalign=0)
            outer.append(self.status_main)
            outer.append(self.status_sub)

            # Buttons row
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            btn_logs = Gtk.Button(label="Open Log")
            btn_logs.set_tooltip_text("Open daemon log")
            btn_logs.connect("clicked", lambda *_: open_logs())
            row.append(btn_logs)
            outer.append(row)

            # First status poll (no auth unless needed)
            self.poll_status(initial=True)
            win.present()

        def set_status(self, main, sub=""):
            self.status_main.set_text(main)
            self.status_sub.set_text(sub)

        def poll_status(self, initial=False):
            def worker():
                try:
                    p = pkexec_run(["status"])
                    out, err = p.communicate(timeout=8)
                    state = (out or b"").decode().strip()
                except Exception as e:
                    state = f"error: {e}"

                def done():
                    running = (state == "running")
                    self.running = running
                    if initial:
                        self.switch.set_active(running)
                    self.set_status("On" if running else "Off")
                    if state.startswith("error"):
                        self.set_status("Off", state)
                    return False
                GLib.idle_add(done)
            threading.Thread(target=worker, daemon=True).start()

        def on_toggle(self, *_):
            want = self.switch.get_active()
            if want and not self.running:
                self.start_stack()
            elif not want and self.running:
                self.stop_stack()

        def start_stack(self):
            self.set_status("Starting…")
            save_gui_cfg(self.cfg)

            args = [
                "start",
                "--outer-endpoint", self.cfg["outer_endpoint"],
                "--outer-bind", self.cfg["outer_bind"],
                "--inner-endpoint", self.cfg["inner_endpoint"],
                "--inner-bind", self.cfg["inner_bind"],
            ]
            if self.cfg.get("register_inner"): args.append("--register-inner")
            if self.cfg.get("warp_check"): args.append("--warp-check")
            if self.cfg.get("udp_over_tcp"): args.append("--udp-over-tcp")

            try:
                p = pkexec_run(args)
            except Exception as e:
                self.set_status("Off", f"pkexec error: {e}")
                self.switch.set_active(False)
                return

            def wait_and_verify():
                out, err = p.communicate()
                rc = p.returncode
                time.sleep(1.0)
                ok = quick_check_port(self.cfg["inner_bind"])
                msg = (out or b"").decode().strip()
                emsg = (err or b"").decode().strip()
                def done():
                    if (rc == 0) or ok:
                        self.running = True
                        self.set_status("On", f"Inner SOCKS {self.cfg['inner_bind']}")
                        self.switch.set_active(True)
                    else:
                        self.running = False
                        hint = emsg or msg or "Failed to start. Check log."
                        self.set_status("Off", hint[:200])
                        self.switch.set_active(False)
                    return False
                GLib.idle_add(done)
            threading.Thread(target=wait_and_verify, daemon=True).start()

        def stop_stack(self):
            self.set_status("Stopping…")
            try:
                p = pkexec_run(["stop"])
            except Exception as e:
                self.set_status("Off", f"pkexec error: {e}")
                self.switch.set_active(False)
                return

            def wait_and_reset():
                p.wait()
                time.sleep(0.3)
                def done():
                    self.running = False
                    self.set_status("Off")
                    self.switch.set_active(False)
                    return False
                GLib.idle_add(done)
            threading.Thread(target=wait_and_reset, daemon=True).start()

        def on_settings(self, *_):
            win = Gtk.Window(title="Settings", transient_for=self.get_active_window())
            win.set_default_size(500, 340)
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8,
                          margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
            win.set_child(box)

            def row(lbl, key):
                h = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                l = Gtk.Label(label=lbl, xalign=0)
                l.set_size_request(160, -1)
                e = Gtk.Entry(text=self.cfg.get(key, ""))
                e.set_hexpand(True)
                h.append(l); h.append(e)
                box.append(h)
                return e

            e_oe = row("Outer endpoint", "outer_endpoint")
            e_ob = row("Outer bind", "outer_bind")
            e_ie = row("Inner endpoint", "inner_endpoint")
            e_ib = row("Inner bind", "inner_bind")

            cb_reg = Gtk.CheckButton(label="Separate inner identity")
            cb_reg.set_active(bool(self.cfg.get("register_inner")))
            cb_warp = Gtk.CheckButton(label="Show inner trace on start")
            cb_warp.set_active(bool(self.cfg.get("warp_check")))
            cb_udp = Gtk.CheckButton(label="UDP over TCP (compat)")
            cb_udp.set_active(bool(self.cfg.get("udp_over_tcp")))
            box.append(cb_reg); box.append(cb_warp); box.append(cb_udp)

            btnrow = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            btn_save = Gtk.Button(label="Save")
            btn_close = Gtk.Button(label="Close")
            btnrow.append(btn_save); btnrow.append(btn_close)
            box.append(btnrow)

            def on_save(_btn):
                self.cfg["outer_endpoint"] = e_oe.get_text().strip()
                self.cfg["outer_bind"] = e_ob.get_text().strip()
                self.cfg["inner_endpoint"] = e_ie.get_text().strip()
                self.cfg["inner_bind"] = e_ib.get_text().strip()
                self.cfg["register_inner"] = cb_reg.get_active()
                self.cfg["warp_check"] = cb_warp.get_active()
                self.cfg["udp_over_tcp"] = cb_udp.get_active()
                save_gui_cfg(self.cfg)
            btn_save.connect("clicked", on_save)
            btn_close.connect("clicked", lambda *_: win.destroy())

            win.present()

    app = App()
    # Important: do NOT pass sys.argv; avoid stray "gui" being treated as file
    app.run(argv or [])

# ------------------------------------------------------------
# Main dispatcher
# ------------------------------------------------------------

def main():
    # Dispatch: "gui" or "--gui" launches GUI; "admin" runs admin helper;
    # otherwise fall through to CLI.
    if len(sys.argv) >= 2 and sys.argv[1] in ("gui", "--gui"):
        gui_main(sys.argv[2:])
        return
    if len(sys.argv) >= 2 and sys.argv[1] == "admin":
        admin_main(sys.argv[2:])
        return
    cli_main(sys.argv[1:])

if __name__ == "__main__":
    main()
