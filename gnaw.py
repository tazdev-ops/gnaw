#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
gnaw.py — MASQUE wrapper with Masque-in-Masque (MiM) using sing-box TUN.

Highlights:
- Outer MASQUE (SOCKS) + sing-box TUN + Inner MASQUE routed via outer SOCKS.
- --mim-register-inner: registers a separate CF identity for the inner hop (after TUN is up).
- --mim-warp-check: prints inner warp/ip/loc/colo from CF trace via inner SOCKS.
- --mim-udp-over-tcp: compatibility mode if upstream SOCKS lacks UDP.

Requirements:
- Linux + root (or CAP_NET_ADMIN) for TUN.
- usque (or tusque) and sing-box-bin installed (PATH or flags).
- Optional: requests[socks] for WARP check (pip install "requests[socks]").
"""

from __future__ import annotations

import argparse
import contextlib
import ipaddress
import json
import os
import random
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# --------------------- Defaults ---------------------

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

# --------------------- Logging ---------------------

def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())

def log_msg(level: str, msg: str, fields: Optional[Dict[str, str]] = None):
    out = {"ts": now_iso(), "level": level, "msg": msg}
    if fields:
        out.update(fields)
    print(json.dumps(out, ensure_ascii=False))

def log_info(msg: str, fields: Optional[Dict[str, str]] = None):
    log_msg("INFO", msg, fields)

def log_warn(msg: str, fields: Optional[Dict[str, str]] = None):
    log_msg("WARN", msg, fields)

def log_error(msg: str, fields: Optional[Dict[str, str]] = None):
    log_msg("ERROR", msg, fields)

def log_error_and_exit(msg: str):
    log_error(msg)
    sys.exit(1)

# --------------------- Utils ---------------------

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

def write_config(path: str, cfg: dict):
    data = json.dumps(cfg, indent=2)
    with open(path, "w", encoding="utf-8") as f:
        f.write(data)

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
        fields["password"] = "[set]"
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

# --------------------- Binary discovery ---------------------

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

# --------------------- Process state ---------------------

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

# --------------------- usque integration ---------------------

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

# --------------------- HTTP trace over SOCKS ---------------------

def fetch_cf_trace_over_socks(bind: str, timeout_s: float) -> Tuple[Dict[str, str], Optional[str]]:
    """
    GET /cdn-cgi/trace via SOCKS and parse key=value lines (warp, ip, loc, colo, etc.).
    """
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

# --------------------- sing-box MiM ---------------------

def require_root_for_tun():
    if os.geteuid() != 0:
        log_error_and_exit("Masque-in-Masque requires root (or CAP_NET_ADMIN) to create TUN. Run with sudo or grant sing-box capabilities.")

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

# --------------------- Identity juggling for inner ---------------------

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
    """
    Temporarily moves DEFAULT_CONFIG_FILE aside, registers a new identity,
    then saves the resulting config.json to target_path and restores the original.
    """
    bk = backup(DEFAULT_CONFIG_FILE)
    try:
        rc = run_register(usque_path)
        if rc != 0:
            raise RuntimeError(f"register failed rc={rc}")
        if not os.path.exists(DEFAULT_CONFIG_FILE):
            raise RuntimeError("register completed but config.json not found")
        # Move new identity to target
        if os.path.exists(target_path):
            os.remove(target_path)
        shutil.move(DEFAULT_CONFIG_FILE, target_path)
    finally:
        # Restore original identity for outer (even if register failed)
        restore(bk, DEFAULT_CONFIG_FILE)

# --------------------- Main ---------------------

def main():
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

    args = p.parse_args()

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
        write_config(DEFAULT_CONFIG_FILE, cfg)
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
    require_root_for_tun()
    singbox_path = find_singbox(args.sing_box_path)
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
        write_config(args.mim_outer_config, cfg_outer)
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
        write_config(args.mim_sbox_config, sbox_cfg)
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
            write_config(args.mim_inner_config, dict(base_cfg2))
        except Exception as e:
            with contextlib.suppress(Exception):
                proc_sbox.terminate()
                proc_outer.terminate()
            log_error_and_exit(f"failed to prep inner config: {e}")

    # 6) Add inner endpoint to inner config and start inner usque
    try:
        cfg_inner = json.load(open(args.mim_inner_config, "r", encoding="utf-8")) if os.path.exists(args.mim_inner_config) else {}
        add_endpoint_to_config(cfg_inner, args.mim_inner_endpoint, USE_IPV6)
        write_config(args.mim_inner_config, cfg_inner)
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
            # Common keys: warp, ip, loc, colo
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


if __name__ == "__main__":
    main()
