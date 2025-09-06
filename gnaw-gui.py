#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, GLib

import os
import sys
import json
import socket
import subprocess
import threading
import time
from pathlib import Path

APP_NAME = "Gnaw"

CFG_DIR = Path(os.environ.get("XDG_CONFIG_HOME", f"{Path.home()}/.config")) / "gnaw"
CFG_DIR.mkdir(parents=True, exist_ok=True)
CFG_FILE = CFG_DIR / "gui.json"

DEFAULTS = {
    "outer_endpoint": "162.159.198.2:443",
    "outer_bind": "127.0.0.1:2080",
    "inner_endpoint": "162.159.198.1:443",
    "inner_bind": "127.0.0.1:2081",
    "register_inner": False,
    "warp_check": False,
    "udp_over_tcp": False,
}

def load_cfg():
    try:
        if CFG_FILE.is_file():
            return {**DEFAULTS, **json.loads(CFG_FILE.read_text())}
    except Exception:
        pass
    return DEFAULTS.copy()

def save_cfg(d):
    try:
        CFG_FILE.write_text(json.dumps(d, indent=2))
    except Exception:
        pass

def resolve_admin_bin():
    # System path (AUR install)
    sys_path = "/usr/lib/gnaw/gnaw_admin.py"
    if os.path.isfile(sys_path):
        return sys_path
    # Local development fallbacks (same dir as this GUI)
    here = os.path.dirname(os.path.abspath(__file__))
    for name in ("gnaw_admin.py", "gnaw-admin.py"):
        p = os.path.join(here, name)
        if os.path.isfile(p):
            return p
    return None

def pkexec_run(args):
    """
    Run pkexec with our admin helper. Returns subprocess.Popen.
    The auth prompt appears via the system policykit agent.
    """
    admin = resolve_admin_bin()
    if not admin:
        raise FileNotFoundError("Admin helper not found. Place gnaw_admin.py next to gnaw-gui.py or install to /usr/lib/gnaw/gnaw_admin.py")
    cmd = ["pkexec", sys.executable, admin] + args
    # Non-blocking. We'll wait/join in a thread.
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def quick_check_port(bind):
    try:
        host, port = bind.split(":")
        with socket.create_connection((host, int(port)), timeout=0.5):
            return True
    except Exception:
        return False

class App(Gtk.Application):
    def __init__(self):
        super().__init__(application_id="dev.gnaw.Gui")
        self.running = False
        self.cfg = load_cfg()

    def do_activate(self):
        win = Gtk.ApplicationWindow(application=self)
        win.set_title(APP_NAME)
        win.set_default_size(360, 160)

        # Header with switch and settings button
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
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        win.set_child(box)

        self.status_main = Gtk.Label(label="Off", xalign=0)
        self.status_sub = Gtk.Label(label="", xalign=0)
        box.append(self.status_main)
        box.append(self.status_sub)

        # First status poll (does not force auth until needed)
        self.poll_status(initial=True)

        win.present()

    def set_status(self, main, sub=""):
        self.status_main.set_text(main)
        self.status_sub.set_text(sub)

    def poll_status(self, initial=False):
        # Ask admin for status (triggers auth once; then cached)
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
        save_cfg(self.cfg)

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
            # Give the background a moment to bind
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
                    hint = emsg or msg or "Failed to start. Check /var/log/gnaw/gnaw.log if installed, else run from terminal for details."
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
        # Simple settings window (not a Dialog; fewer API pitfalls)
        win = Gtk.Window(title="Settings", transient_for=self.get_active_window())
        win.set_default_size(420, 280)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        win.set_child(box)

        def row(lbl, key):
            h = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            l = Gtk.Label(label=lbl, xalign=0)
            e = Gtk.Entry(text=self.cfg.get(key, ""))
            e.set_hexpand(True)
            h.append(l); h.append(e)
            box.append(h)
            return e

        e_oe = row("Outer endpoint", "outer_endpoint")
        e_ob = row("Outer bind", "outer_bind")
        e_ie = row("Inner endpoint", "inner_endpoint")
        e_ib = row("Inner bind", "inner_bind")

        # Options (tiny)
        cb_reg = Gtk.CheckButton(label="Separate inner identity")
        cb_reg.set_active(bool(self.cfg.get("register_inner")))
        cb_warp = Gtk.CheckButton(label="Show inner trace on start")
        cb_warp.set_active(bool(self.cfg.get("warp_check")))
        cb_udp = Gtk.CheckButton(label="UDP over TCP (compat)")
        cb_udp.set_active(bool(self.cfg.get("udp_over_tcp")))
        box.append(cb_reg); box.append(cb_warp); box.append(cb_udp)

        # Save/Close
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
            save_cfg(self.cfg)
        btn_save.connect("clicked", on_save)
        btn_close.connect("clicked", lambda *_: win.destroy())

        win.present()

def main():
    app = App()
    app.run(sys.argv)

if __name__ == "__main__":
    main()
