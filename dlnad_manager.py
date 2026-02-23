#!/usr/bin/env python3.11
#
import os
import shlex
import signal
import subprocess
import sys
import threading
from tkinter import Tk, filedialog

import rumps


class DLNADManager(rumps.App):
    def __init__(self):
        self.menu_icon = "📺"
        super(DLNADManager, self).__init__(self.menu_icon, icon=None)
        self.config_path = os.path.expanduser("~/.dlnad")

        # Load initial config
        config = self.load_config()
        self.dlna_dir = config.get("DLNA_DIR", os.path.expanduser("~"))
        self.custom_command = config.get("DLNAD_COMMAND")

        self.process = None
        self.log_content = []

        # Menu Setup
        self.start_button = rumps.MenuItem("Start Service", callback=self.start_service)
        self.stop_button = rumps.MenuItem("Stop Service", callback=self.stop_service)
        self.stop_button.set_callback(None)
        self.dir_display = rumps.MenuItem(
            f"Current Dir: {self.dlna_dir}", callback=None
        )

        self.menu = [
            self.dir_display,
            "Select New Directory",
            None,
            self.start_button,
            self.stop_button,
            "Show Console Log",
            None,
        ]

    def load_config(self):
        """Search for DLNA_DIR and DLNAD_COMMAND in ~/.dlnad"""
        config = {}
        if os.path.exists(self.config_path):
            with open(self.config_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        key, value = line.split("=", 1)
                        config[key.strip()] = value.strip().strip('"')
        return config

    def save_config(self, directory=None):
        """Save current configuration back to ~/.dlnad while preserving other variables."""
        config = self.load_config()

        if directory:
            config["DLNA_DIR"] = directory
            self.dlna_dir = directory

        with open(self.config_path, "w") as f:
            for key, value in config.items():
                f.write(f'{key}="{value}"\n')

        self.title = f"{self.menu_icon} (Ready)"

    @rumps.clicked("Select New Directory")
    def select_directory(self, _):
        # Native AppleScript folder picker: avoids the Tkinter/rumps crash
        cmd = 'POSIX path of (choose folder with prompt "Select DLNA Shared Directory")'

        try:
            # Execute the system dialog
            proc = subprocess.run(
                ["osascript", "-e", cmd], capture_output=True, text=True
            )

            if proc.returncode == 0:
                selected = proc.stdout.strip()
                if selected:
                    self.save_config(directory=selected)
                    # Update the menu item title dynamically
                    for item in self.menu:
                        if (
                            isinstance(self.menu[item], rumps.MenuItem)
                            and "Current Dir:" in self.menu[item].title
                        ):
                            self.menu[item].title = f"Current Dir: {selected}"

                    rumps.notification("dlnad", "Directory Updated", selected)
        except Exception as e:
            rumps.alert(f"Selection Error: {e}")

    def start_service(self, _):
        if self.process:
            return

        # 1. Resolve Binary Path for Default Command
        if getattr(sys, "frozen", False):
            bundle_res = os.path.join(
                os.path.dirname(sys.executable), "..", "Resources"
            )
            binary_path = os.path.abspath(os.path.join(bundle_res, "dlnad"))
        else:
            base_path = os.path.dirname(os.path.abspath(__file__))
            binary_path = os.path.join(base_path, "target", "release", "dlnad")

        # 2. Determine Command to Run
        config = self.load_config()
        self.custom_command = config.get("DLNAD_COMMAND")

        if self.custom_command:
            # Interpolate {} with the current DLNA_DIR
            interpolated_cmd = self.custom_command.replace("{}", self.dlna_dir)
            cmd = shlex.split(interpolated_cmd)
        else:
            # Fallback to default
            cmd = [binary_path, "-v", "-d", self.dlna_dir]

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=True,
            )

            thread = threading.Thread(target=self.read_logs, daemon=True)
            thread.start()

            self.start_button.set_callback(None)
            self.stop_button.set_callback(self.stop_service)
            self.title = f"{self.menu_icon} (Running)"
            rumps.notification(
                "dlnad", "Service Started", f"Running: {' '.join(cmd[:3])}..."
            )
        except Exception as e:
            rumps.alert(f"Failed to start service: {e}")

    def read_logs(self):
        if self.process and self.process.stdout:
            for line in iter(self.process.stdout.readline, ""):
                self.log_content.append(line)
                if len(self.log_content) > 500:
                    self.log_content.pop(0)

    def stop_service(self, _):
        if self.process:
            try:
                if self.process.poll() is None:
                    pgid = os.getpgid(self.process.pid)
                    os.killpg(pgid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except Exception as e:
                print(f"DEBUG: Error during stop: {e}")
            finally:
                self.process = None
                self.start_button.set_callback(self.start_service)
                self.stop_button.set_callback(None)
                self.title = self.menu_icon
                rumps.notification("dlnad", "Service Stopped", "")

    @rumps.clicked("Show Console Log")
    def show_log(self, _):
        log_window = rumps.Window(
            title="dlnad Console Log",
            default_text="".join(self.log_content),
            ok="Close",
            dimensions=(600, 400),
        )
        log_window.run()


if __name__ == "__main__":
    DLNADManager().run()
