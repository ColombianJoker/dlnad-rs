#!/usr/bin/env python3.11
#
import os
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
        self.dlna_dir = self.load_config()
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
        """Search for DLNA_DIR in ~/.dlnad"""
        if os.path.exists(self.config_path):
            with open(self.config_path, "r") as f:
                for line in f:
                    if line.startswith("DLNA_DIR="):
                        return line.split("=")[1].strip().strip('"')
        return os.path.expanduser("~")  # Default to HOME

    def save_config(self, path):
        with open(self.config_path, "w") as f:
            f.write(f'DLNA_DIR="{path}"\n')
        self.dlna_dir = path
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
                    self.save_config(selected)
                    # Update the menu item title dynamically
                    # We iterate to find the item since the title changed
                    for item in self.menu:
                        if "Current Dir:" in item:
                            self.menu[item].title = f"Current Dir: {selected}"

                    rumps.notification("dlnad", "Directory Updated", selected)
        except Exception as e:
            rumps.alert(f"Selection Error: {e}")

    def start_service(self, _):
        # Check if running as a bundled app or a script
        if getattr(sys, "frozen", False):
            # Path inside the .app bundle
            base_path = os.path.dirname(sys.executable)
            # In a .app, DATA_FILES usually end up in the Resources folder
            binary_path = os.path.join(os.path.dirname(base_path), "Resources", "dlnad")
        else:
            # Path during development
            base_path = os.path.dirname(os.path.abspath(__file__))
            binary_path = os.path.join(base_path, "target", "release", "dlnad")

        cmd = [binary_path, "-v", "-d", self.dlna_dir]

        if self.process:
            return

        # 2. Logic using 'self' must be inside the class methods
        base_path = os.path.dirname(os.path.abspath(__file__))
        binary_path = os.path.join(base_path, "target", "release", "dlnad")
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
            self.title = f"{self.menu_icon} (Running)"  # Update title to show status
            rumps.notification("dlnad", "Service Started", f"Watching {self.dlna_dir}")
        except Exception as e:
            rumps.alert(f"Failed to start dlnad: {e}")

    def read_logs(self):
        for line in iter(self.process.stdout.readline, ""):
            self.log_content.append(line)
            if len(self.log_content) > 500:  # Keep last 500 lines
                self.log_content.pop(0)

    def stop_service(self, _):
        if self.process:
            try:
                # 1. Check if the process is actually still alive
                if self.process.poll() is None:
                    # 2. Use a safer approach to killing the process group
                    pgid = os.getpgid(self.process.pid)
                    os.killpg(pgid, signal.SIGTERM)
                else:
                    print("DEBUG: Process already exited on its own.")
            except ProcessLookupError:
                # Handle the specific error you saw
                print("DEBUG: Process group already gone.")
            except Exception as e:
                print(f"DEBUG: Unexpected error during stop: {e}")
            finally:
                # 3. Always clean up the state regardless of how it died
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
