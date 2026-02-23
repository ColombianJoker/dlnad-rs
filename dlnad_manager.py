#!/usr/bin/env python3.11
#
import datetime
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
        self.log_file_path = "/tmp/dlnad_manager.log"

        self.log("App initialized. Starting dlnad_manager...")

        # Load initial config
        config = self.load_config()
        self.dlna_dir = config.get("DLNA_DIR", os.path.expanduser("~"))
        self.custom_command = config.get("DLNAD_COMMAND")

        self.log(
            f"Values found: DLNA_DIR='{self.dlna_dir}', DLNAD_COMMAND='{self.custom_command}'"
        )

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

    def log(self, message):
        """Writes a timestamped message to /tmp/dlnad_manager.log and prints to stdout."""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_line = f"{timestamp} dlnad_manager {message}"
        print(log_line)
        try:
            with open(self.log_file_path, "a") as f:
                f.write(log_line + "\n")
        except Exception as e:
            print(f"Failed to write to log file: {e}")

    def load_config(self):
        """Search for DLNA_DIR and DLNAD_COMMAND in ~/.dlnad"""
        config = {}
        if os.path.exists(self.config_path):
            self.log(f"Config file found at {self.config_path}")
            try:
                with open(self.config_path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if "=" in line:
                            key, value = line.split("=", 1)
                            config[key.strip()] = value.strip().strip('"')
            except Exception as e:
                self.log(f"Error reading config file: {e}")
        else:
            self.log(f"Config file NOT found at {self.config_path}")
        return config

    def save_config(self, directory=None):
        """Save current configuration back to ~/.dlnad while preserving other variables."""
        config = self.load_config()

        if directory:
            self.log(
                f"Changing shared directory from '{self.dlna_dir}' to '{directory}'"
            )
            config["DLNA_DIR"] = directory
            self.dlna_dir = directory

        with open(self.config_path, "w") as f:
            for key, value in config.items():
                f.write(f'{key}="{value}"\n')

        self.title = f"{self.menu_icon} (Ready)"

    @rumps.clicked("Select New Directory")
    def select_directory(self, _):
        cmd = 'POSIX path of (choose folder with prompt "Select DLNA Shared Directory")'
        try:
            proc = subprocess.run(
                ["osascript", "-e", cmd], capture_output=True, text=True
            )
            if proc.returncode == 0:
                selected = proc.stdout.strip()
                if selected:
                    self.save_config(directory=selected)
                    for item in self.menu:
                        if (
                            isinstance(self.menu[item], rumps.MenuItem)
                            and "Current Dir:" in self.menu[item].title
                        ):
                            self.menu[item].title = f"Current Dir: {selected}"
                    rumps.notification("dlnad", "Directory Updated", selected)
        except Exception as e:
            self.log(f"Selection Error: {e}")
            rumps.alert(f"Selection Error: {e}")

    def start_service(self, _):
        if self.process:
            return

        if getattr(sys, "frozen", False):
            # When running as .app, binary is in Resources
            bundle_res = os.path.join(
                os.path.dirname(sys.executable), "..", "Resources"
            )
            binary_path = os.path.abspath(os.path.join(bundle_res, "dlnad"))
        else:
            # When running from source
            base_path = os.path.dirname(os.path.abspath(__file__))
            binary_path = os.path.join(base_path, "target", "release", "dlnad")

        config = self.load_config()
        self.custom_command = config.get("DLNAD_COMMAND")

        if self.custom_command:
            # CRITICAL: Quote paths to handle spaces correctly before splitting
            interpolated_cmd = self.custom_command.replace(
                "{s}", shlex.quote(self.dlna_dir)
            )
            interpolated_cmd = interpolated_cmd.replace("{d}", shlex.quote(binary_path))
            interpolated_cmd = interpolated_cmd.replace(
                "{}", shlex.quote(self.dlna_dir)
            )
            cmd = shlex.split(interpolated_cmd)
        else:
            cmd = [binary_path, "-v", "-d", self.dlna_dir]

        self.log(f"Starting service with command: {' '.join(cmd)}")

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=True,
            )

            # Verification: Check if process died immediately
            threading.Timer(1.0, self.verify_process).start()

            thread = threading.Thread(target=self.read_logs, daemon=True)
            thread.start()

            self.start_button.set_callback(None)
            self.stop_button.set_callback(self.stop_service)
            self.title = f"{self.menu_icon} (Running)"
            rumps.notification(
                "dlnad", "Service Started", f"Running: {' '.join(cmd[:3])}..."
            )
            self.log(f"Service started successfully (PID: {self.process.pid})")
        except Exception as e:
            self.log(f"Failed to start service: {e}")
            rumps.alert(f"Failed to start service: {e}")

    def verify_process(self):
        """Checks if the process is still alive 1 second after starting."""
        if self.process:
            poll = self.process.poll()
            if poll is not None:
                self.log(
                    f"ERROR: Service process (PID {self.process.pid}) terminated immediately with exit code {poll}"
                )
                self.stop_service(None)
                rumps.notification(
                    "dlnad",
                    "Service Error",
                    "The process terminated immediately. Check logs.",
                )

    def read_logs(self):
        if self.process and self.process.stdout:
            for line in iter(self.process.stdout.readline, ""):
                self.log_content.append(line)
                if len(self.log_content) > 500:
                    self.log_content.pop(0)

    def stop_service(self, _):
        if self.process:
            self.log("Stopping service...")
            try:
                if self.process.poll() is None:
                    # Kill the whole process group using SIGTERM (default for kill)
                    pgid = os.getpgid(self.process.pid)
                    os.killpg(pgid, signal.SIGTERM)
                    self.log(f"Sent SIGTERM to process group {pgid}")
            except Exception as e:
                self.log(f"Error during stop: {e}")
            finally:
                self.process = None
                self.start_button.set_callback(self.start_service)
                self.stop_button.set_callback(None)
                self.title = self.menu_icon
                self.log("Service stopped.")

    @rumps.clicked("Show Console Log")
    def show_log(self, _):
        log_window = rumps.Window(
            title="dlnad Console Log",
            default_text="".join(self.log_content),
            ok="Close",
            dimensions=(600, 400),
        )
        log_window.run()

    @rumps.notifications
    def notification_handler(self, info):
        pass

    def on_quit(self):
        """Cleanup logic when app quits."""
        self.log("App quitting. Cleaning up...")
        if self.process:
            self.stop_service(None)
        self.log("Cleanup complete. terminating app.")

    # Overriding the default Quit handler in rumps
    @rumps.clicked("Quit")
    def quit(self, _):
        self.on_quit()
        rumps.quit_application()


if __name__ == "__main__":
    app = DLNADManager()
    app.run()
