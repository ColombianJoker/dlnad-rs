#!/usr/bin/env python3.11
#
from setuptools import setup

APP = ["dlnad_manager.py"]
# DATA_FILES = [("", ["target/release/dlnad"])]
OPTIONS = {
    "argv_emulation": True,
    "plist": {
        "LSUIElement": True,  # This makes it a "Background/Menu" app (no Dock icon)
        "CFBundleName": "dlnad Manager",
        "CFBundleDisplayName": "dlnad Manager",
        "CFBundleIdentifier": "com.gunther.dlnad",
        "CFBundleVersion": "0.1.0",
        "CFBundleShortVersionString": "0.1.0",
    },
    "packages": [
        "rumps",
    ],
    "resources": ["target/release/dlnad"],
}

setup(
    app=APP,
    data_files=None,  # or DATA_FILES,
    options={"py2app": OPTIONS},
    setup_requires=["py2app"],
)
