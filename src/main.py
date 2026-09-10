"""Launcher for the task-oriented controller app."""

from __future__ import annotations

import os
import sys

SRC_ROOT = os.path.abspath(os.path.dirname(__file__))
if SRC_ROOT not in sys.path:
    sys.path.insert(0, SRC_ROOT)


def main() -> None:
    from os_ken.base import app_manager
    from os_ken.lib.hub import HubThread

    if "ARF_MODEL_PATH" not in os.environ:
        default_model = os.path.abspath(os.path.join(SRC_ROOT, "models", "arf_model_major.pkl"))
        if os.path.exists(default_model):
            os.environ["ARF_MODEL_PATH"] = default_model

    if "--model" in sys.argv:
        idx = sys.argv.index("--model")
        if idx + 1 < len(sys.argv):
            os.environ["ARF_MODEL_PATH"] = sys.argv[idx + 1]
            sys.argv.pop(idx + 1)
        sys.argv.pop(idx)

    if not hasattr(HubThread, "kill"):
        HubThread.kill = lambda self: None

    try:
        app_manager.AppManager.run_apps(["controller.app"])
    except (KeyboardInterrupt, SystemExit):
        print("\n[+] Controller shut down gracefully.")


if __name__ == "__main__":
    main()
