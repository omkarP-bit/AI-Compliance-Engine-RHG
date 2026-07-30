import os
import subprocess
import sys

policies_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "policies")

proc = subprocess.Popen(
    [
        "/usr/local/bin/opa", "run", "--server",
        "--addr=0.0.0.0:8181",
        "--set=decision_logs.console=true",
        policies_dir,
    ],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)

os.execvp("uvicorn", ["uvicorn", "ace.main:app", "--host", "0.0.0.0", "--port", "8000"])
