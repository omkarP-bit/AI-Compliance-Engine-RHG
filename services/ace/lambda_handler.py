import os
import subprocess
import time
import httpx

policies_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "policies")
proc = subprocess.Popen(
    ["/usr/local/bin/opa", "run", "--server",
     "--addr=0.0.0.0:8181", "--set=decision_logs.console=true", policies_dir],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
)

for _ in range(30):
    try:
        r = httpx.get("http://localhost:8181/health", timeout=1.0)
        if r.status_code == 200:
            break
    except Exception:
        pass
    time.sleep(0.25)

from mangum import Mangum
from ace.main import app

handler = Mangum(app, lifespan="off")
