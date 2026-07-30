import os
import subprocess

# Start OPA at module load (Lambda init phase)
policies_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "policies")
subprocess.Popen(
    ["/usr/local/bin/opa", "run", "--server",
     "--addr=0.0.0.0:8181", "--set=decision_logs.console=true", policies_dir],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
)

from mangum import Mangum
from ace.main import app

handler = Mangum(app, lifespan="off")
