"""AWS Lambda entrypoint for the RHG API."""
from mangum import Mangum

from rhg.main import app

handler = Mangum(app, lifespan="off")
