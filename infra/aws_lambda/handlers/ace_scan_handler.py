from mangum import Mangum

from ace.main import app

handler = Mangum(app, lifespan="off")
