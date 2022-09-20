import debugpy
from py4web.core import cli
print("Debugpy launched ...")
debugpy.listen(("0.0.0.0", 5678))
print("Py4web starting ...")
cli()