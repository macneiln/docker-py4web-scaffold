import debugpy
import pytest

print("Debugpy launched ...")
debugpy.listen(("0.0.0.0", 5678))
# debugpy.wait_for_client()

print("Pytest starting ...")
exit_code = pytest.main(['./apps/_default/tests'])

# pytest.main(['--cov']) # No test debugging
# pytest.main(['--cov', '--cov-report', 'html']) # No test debugging
exit(exit_code) # So github actions recognize success or failure.