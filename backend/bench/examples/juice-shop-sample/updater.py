import os

def run_update(package_name):
    # CWE-78: OS Command Injection
    cmd = "pip install " + package_name
    os.system(cmd)
