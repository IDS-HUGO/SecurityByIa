import os

def serve_user_file(filename):
    # CWE-22: Path Traversal
    target = "public/uploads/" + filename
    with open(target, "r") as f:
        return f.read()
