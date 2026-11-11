import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(os.path.dirname(__file__), "fixtures")

def fixture(name):
    with open(os.path.join(FIX, name)) as fh:
        return fh.read()
