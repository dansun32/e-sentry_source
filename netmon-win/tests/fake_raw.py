"""Fake netmon-raw.exe: prints the admin fixture."""
import os, sys
sys.stdout.write(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "raw_admin.json")).read())
