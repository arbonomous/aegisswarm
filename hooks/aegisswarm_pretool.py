#!/usr/bin/env python3
"""AegisSwarm IDE policy hook; delegates to the fail-closed hook implementation."""
import runpy
from pathlib import Path

runpy.run_path(str(Path(__file__).with_name("swarmguard_pretool.py")), run_name="__main__")
