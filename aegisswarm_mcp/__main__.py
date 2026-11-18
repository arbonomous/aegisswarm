"""python -m aegisswarm_mcp -- <upstream command...>"""
import runpy

runpy.run_module("swarmguard_mcp", run_name="__main__")
