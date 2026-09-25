"""Profile orchestration: declarative profiles → DAG of tool runs.

- ``profile``  — profile / step models and the built-in profile library
- ``dag``      — dependency-aware parallel executor (retry, timeout, cancel)
- ``steps``    — runs one step (tool with fallback chain, or built-in action)
- ``runs``     — profile runs: lifecycle, background worker, run.json
"""
