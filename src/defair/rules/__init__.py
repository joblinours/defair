"""Detection rule supply chain: pinned sources, verified store, per-run assembly.

See ``sources.yaml`` (where rules come from) and ``lock/`` (exact pinned bytes).
"""

from defair.rules.lock import PROFILES, RuleIntegrityError, load_lock

__all__ = ["PROFILES", "RuleIntegrityError", "load_lock"]
