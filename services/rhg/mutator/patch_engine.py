"""Backward-compatible import path for the JSON Patch engine.

The canonical implementation now lives in :mod:`ace.mutator.patch_engine` so
that the ACE agentic loop (``ace.agents.graph``) can mutate artifacts without
depending on RHG — the ACE container image ships ``services/ace`` only, and the
dependency direction must stay ACE <- RHG.

``from rhg.mutator.patch_engine import PatchEngine`` keeps working unchanged.
"""

from ace.mutator.patch_engine import PatchEngine

__all__ = ["PatchEngine"]
