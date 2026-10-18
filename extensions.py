"""Compatibility shim.

The canonical extension objects live in :mod:`securecloud.extensions`.  This
module re-exports them so that the layout documented in the project tree
(``extensions.py`` at the repository root) keeps working.
"""
from securecloud.extensions import csrf, db, limiter  # noqa: F401

__all__ = ["db", "csrf", "limiter"]
