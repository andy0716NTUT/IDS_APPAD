"""
APPAD core package.

Exposes the main components so tests and demos can simply import:

    from Week3.appad_core import APPADCore, AdaptiveModule
"""

from .core import APPADCore
from .adaptive_module import AdaptiveModule

__all__ = ["APPADCore", "AdaptiveModule"]

