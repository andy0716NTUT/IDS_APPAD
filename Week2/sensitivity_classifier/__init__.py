"""
Field-level sensitivity classifier package.

This file makes `Week2.sensitivity_classifier` a proper package so that
imports like

    from Week2.sensitivity_classifier.classifier import SensitivityClassifier

work reliably in tests and demos.
"""

from .classifier import SensitivityClassifier

__all__ = ["SensitivityClassifier"]

