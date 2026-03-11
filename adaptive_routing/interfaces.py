from __future__ import annotations

from typing import Any, Dict, Protocol, runtime_checkable


@runtime_checkable
class Encryptor(Protocol):
    """
    Client-side HE interface.

    The server can operate on ciphertexts, but must never decrypt.
    """

    def encrypt(self, value: Any) -> Any: ...

    def decrypt(self, ciphertext: Any) -> float: ...


class RecordEncoder(Protocol):
    """
    Converts raw event records (strings/mixed types) to numeric model features.
    """

    def encode(self, raw_record: Dict[str, Any]) -> Dict[str, float]: ...


class SensitivityClassifierLike(Protocol):
    """
    Record-level sensitivity classification interface (classifier module compatible).
    """

    def classify(self, record: Dict[str, Any]) -> Dict[str, Any]: ...


class ModelServerLike(Protocol):
    """
    Server-side model inference interface.
    """

    def infer(self, payload: Dict[str, Dict[str, Any]]) -> Any: ...

