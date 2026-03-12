from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from adaptive_module.core.mixed_protection import MixedProtectionPipeline
from adaptive_routing.adaptive_router import AdaptiveRouter, RoutingConfig
from adaptive_routing.feature_encoder import SimpleRecordEncoder
from adaptive_routing.interfaces import Encryptor, ModelServerLike, RecordEncoder, SensitivityClassifierLike


@dataclass
class IDSSystemConfig:
    """
    Stable config surface for future full-system assembly.

    Keep this small and explicit so you can wire it from:
    - CLI args
    - env vars
    - config files
    - service settings
    """

    routing: RoutingConfig = field(default_factory=RoutingConfig)
    decision_threshold: float = 0.5


class IDSSystem:
    """
    A single stable entrypoint to assemble the full system later.

    External callers should depend on:
      - IDSSystem.process_event(raw_record) -> result dict

    Internally we can swap:
      - sensitivity classifier
      - encoder
      - HE encryptor
      - mixed protection pipeline
      - server model (real RPC/service later)
    """

    def __init__(
        self,
        config: Optional[IDSSystemConfig] = None,
        *,
        encryptor: Encryptor | None = None,
        sensitivity_clf: SensitivityClassifierLike | None = None,
        encoder: RecordEncoder | None = None,
        pipeline: MixedProtectionPipeline | None = None,
        server: ModelServerLike | None = None,
    ) -> None:
        self.config = config or IDSSystemConfig()

        # 在真實系統前提下：不再自動 fallback 到 FakeEncryptor
        if encryptor is None:
            raise ValueError(
                "IDSSystem 需要傳入一個真實的同態加密 encryptor（例如 ckks_homomorphic_encryption.PaillierEncryptor）。"
            )

        self.encryptor = encryptor
        self.encoder = encoder or SimpleRecordEncoder()
        self.pipeline = pipeline or MixedProtectionPipeline(encryptor=self.encryptor)

        # Router is the orchestrator for routing + privacy + inference + client decision
        self.router = AdaptiveRouter(
            config=self.config.routing,
            encryptor=self.encryptor,
            sensitivity_clf=sensitivity_clf,
            encoder=self.encoder,
            pipeline=self.pipeline,
            server=server,
            threshold=self.config.decision_threshold,
        )

    def process_event(self, raw_record: Dict[str, Any]) -> Dict[str, Any]:
        return self.router.process(raw_record)

