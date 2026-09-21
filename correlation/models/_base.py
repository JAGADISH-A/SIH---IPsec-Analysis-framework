"""Shared serialization helpers for the correlation data contract.

Standard library only. Never uses ``pickle``; only JSON-compatible primitives.
"""

import dataclasses
import json
from typing import Any, Dict, Type, TypeVar

T = TypeVar("T", bound="JsonModel")


class JsonModel:
    """Mixin providing ``dict`` and ``json`` serialization for frozen dataclasses.

    Subclasses implement a classmethod ``from_dict`` (and option ``validate``).
    Constraints are enforced in each model's ``__post_init__`` so that a model
    can never be constructed in an invalid state.
    """

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    def to_json(self, *, indent: int = 2, sort_keys: bool = False) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=sort_keys)

    @classmethod
    def from_json(cls: Type[T], raw: str) -> T:
        return cls.from_dict(json.loads(raw))

    def validate(self):
        """Validate constraints; returns ``self`` and raises ``ValueError``.

        Construction already validates via ``__post_init__``; this method is a
        convenience for chaining and for validation-only code paths.
        """
        return self