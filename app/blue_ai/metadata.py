from __future__ import annotations

import yaml

from ..config import config
from ..models import Action

_DEFAULT_META = {"action_criticality": 30, "privilege_impact": 30}


class ActionMetadata:
    """Loads action_metadata.yaml; provides intrinsic action properties.

    These are baseline/static properties. Dynamic risk comes from trajectory.
    """

    def __init__(self, path: str | None = None) -> None:
        path = path or config.ACTION_METADATA_PATH
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        self._actions: dict[str, dict] = data.get("actions", {})

    def get(self, action: Action | str) -> dict:
        value = action.value if isinstance(action, Action) else action
        return self._actions.get(value, dict(_DEFAULT_META))

    def action_criticality(self, action: Action | str) -> int:
        return int(self.get(action).get("action_criticality", _DEFAULT_META["action_criticality"]))

    def privilege_impact(self, action: Action | str) -> int:
        return int(self.get(action).get("privilege_impact", _DEFAULT_META["privilege_impact"]))
