from __future__ import annotations

import json
from pathlib import Path

from argus.events.schema import Event


class JsonlLogger:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._events: list[Event] = []

    def append(self, event: Event) -> None:
        self._events.append(event)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(event.model_dump_json() + "\n")

    @property
    def events(self) -> list[Event]:
        return list(self._events)

    @classmethod
    def load(cls, path: Path) -> list[Event]:
        events: list[Event] = []
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    events.append(Event.model_validate(json.loads(line)))
        return events
