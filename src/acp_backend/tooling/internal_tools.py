from __future__ import annotations

from typing import Any, Callable, Dict


class InternalToolRegistry:
    def __init__(self) -> None:
        self._tools: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {}
        self.register("echo", lambda args: {"echo": args})
        self.register("sum_numbers", lambda args: {"sum": sum(args.get("numbers", []))})

    def register(self, name: str, func: Callable[[Dict[str, Any]], Dict[str, Any]]) -> None:
        self._tools[name] = func

    def execute(self, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        if name not in self._tools:
            raise ValueError("unknown_tool")
        return self._tools[name](args)
