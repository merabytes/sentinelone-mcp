"""Minimal dag_node / DagNotifier stubs for standalone MCP."""

from typing import Any, Callable, TypeVar

F = TypeVar("F", bound=Callable[..., Any])


class DagNotifier:
    def notify_dag(self, *args: Any, **kwargs: Any) -> None:
        pass


def dag_node(*args: Any, **kwargs: Any) -> Callable[[F], F]:
    def decorator(fn: F) -> F:
        return fn

    if args and callable(args[0]):
        return args[0]
    return decorator
