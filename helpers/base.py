"""Minimal BaseHelper stub for standalone MCP."""


class BaseHelper:
    NODE_PREFIX: str = ""

    @classmethod
    def node_prefix(cls) -> str:
        if cls.NODE_PREFIX:
            return cls.NODE_PREFIX
        name = cls.__name__.replace("Helper", "")
        import re
        return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()
