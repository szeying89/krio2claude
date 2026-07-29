from __future__ import annotations


class MermaidParseError(Exception):
    def __init__(self, line: int, column: int, message: str, text: str = "") -> None:
        self.line = line
        self.column = column
        self.message = message
        self.text = text
        located = f"line {line}, column {column}: {message}"
        if text:
            located += f" (near {text!r})"
        super().__init__(located)
