"""Versioned prompt templates. Uses stdlib string.Template ($variable
substitution) rather than a full templating engine — no arbitrary
expression evaluation, which matters for a system that treats untrusted
document content as data that flows into prompts (see the threat-intel
handling design elsewhere in the plan)."""

from __future__ import annotations

import string
from dataclasses import dataclass


class PromptTemplateError(Exception):
    pass


@dataclass(frozen=True)
class PromptTemplate:
    name: str
    version: str
    template: str

    @property
    def id(self) -> str:
        return f"{self.name}@{self.version}"

    def render(self, **variables: str) -> str:
        try:
            return string.Template(self.template).substitute(**variables)
        except KeyError as exc:
            raise PromptTemplateError(
                f"template {self.id!r} is missing a value for variable {exc}"
            ) from exc
