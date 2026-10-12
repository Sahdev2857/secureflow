"""Strict structured hand-off formats used by the example workflow."""

from pydantic import BaseModel, Field


class ResearchNotes(BaseModel):
    topic: str
    facts: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)


class Draft(BaseModel):
    title: str
    markdown: str
