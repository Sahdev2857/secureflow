from typing import Literal

from pydantic import BaseModel, Field

from secureflow.messages import TrustLevel


class Fragment(BaseModel):
    sender: str
    recipient: str
    trust: TrustLevel = TrustLevel.AGENT
    content: str


class Case(BaseModel):
    id: str
    split: Literal["dev", "test"]
    label: Literal["attack", "benign"]
    kind: Literal["whole", "split_2", "split_3", "split_encoded", "benign_plain", "benign_lookalike"]
    fragments: list[Fragment] = Field(min_length=1)
    expected_flag: bool
    notes: str
