from dataclasses import dataclass
from typing import List


@dataclass
class FunctionInfo:
    name: str
    entry: str
    body_size: int

    calls: List[str]
    called_by: List[str]

    xrefs_in: int
    xrefs_out: int

    api_calls: List[str]
    strings: List[str]

    parameters: List[str]
    return_type: str