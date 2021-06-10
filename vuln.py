from typing import Dict, Tuple, List, Optional, AnyStr, Generator
from dataclasses import dataclass
import enum


class VulnerabilityClass(enum.IntEnum):
    root = 3
    user = 2
    guest = 1
    none = 0


@dataclass(eq=True, frozen=True)
class Vulnerability:
    name: str
    type: VulnerabilityClass


class VulnRegistry:
    __vulns: Dict[str, Vulnerability] = dict()

    @classmethod
    def get(cls, name: str) -> Vulnerability:
        return cls.__vulns.get(name)

    @classmethod
    def has(cls, key: str) -> bool:
        return key in cls.__vulns

    @classmethod
    def add(cls, key: str, vuln: Vulnerability) -> None:
        cls.__vulns[key] = vuln
