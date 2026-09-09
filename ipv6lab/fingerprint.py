from dataclasses import dataclass, asdict
from typing import Optional

@dataclass
class Fingerprint:
    os_guess: str
    confidence: str
    evidence: list

def classify_reply(tc: int, hlim: int, fl: int) -> Fingerprint:
    evidence = [f"tc=0x{tc:02x}", f"hlim={hlim}", f"flow_label=0x{fl:x}"]

    if tc == 0 and hlim == 128 and fl == 0:
        return Fingerprint("Windows-like", "high", evidence)
    if tc == 0xFF and fl != 0:
        return Fingerprint("Linux-like", "high", evidence)
    if tc == 0xFF and fl == 0:
        return Fingerprint("macOS-like", "medium", evidence)
    if tc == 0 and fl == 0 and hlim == 64:
        return Fingerprint("BSD-like", "medium", evidence)

    return Fingerprint("Unknown", "low", evidence)

def to_dict(fp: Fingerprint):
    return asdict(fp)
