from __future__ import annotations
from dataclasses import dataclass
import glob
import os

from .types import *

__all__ = [
    "InstrumentedInstruction",
]

@dataclass
class InstrumentedInstruction:
    addr: int
    opcode: int
    mnemonic: str
    disasm: str
    image: str

    @staticmethod
    def from_line(line: str) -> Optional[InstrumentedInstruction]:
        if line == "": return None
        split_line = line.split(";")
        return InstrumentedInstruction(
            addr=int(split_line[0]),
            opcode=int(split_line[1]),
            mnemonic=split_line[2],
            disasm=split_line[3],
            image=";".join(split_line[4:])
        )

def load_ins_log(data_path: str) -> Dict[int, Dict[int, InstrumentedInstruction]]:
    path = os.path.join(data_path, "ins_log.*")
    res: Dict[int, Dict[int, InstrumentedInstruction]] = dict()
    for file in glob.glob(path):
        pid = int(file.split(".")[-1])
        res[pid] = {}
        with open(file) as f:
            for line in f:
                ins = InstrumentedInstruction.from_line(line)
                if ins is not None:
                    res[pid][ins.addr] = ins
    return res