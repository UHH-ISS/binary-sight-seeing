# Optional import. Only required when using the get_pid_by_name function.
try:
    import psutil
except ModuleNotFoundError:
    pass
import enum
from .types import *

__all__ = [
    "get_pid_by_name",
    "RpycEnum",
    "parse_bootstrap_list_file",
    "reverse_bytes_num",
]

def host_address_to_str(addr: HostServiceAddress) -> str:
    return f"{addr[0]}:{addr[1]}"

# Gets a process ID by a processe's name.
def get_pid_by_name(name: str) -> Optional[int]:
    for proc in psutil.process_iter():
        try:
            if proc.name() == name:
                return proc.pid
        except: pass
    return None

# The Enum function does not work for comparing the 
# local and the netref enum objects. This class
# overwrites the __eq__ method to compare by value.
class RpycEnum(enum.Enum):
    def __eq__(self, other) -> bool:
        return self.value == other.value

def parse_bootstrap_list_file(file: str) -> Set[HostServiceAddress]:
    res = set()
    with open(file) as f:
        for line in f:
            if line == "": continue
            split_line = line.split(":")
            res.add((IPv4Address(split_line[0]), int(split_line[1])))
    return res

# Reverse the byte order of an integer with the length
# given in bytes.
def reverse_bytes_num(num, length=4):
    return int.from_bytes(num.to_bytes(4, 'big'), 'little')