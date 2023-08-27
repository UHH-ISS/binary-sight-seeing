import enum
import ipaddress
import struct
import glob
import functools
import os
from .util import reverse_bytes_num
from .types import *


class TraceLineType(enum.Enum):
    REGS = 0
    MEM_R = 1
    MEM_W = 2
    SOCKET_ENTRY = 3
    SOCKET_EXIT = 4

class TraceLine:
    def __init__(self):
        self.type: Optional[TraceLineType] = None
        # for socket trace lines, the instruction_address stores
        # the return address of the API call
        self.instruction_address: int = 0

        self.eax: int = 0
        self.ebx: int = 0
        self.ecx: int = 0
        self.edx: int = 0
        self.esi: int = 0
        self.edi: int = 0
        
        self.mem_buffer: bytes = bytes()
        self.mem_addr: int = 0
        self.destination_ip: int = 0
        self._hash = None
        

    def __str__(self):
        retval = f"[{self.type.name}]\t"
        if self.type == TraceLineType.MEM_R or self.type is TraceLineType.MEM_W:
            retval += f"IP: {hex(self.instruction_address)} ADDR: {hex(self.mem_addr)} BUF: {str(self.mem_buffer)}"
        elif self.type is TraceLineType.REGS:
            retval += f"IP: {hex(self.instruction_address)} EAX: {hex(self.eax)} EBX: {hex(self.ebx)} ECX: {hex(self.ecx)} EDX: {hex(self.edx)} ESI: {hex(self.esi)} EDI: {hex(self.edi)}"
        elif self.type is TraceLineType.SOCKET_ENTRY or self.type is TraceLineType.SOCKET_EXIT:
            ip = struct.unpack("<I", struct.pack(">I", self.destination_ip))[0]
            retval += f"IP_Addr: {ipaddress.IPv4Address(ip)}"
        return retval
    
    def __hash__(self) -> int:
        if not self._hash:
            self._hash = hash((self.type, self.instruction_address, self.mem_buffer, self.destination_ip,
                     self.eax, self.ebx, self.ecx, self.edx, self.esi, self.edi))
        return self._hash

    def __eq__(self, o: object) -> bool:
        if isinstance(o, TraceLine):
            if all([
                    self.instruction_address == o.instruction_address,
                    self.mem_buffer == o.mem_buffer,
                    #self.mem_addr == o.mem_addr,
                    self.destination_ip == o.destination_ip,
                    self.type == o.type,
                    self.eax == o.eax,
                    self.ebx == o.ebx,
                    self.ecx == o.ecx,
                    self.edx == o.edx,
                    self.esi == o.esi,
                    self.edi == o.edi
                ]):
                return True
        return False
    
    def __ne__(self, o: object) -> bool:
        return not self.__eq__(o)
    
    # Parse a single file from the file stream "file".
    @staticmethod
    def from_file(file):
        try:
            tl = TraceLine()
            d = file.read(4)
            assert(d == b"\xA1\xA2\xA3\xA4" or d == b"")
            tl.type = TraceLineType(file.read(1)[0])
            
            if tl.type is TraceLineType.REGS:
                tl.instruction_address = int.from_bytes(file.read(4), 'little')
                tl.eax = int.from_bytes(file.read(4), 'little')
                tl.ebx = int.from_bytes(file.read(4), 'little')
                tl.ecx = int.from_bytes(file.read(4), 'little')
                tl.edx = int.from_bytes(file.read(4), 'little')
                tl.esi = int.from_bytes(file.read(4), 'little')
                tl.edi = int.from_bytes(file.read(4), 'little')
            elif tl.type is TraceLineType.MEM_W or tl.type is TraceLineType.MEM_R:
                tl.instruction_address = int.from_bytes(file.read(4), 'little')
                tl.mem_addr = int.from_bytes(file.read(4), 'little')
                mem_buffer_size = int.from_bytes(file.read(4), 'little')
                tl.mem_buffer = file.read(mem_buffer_size)
            elif tl.type is TraceLineType.SOCKET_ENTRY:
                tl.destination_ip = int.from_bytes(file.read(4), 'little')
                tl.instruction_address = int.from_bytes(file.read(4), 'little')
            elif tl.type is TraceLineType.SOCKET_EXIT:
                tl.destination_ip = int.from_bytes(file.read(4), 'little')
                tl.instruction_address = int.from_bytes(file.read(4), 'little')
            else:
                raise RuntimeError("Unknown TraceLineType")
            return tl
        except (IndexError, AssertionError):
            return None
        except:
            raise RuntimeError("Error at index: " + hex(file.tell()))

def all_trace_lines(data_path: str, parse_glob=True, use_own_glob=False) -> Generator[Tuple[int, TraceLine], None, None]:
    if parse_glob:
        trace_glob = os.path.join(data_path, "trace.*")
        if use_own_glob:
            trace_glob = data_path
        files = glob.glob(trace_glob)
    else:
        files = [data_path]
    for file in files:
        pid = int(file.split(".")[-1])
        with open(file, "rb") as f:
            try:
                while True:
                    tl = TraceLine.from_file(f)
                    if tl is None: break
                    yield (pid, tl)
            except:
                raise RuntimeError("Exception in file: " + file)
# TODO merge
# https://stackoverflow.com/questions/4836710/is-there-a-built-in-function-for-string-natural-sort
import re
def natural_sort(l): 
    convert = lambda text: int(text) if text.isdigit() else text.lower() 
    alphanum_key = lambda key: [ convert(c) for c in re.split('([0-9]+)', key) ] 
    return sorted(l, key = alphanum_key)

def get_tracelines(filename, parse_glob=False):
    if parse_glob:
        trace_glob = os.path.join(filename, "trace.*")
        files = natural_sort(glob.glob(trace_glob))
        for file in files:
            print(file)
            with open(file, "rb") as f:
                try:
                    while True:
                        tl = TraceLine.from_file(f)
                        if tl is None: break
                        yield tl
                except Exception:
                    raise RuntimeError("Exception in file: " + file)
    else:
        file = open(filename, "rb")
        file.seek(0, 2)
        file_length = file.tell()
        file.seek(0, 0)

        while file.tell() != file_length:
            trace = TraceLine.from_file(file)
            yield trace

# A TraceLineFilter which is used to test
# whether a TraceLine contains either an
# IP or a port.
class TraceLineFilter():
    # Additional filter details (bitflag)
    class FilterDetails(enum.IntFlag):
        ORDER_MSB_FIRST = 1 << 0
        ORDER_LSB_FIRST = 1 << 1

    # The match place where the match was found.
    class Match(enum.IntEnum):
        REG_EAX = 0
        REG_EBX = 1
        REG_ECX = 2
        REG_EDX = 3
        REG_ESI = 4
        REG_EDI = 5
        MEM_R = 6
        MEM_W = 7

        def is_reg(self):
            return self <= 5
        def is_mem(self):
            return self >= 6

    def __init__(self):
        self.reg_matches = dict()
        self.mem_matches = dict()

    # Add an IP address to the filter.
    def add_ip(self, ip, reg_order=0b11, mem_order=0b11):
        # Add the IP value both with MSB- and LSB-first to mem_matches and reg_matches.
        if mem_order & self.FilterDetails.ORDER_MSB_FIRST:
            self.mem_matches[ip.packed] = (ip, self.FilterDetails.ORDER_MSB_FIRST)
        if mem_order & self.FilterDetails.ORDER_LSB_FIRST:
            self.mem_matches[ip.packed[::-1]] = (ip, self.FilterDetails.ORDER_LSB_FIRST)
        if reg_order & self.FilterDetails.ORDER_MSB_FIRST:
            self.reg_matches[int.from_bytes(ip.packed, 'big')] = (ip, self.FilterDetails.ORDER_MSB_FIRST)
        if reg_order & self.FilterDetails.ORDER_LSB_FIRST:
            self.reg_matches[int.from_bytes(ip.packed, 'little')] = (ip, self.FilterDetails.ORDER_LSB_FIRST)

    # Add a port to the filter.
    def add_port(self, port: int, reg_order=0b11, mem_order=0b11):
        # Add the port value both with MSB- and LSB-first to mem_matches and reg_matches.
        if mem_order & self.FilterDetails.ORDER_MSB_FIRST:
            self.mem_matches[port.to_bytes(4, 'big', signed=False)] = (port, self.FilterDetails.ORDER_MSB_FIRST)
        if mem_order & self.FilterDetails.ORDER_LSB_FIRST:
            self.mem_matches[port.to_bytes(4, 'little', signed=False)] = (port, self.FilterDetails.ORDER_LSB_FIRST)
        if reg_order & self.FilterDetails.ORDER_MSB_FIRST:
            self.reg_matches[port] = (port, self.FilterDetails.ORDER_MSB_FIRST)
        if reg_order & self.FilterDetails.ORDER_LSB_FIRST:
            self.reg_matches[reverse_bytes_num(port)] = (port, self.FilterDetails.ORDER_LSB_FIRST)

    # Check whether the trace line matches any of the values
    # in reg_matches or mem_matches.
    def matches(self, trace_line) -> Optional[Tuple[Any, Match, FilterDetails]]:
        for k,(val,details) in self.reg_matches.items():
            if trace_line.eax == k:
                return (val, self.Match.REG_EAX, details)
            elif trace_line.ebx == k:
                return (val, self.Match.REG_EBX, details)
            elif trace_line.ecx == k:
                return (val, self.Match.REG_ECX, details)
            elif trace_line.edx == k:
                return (val, self.Match.REG_EDX, details)
            elif trace_line.esi == k:
                return (val, self.Match.REG_ESI, details)
            elif trace_line.edi == k:
                return (val, self.Match.REG_EDI, details)
        for k,(val,details) in self.mem_matches.items():
            if trace_line.mem_buffer and trace_line.mem_buffer.startswith(k):
                if trace_line.type is TraceLineType.MEM_R:
                    match_type = self.Match.MEM_R
                else:
                    match_type = self.Match.MEM_W
                return (val, match_type, details)
        return None