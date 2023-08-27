from ast import parse
import multiprocessing
import glob
import os
import logging
import functools
import itertools
from typing import TypeVar

from .base import PoiExtractor, Poi
from ..types import *
#from ..auto_puppeteer import AutoPuppeteer
from ..trace_reader import TraceLineFilter, all_trace_lines, TraceLineType, TraceLine
from ..util import reverse_bytes_num
from ..ins_log_reader import InstrumentedInstruction, load_ins_log

class NaivePoi:
    NEXT_ID = 0
    def __init__(self, address: int, opcode: int, match_type: TraceLineFilter.Match, byte_order: TraceLineFilter.FilterDetails, confidence_score: Optional[float] = None):
        self.id = NaivePoi.NEXT_ID
        NaivePoi.NEXT_ID += 1
        self.address = address
        self.opcode = opcode
        self.match_type = match_type
        self.byte_order = byte_order
        self.confidence_score = confidence_score

    def __eq__(self, o: object) -> bool:
        if isinstance(o, NaivePoi):
            return self.id == o.id
        return False

    def __hash__(self) -> int:
        return hash(self.id)

    # Extract the raw value from a trace line.
    def extract(self, tl):
        # When the POI is for a register and the trace line is for a register:
        if self.match_type.is_reg() and tl.type == TraceLineType.REGS:
            # Extract the corresponding register.
            if self.match_type == TraceLineFilter.Match.REG_EAX:
                val = tl.eax
            elif self.match_type == TraceLineFilter.Match.REG_EBX:
                val = tl.ebx
            elif self.match_type == TraceLineFilter.Match.REG_ECX:
                val = tl.ecx
            elif self.match_type == TraceLineFilter.Match.REG_EDX:
                val = tl.edx
            elif self.match_type == TraceLineFilter.Match.REG_ESI:
                val = tl.esi
            elif self.match_type == TraceLineFilter.Match.REG_EDI:
                val = tl.edi
            else:
                raise RuntimeError("Unknown match_type")

            # Reverse the byte order if required, i.e., LSB-first -> MSB-first.
            if self.byte_order == TraceLineFilter.FilterDetails.ORDER_LSB_FIRST:
                val = reverse_bytes_num(val)
            return val
        # When the POI is for a memory write and the trace line is for a memory write,
        # OR when the POI is for a memory read and the trace line is for a memory read:
        if (self.match_type == TraceLineFilter.Match.MEM_R and tl.type == TraceLineType.MEM_R) or\
                (self.match_type == TraceLineFilter.Match.MEM_W and tl.type == TraceLineType.MEM_W):
            # Read the bytes from the buffer in the correct order. This returns a number.
            if self.byte_order == TraceLineFilter.FilterDetails.ORDER_LSB_FIRST:
                return int.from_bytes(tl.mem_buffer[0:4], "little")
            elif self.byte_order == TraceLineFilter.FilterDetails.ORDER_MSB_FIRST:
                return int.from_bytes(tl.mem_buffer[0:4], "big")

        return None       

    # Extract the value from the trace line but interpret it as an IP address.
    def extract_ip(self, tl: TraceLine) -> Optional[IPv4Address]:
        val = self.extract(tl)
        if val is not None:
            val = IPv4Address(val)
        return val

    # Extract the value from the trace line but interpret it as a port.
    def extract_port(self, tl: TraceLine) -> Optional[int]:
        return self.extract(tl)

T = TypeVar("T")

def _ordered_results(files: List[str], results: List[T]) -> List[T]:
    file_data = map(_parse_trace_filename, files)
    combined = zip(file_data, results)
    return list(map(
        lambda x: x[1],
        sorted(
            combined,
            key=lambda x: x[0]
        )
    ))

def _parse_trace_filename(filename: str) -> Tuple[int, int]:
    pid = int(filename.split(".")[-1])
    index_str = filename.split(".")[-2]
    try:
        index = int(index_str)
    except ValueError:
        index = 0
    return (pid, index)


def _find_candidates(multiple_ports, tl_filter_new, port_filter_new, file: str) -> Tuple[
    Dict[Tuple[int, int, TraceLineFilter.Match], Tuple[int, int]],
    Dict[Tuple[int, int, TraceLineFilter.Match], Tuple[int, int]]
]:
    # Find IP and port POI candidates:
    # For every trace line that matches the NP filter,
    # log the match. Count LSB and MSB matches
    # independently from each other.
    i = 0
    candidates: Dict[Tuple[int, int, TraceLineFilter.Match], Tuple[int, int]] = {}
    port_candidates: Dict[Tuple[int, int, TraceLineFilter.Match], Tuple[int, int]] = {}
    for pid,tl in all_trace_lines(file, parse_glob=False):
        # if i % 10**5 == 0: self.logger.debug(f"Phase 1 @ TL {i}")
        i += 1
        match = tl_filter_new.matches(tl)
        if match:
            if tl.instruction_address not in candidates:
                candidates[(pid, tl.instruction_address, match[1])] = (0, 0)
            lsb, msb = candidates[(pid, tl.instruction_address, match[1])]
            if match[2] == TraceLineFilter.FilterDetails.ORDER_LSB_FIRST:
                lsb += 1
            elif match[2] == TraceLineFilter.FilterDetails.ORDER_MSB_FIRST:
                msb += 1
            candidates[(pid, tl.instruction_address, match[1])] = (lsb, msb)
        
        if not multiple_ports: continue

        match = port_filter_new.matches(tl)
        if match:
            if tl.instruction_address not in candidates:
                port_candidates[(pid, tl.instruction_address, match[1])] = (0, 0)
            lsb, msb = port_candidates[(pid, tl.instruction_address, match[1])]
            if match[2] == TraceLineFilter.FilterDetails.ORDER_LSB_FIRST:
                lsb += 1
            elif match[2] == TraceLineFilter.FilterDetails.ORDER_MSB_FIRST:
                msb += 1
            port_candidates[(pid, tl.instruction_address, match[1])] = (lsb, msb)
    return (candidates,port_candidates)

def _count_occurences(candidate_pois, candidate_port_pois, all_ips, all_ports, file: str) -> Tuple[
    Dict[NaivePoi, Tuple[int, int, List[IPv4Address]]],
    Dict[NaivePoi, Tuple[int, int, List[int]]],
]:
    poi_counts: Dict[NaivePoi, Tuple[int, int, List[IPv4Address]]] = dict()
    port_poi_counts: Dict[NaivePoi, Tuple[int, int, List[int]]] = dict()
    
    # Calculate the confidence score.
    # We do this for both IP and port POI candidates
    # even though we only use the confidence score for
    # IP POI candidates.
    i = 0
    poi_counts: Dict[NaivePoi, Tuple[int, int, List[IPv4Address]]] = dict()
    port_poi_counts: Dict[NaivePoi, Tuple[int, int, List[int]]] = dict()
    # TODO opcode check necessary?
    for _,tl in all_trace_lines(file, parse_glob=False):
        # if i % 10**5 == 0: self.logger.debug(f"Phase 2 @ TL {i}")
        i += 1
        if tl.instruction_address in candidate_pois:
            for candidate_poi in candidate_pois[tl.instruction_address]:
                if candidate_poi not in poi_counts:
                    poi_counts[candidate_poi] = (0, 0, [])
                ip = candidate_poi.extract_ip(tl)
                if ip:
                    current_score = poi_counts[candidate_poi]
                    current_score[2].append(ip)
                    if ip in all_ips:
                        poi_counts[candidate_poi] = (current_score[0]+1, current_score[1]+1, current_score[2])
                    else:
                        poi_counts[candidate_poi] = (current_score[0], current_score[1]+1, current_score[2])

        if tl.instruction_address in candidate_port_pois:
            for candidate_poi in candidate_port_pois[tl.instruction_address]:
                if candidate_poi not in port_poi_counts:
                    port_poi_counts[candidate_poi] = (0, 0, [])
                port = candidate_poi.extract_port(tl)
                if port:
                    current_score = port_poi_counts[candidate_poi]
                    current_score[2].append(port)
                    if port in all_ports:
                        port_poi_counts[candidate_poi] = (current_score[0]+1, current_score[1]+1, current_score[2])
                    else:
                        port_poi_counts[candidate_poi] = (current_score[0], current_score[1]+1, current_score[2])
    return (poi_counts,port_poi_counts)

def _extract_ips_ports(
    ip_pois: Dict[int, Set[NaivePoi]],
    port_pois: Dict[int, Set[NaivePoi]],
    ins_log: Dict[int, Dict[int, InstrumentedInstruction]],
    file: str) -> Tuple[
    Dict[NaivePoi, List[IPv4Address]],
    Dict[NaivePoi, List[int]]
]:
    ip_poi_res: Dict[NaivePoi, List[IPv4Address]] = {}
    port_poi_res: Dict[NaivePoi, List[int]] = {}
    for pid,tl in all_trace_lines(file, parse_glob=False):
        try:
            ins = ins_log[pid][tl.instruction_address]
        except KeyError:
            # self.logger.error("Error loading instruction log for trace line.")
            continue
        if tl.instruction_address in ip_pois:
            pois_for_addr: Set[NaivePoi] = ip_pois[tl.instruction_address]
            for poi in pois_for_addr:
                if poi.opcode != ins.opcode: continue
                new_ip = poi.extract_ip(tl)
                if new_ip:
                    if poi not in ip_poi_res:
                        ip_poi_res[poi] = []
                    ip_poi_res[poi].append(new_ip)
        if tl.instruction_address in port_pois:
            pois_for_addr: Set[NaivePoi] = port_pois[tl.instruction_address]
            for poi in pois_for_addr:
                if poi.opcode != ins.opcode: continue
                new_port = poi.extract_port(tl)
                if new_port:
                    if poi not in port_poi_res:
                        port_poi_res[poi] = []
                    port_poi_res[poi].append(new_port)
    return ip_poi_res,port_poi_res

class NaivePoiExtractor(PoiExtractor):
    NAME = "NaivePoiExtractor"        

    def __init__(self, auto_puppeteer, data_path: str, cores: int):
        self.logger = logging.getLogger(__name__)
        self.logger.info("Identifying naive IP and port POIs")
        self.auto_puppeteer = auto_puppeteer
        self.cores = cores

        ins_log = load_ins_log(data_path)

        all_peers = auto_puppeteer.config.bootstrap_list | auto_puppeteer.new_peers
        all_ips = set(map(lambda x: x[0], all_peers))
        all_ports = set(map(lambda x: x[1], all_peers))

        # Create TraceLineFilters for:
        # - Only IPs from BS
        # - Only IPs from NP
        # - IPs from both BS and NP.
        tl_filter_bs_new = TraceLineFilter()
        tl_filter_bs = TraceLineFilter()
        for peer in auto_puppeteer.config.bootstrap_list:
            tl_filter_bs.add_ip(peer[0])
            tl_filter_bs_new.add_ip(peer[0])
        tl_filter_new = TraceLineFilter()
        port_filer_new = TraceLineFilter()
        for peer in auto_puppeteer.new_peers:
            tl_filter_new.add_ip(peer[0])
            tl_filter_bs_new.add_ip(peer[0])
            port_filer_new.add_port(peer[1])

        proc_pool = multiprocessing.Pool(cores)
        trace_files = list(glob.glob(os.path.join(data_path, "trace.*")))

        f = functools.partial(
            _find_candidates,
            auto_puppeteer.bs_list_contains_multiple_ports,
            tl_filter_new,
            port_filer_new
        )
        candidate_results = proc_pool.map(f, trace_files)
        candidates: Dict[Tuple[int, int, TraceLineFilter.Match], Tuple[int, int]] = {}
        port_candidates: Dict[Tuple[int, int, TraceLineFilter.Match], Tuple[int, int]] = {}
        for ip_cand,port_cand in candidate_results:
            for x,(lsb,msb) in ip_cand.items():
                if x not in candidates:
                    candidates[x] = (lsb,msb)
                else:
                    lsb_old,msb_old = candidates[x]
                    candidates[x] = (lsb+lsb_old, msb+msb_old)
            for x,(lsb,msb) in port_cand.items():
                if x not in port_candidates:
                    port_candidates[x] = (lsb,msb)
                else:
                    lsb_old,msb_old = port_candidates[x]
                    port_candidates[x] = (lsb+lsb_old, msb+msb_old)

        # Check which for each address and match place:
        # Which byte order was more common. LSB-first or MSB-first.
        # Create a POI object for the more common variation.
        candidate_pois: Dict[int, List[NaivePoi]] = dict()
        for (pid,addr,match_type),(lsb,msb) in candidates.items():
            if lsb >= msb:
                byte_order = TraceLineFilter.FilterDetails.ORDER_LSB_FIRST
            else:
                byte_order = TraceLineFilter.FilterDetails.ORDER_MSB_FIRST

            try:
                ins = ins_log[pid][addr]
            except KeyError:
                self.logger.error("Error creating IP POI. Corresponding instruction log line does not exist.")
            else:
                if addr not in candidate_pois:
                    candidate_pois[addr] = []
                new_poi = NaivePoi(addr, ins.opcode, match_type, byte_order)
                candidate_pois[addr].append(new_poi)

        candidate_port_pois: Dict[int, List[NaivePoi]] = dict()
        for (pid,addr,match_type),(lsb,msb) in port_candidates.items():
            if lsb >= msb:
                byte_order = TraceLineFilter.FilterDetails.ORDER_LSB_FIRST
            else:
                byte_order = TraceLineFilter.FilterDetails.ORDER_MSB_FIRST
            try:
                ins = ins_log[pid][addr]
            except KeyError:
                self.logger.error("Error creating port POI. Corresponding instruction log line does not exist.")
            else:
                if addr not in candidate_port_pois:
                    candidate_port_pois[addr] = []
                new_poi = NaivePoi(addr, ins.opcode, match_type, byte_order)
                candidate_port_pois[addr].append(new_poi)

        f = functools.partial(
            _count_occurences,
            candidate_pois,
            candidate_port_pois,
            all_ips,
            all_ports
        )
        count_results = proc_pool.map(f, trace_files)
        poi_counts: Dict[NaivePoi, Tuple[int, int, List[IPv4Address]]] = dict()
        port_poi_counts: Dict[NaivePoi, Tuple[int, int, List[int]]] = dict()
        for ip_count,port_count in _ordered_results(trace_files, count_results):
            for poi,(a,b,c) in ip_count.items():
                if poi not in poi_counts:
                    poi_counts[poi] = (a, b, c)
                else:
                    x,y,z = poi_counts[poi]
                    poi_counts[poi] = (a+x, y+b, z+c)
            for poi,(a,b,c) in port_count.items():
                if poi not in port_poi_counts:
                    port_poi_counts[poi] = (a, b, c)
                else:
                    x,y,z = port_poi_counts[poi]
                    port_poi_counts[poi] = (a+x, y+b, z+c)

        self.unused_ip_pois: Set[NaivePoi] = set()
        self.ip_pois: Dict[int, Set[NaivePoi]] = {}
        self.unused_port_pois: Set[NaivePoi] = set()
        self.port_pois: Dict[int, Set[NaivePoi]] = {}
        self.poi_mapping: Dict[NaivePoi, Set[NaivePoi]] = {}

        ip_poi_count = 0
        for poi,(interesting,total,ips) in poi_counts.items():
            poi.confidence_score = interesting/total
            if poi.confidence_score >= auto_puppeteer.config.confidence_score_threshold:
                if poi.address not in self.ip_pois:
                    self.ip_pois[poi.address] = set()
                self.ip_pois[poi.address].add(poi)
                ip_poi_count += 1
            else:
                self.unused_ip_pois.add(poi)

        # Try matching the IP and port POIs by 
        # comparing the extracted values for all
        # possible permutations of IP and port POI.
        # Skip IP POIs that do not fulfill the confidence_score_threshold 
        # filter.
        for ip_poi,(_,_,ips) in poi_counts.items():
            if ip_poi.confidence_score < auto_puppeteer.config.confidence_score_threshold: continue
            for port_poi,(_,_,ports) in port_poi_counts.items():
                matches = True
                for ip,port in zip(ips,ports):
                    if ip in all_ips and (ip,port) not in all_peers:
                        matches = False
                if matches:
                    if ip_poi not in self.poi_mapping:
                        self.poi_mapping[ip_poi] = set()
                    self.poi_mapping[ip_poi].add(port_poi)
                    if port_poi.address not in self.port_pois:
                        self.port_pois[port_poi.address] = set()
                    self.port_pois[port_poi.address].add(port_poi)
        for port_poi in port_poi_counts.keys():
            if port_poi.address not in self.port_pois or port_poi not in self.port_pois[port_poi.address]:
                self.unused_port_pois.add(port_poi)

        self.logger.info(f"Identified {ip_poi_count}/{len(poi_counts)} IP POI candidates (confidence_score_threshold)")
        self.logger.info(f"Identified {len(port_poi_counts)-len(self.unused_port_pois)}/{len(port_poi_counts)} port POI candidates (matching)")

        proc_pool.close()

    def __naive_poi_to_poi(self, t: Poi.PoiType, x: NaivePoi) -> Poi:
        assert(t != Poi.PoiType.IP or x.confidence_score is not None)
        return Poi(
            t,
            x.address,
            self.NAME,
            f"{x.match_type.name};{x.byte_order.name}",
            x.confidence_score
        )

    def extract_ips(self, data_path: str) -> Dict[HostServiceAddress, List[Poi]]:
        ip_poi_res: Dict[NaivePoi, List[IPv4Address]] = {}
        port_poi_res: Dict[NaivePoi, List[int]] = {}
        
        ins_log = load_ins_log(data_path)

        proc_pool = multiprocessing.Pool(self.cores)
        trace_files = list(glob.glob(os.path.join(data_path, "trace.*")))


        # Go through every trace line and see which IP and port POIs
        # correspond to the addresses (and opcodes).
        # Everytime we have a POI that matches the trace line,
        # we try to extract the IP/port using the POI.
        # This might fail: For example, we have a register IP POI for
        # address x. Of course, this POI is not able to extract an IP address
        # from a memory read trace line.
        f = functools.partial(
            _extract_ips_ports,
            self.ip_pois,
            self.port_pois,
            ins_log
        )
        results = proc_pool.map(f, trace_files)
        for ip_poi_res_l,port_poi_res_l in _ordered_results(trace_files, results):
            for poi,ips in ip_poi_res_l.items():
                if poi not in ip_poi_res:
                    ip_poi_res[poi] = []
                ip_poi_res[poi] += ips
            for poi,ports in port_poi_res_l.items():
                if poi not in port_poi_res:
                    port_poi_res[poi] = []
                port_poi_res[poi] += ports

        result: Dict[HostServiceAddress, List[Poi]] = dict()

        if self.auto_puppeteer.bs_list_contains_multiple_ports:
            for ip_poi,ips in ip_poi_res.items():
                if ip_poi not in self.poi_mapping: continue
                for port_poi in self.poi_mapping[ip_poi]:
                    if port_poi not in port_poi_res: continue
                    ports = port_poi_res[port_poi]
                    for ip,port in zip(ips, ports):
                        if not self.auto_puppeteer.ignore_ip(str(ip)):
                            relevant_poi = self.__naive_poi_to_poi(Poi.PoiType.IP, ip_poi)
                            result.setdefault((ip, port), []).append(relevant_poi)
                            # result.add((ip, port))
        else:
            fixed_port = self.auto_puppeteer.bs_list_port
            if fixed_port is None: raise RuntimeError("Should not happen")
            for ip_poi,ips in ip_poi_res.items():
                for ip in ips:
                    if not self.auto_puppeteer.ignore_ip(str(ip)):
                        relevant_poi = self.__naive_poi_to_poi(Poi.PoiType.IP, ip_poi)
                        result.setdefault((ip, fixed_port), []).append(relevant_poi)
                        # result.add((ip, fixed_port))

        proc_pool.close()
        return result   

    def get_pois(self) -> Iterable[Poi]:
        ip_mapper = functools.partial(self.__naive_poi_to_poi, Poi.PoiType.IP)
        port_mapper = functools.partial(self.__naive_poi_to_poi, Poi.PoiType.PORT)
        return itertools.chain(
            map(ip_mapper, itertools.chain.from_iterable(self.ip_pois.values())),
            map(port_mapper, itertools.chain.from_iterable(self.port_pois.values()))
        )