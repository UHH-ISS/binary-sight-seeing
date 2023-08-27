import multiprocessing
import glob
import os
import logging
import functools
import dataclasses
import copy
from .memory_pattern_extractor import MemoryPattern, MemoryPatternExtractor
from .base import PoiExtractor, Poi
from ..types import *
from ..trace_reader import TraceLineFilter, all_trace_lines, TraceLineType, TraceLine
from ..util import reverse_bytes_num
from ..ins_log_reader import load_ins_log

import itertools
from typing import Generator, List, Mapping, NamedTuple, Optional, Union
from puppeteering.trace_reader import TraceLineType, TraceLine, get_tracelines


SEARCH_POIS = True
RATE_POIS = False

def _search_pois_worker(filename: str, mem_extr: MemoryPatternExtractor, operation_mode = SEARCH_POIS):
    """Called in a process pool to search POIs"""
    if operation_mode == RATE_POIS:
        mem_extr.prepare_poi_rating()
        
    traceline_gen = all_trace_lines(filename, parse_glob=True, use_own_glob=True)
    for pid, tl in traceline_gen:
        mem_extr.process_traceline(tl, operation_mode)
    return (filename, mem_extr)


def _score_pois_worker(filename: str, mem_extr: MemoryPatternExtractor):
    """Called in a process pool to score POIs"""
    return _search_pois_worker(filename, mem_extr, operation_mode=RATE_POIS)


def _extract_ips_ports(filename: str, mem_extr: MemoryPatternExtractor):
    pass
    # return All Patterns


class MemoryPatternPoiExtractor(PoiExtractor):
    """IP and Port POI extraction. The scoring does not work well with memory patterns since 
    it is not easy to determine when something is done written"""
    
    NAME = "MemoryPatternPoiExtractor"

    def __init__(self, auto_puppeteer, data_path: str, cores: int):
        self.logger = logging.getLogger(__name__)
        self.logger.info("Identifying MemoryPattern IP and port POIs")
        self.auto_puppeteer = auto_puppeteer
        self.cores = 1 # cores
        self.data_path = data_path

        self.all_peers: List[HostServiceAddress] = auto_puppeteer.config.bootstrap_list | auto_puppeteer.new_peers

        self.ip_port_mapping: Dict[bytes, bytes] = dict()   
        self.all_ips: List[MemoryPattern] = []
        self.all_ports: List[MemoryPattern] = []
        for ip, port in map(lambda x: (x[0], x[1]), self.all_peers):
            b_ip = bytes(ip.__str__(), "utf-8")
            self.all_ips.append(MemoryPattern(b_ip, "IP-" + ip.__str__()))
            
            b_port = bytes(port.__str__(), "utf-8")
            self.all_ports.append(MemoryPattern(b_port, "Port-" + str(port)))
            
            self.ip_port_mapping[b_ip] = b_port


        first_pass_ip_pois = self._find_pois(self.all_ips)
        self.qualified_ip_pois = self._score_poi_candidates(first_pass_ip_pois, Poi.PoiType.IP)
        self.logger.info(f"Identified memory pattern IP POIs {self.qualified_ip_pois}")
        
        first_pass_port_pois = self._find_pois(self.all_ports)
        self.qualified_port_pois = self._score_poi_candidates(first_pass_port_pois, Poi.PoiType.PORT) 
        self.logger.info(f"Identified memory pattern port POIs {self.qualified_ip_pois}")

        self.result_pois: List[Poi] = []  # These are the final result pois
        self._match_ip_port_pois()
        self.logger.info(f"Final POIs {len(self.result_pois)}")
        

    def _reverse_pattern_endian(self, pattern: MemoryPattern):
        pattern.pattern_name = "Reversed-" + pattern.pattern_name
        pattern.pattern = pattern.pattern[::-1]
        
    def _find_pois(self, patterns: List[MemoryPattern]):
        trace_file_names = list(glob.glob(os.path.join(self.data_path, "trace.*")))
        
        unique_traces = list({os.path.join(self.data_path, "*." + trace.split(".")[-1]) for trace in trace_file_names})
        
        memory_pattern_extractors = []  # Setup extractors for each file 
        for _ in range(len(unique_traces)):
            m_extractor = MemoryPatternExtractor()
            for pattern in patterns:
                cloned_pattern = copy.deepcopy(pattern)  # Clones since we could have mult files
                m_extractor.add_memory_pattern(cloned_pattern)
            memory_pattern_extractors.append(m_extractor)

        for _ in range(len(unique_traces)):  # Setup reverse pattern (endian)
            m_extractor = MemoryPatternExtractor()
            for pattern in patterns:
                cloned_pattern = copy.deepcopy(pattern)
                self._reverse_pattern_endian(cloned_pattern)
                m_extractor.add_memory_pattern(cloned_pattern)
            memory_pattern_extractors.append(m_extractor)

        unique_traces.extend(unique_traces.copy())  # Extend for reverse patterns
        
        search_poi_arguments = [(fn, e) for fn, e in zip(unique_traces, memory_pattern_extractors)]       
        
        # execute search pois with one extractor for each file
        proc_pool = multiprocessing.Pool(self.cores)
        f = proc_pool.starmap(_search_pois_worker, search_poi_arguments)
        search_poi_arguments = [(fn, e) for fn, e in f]
        proc_pool.close()
        return search_poi_arguments
    
        
    def _score_poi_candidates(self, first_pass_pois: List[Tuple[str, MemoryPatternExtractor]], poi_type) -> List[Tuple[Poi, Set]]:
        proc_pool = multiprocessing.Pool(self.cores)
        f = proc_pool.starmap(_score_pois_worker, first_pass_pois)
        score_poi_arguments = [(fn, e) for fn, e in f]
        
        rated_pois = []
        
        for f , extr in score_poi_arguments:
            style = "Normal"
            if "Reversed" in extr.memory_patterns[0].pattern_name:
                style = "Reversed"
            
            for ip, info in extr.rated_pois.items():
                p = Poi(
                    poi_type,
                    ip,
                    self.NAME,
                    f"POI style:{style}, POI operation:{info[2]}, From file:{f}",
                    info[0] / info[1]
                )
                rated_pois.append((p, info[3]))
            
        return rated_pois


    def _match_ip_port_pois(self):
        self.result_pois = []
        visited_instructions = set()
        
        for ip_poi, accessed_ips in self.qualified_ip_pois:
            self.result_pois.append(ip_poi)
            
            # find matching port poi
            for port_poi, accessed_ports in self.qualified_port_pois:
                if port_poi.address in visited_instructions:
                    continue
                visited_instructions.add(port_poi.address)

                for ip in accessed_ips:
                    if ip not in self.ip_port_mapping:
                        continue
                    if self.ip_port_mapping[ip] in accessed_ports:
                        self.result_pois.append(port_poi)
                        break
                            
    # extracts ips and ports from pois
    def extract_ips(self, data_path: str) -> Set[HostServiceAddress]:
        """Extraction of excact IPs is not possible with the current pattern poi approach. 
        The POI is the last instruction address that accessed a pattern. 
        This could be at the end, at the start or at the middle.
        We could extract here everything that the POI instruction writes but the pattern
        be written from more than that instruction addresses.
        """        
        return set()

    
    def get_pois(self) -> Iterable[Poi]:      
        return self.result_pois