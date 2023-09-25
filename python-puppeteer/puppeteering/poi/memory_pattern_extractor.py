from dataclasses import dataclass, field
from os import access, pathsep
from re import T
from puppeteering.ins_log_reader import InstrumentedInstruction
from typing import List, Tuple, Dict, Set
from ..trace_reader import TraceLine, TraceLineType, all_trace_lines
import fire
import json

debug_mode = True

@dataclass(init=False)
class MemoryPattern:
    memory_locations: Set[int] # [mem_addr, ] 
    read_accessed_instructions: Set[Tuple[int, int]] # [(ip, mem_addr)]
    write_accessed_instructions: Set[Tuple[int, int]] # [(ip, mem_addr)]
    rated_pois: Dict[int, List] # ip -> Pattern_Bytes_Written, Bytes_Written, r/w
    pattern: bytes = bytes()
    pattern_name: str = ""

    def __init__(self, pattern: bytes, pattern_name: str) -> None:
        self.pattern = pattern
        self.pattern_name = pattern_name

        self.memory_locations = set()
        self.read_accessed_instructions = set()
        self.write_accessed_instructions = set()
        self.rated_pois = dict()
        
        
@dataclass
class InstructionInformation:
    instruction_address: int
    operation_mode: str # read, write or both
    amount_accessed_bytes: int = 0
    accessed_pattern_bytes: int = 0
    accessed_data: bytearray = field(default_factory=bytearray)
    accessed_memory_locations: list = field(default_factory=list)
    accessed_patterns: list = field(default_factory=list)


class MemoryPatternExtractor:
    MEM_VALUE = 0
    MEM_REGION = 1
    INSTRUCTION_ADDR = 2
    RATED = 3

    def __init__(self) -> None:
        self.memory_value_map = {} # ADDR -> [Value, Identifier, last written by, considered in rating]
        self.identifier_map = {} # IDENTIFIER -> Length

        self._memory_patterns: List[MemoryPattern] = []
        self._max_pattern_lenght: int = 0
        self.ips_debug = set()


        
    @property
    def memory_patterns(self):
        return self._memory_patterns

    def add_memory_pattern(self, pattern: MemoryPattern):
        """Add memory pattern to search

        Args:
            pattern (MemoryPattern): The named pattern to search
        """
        self._memory_patterns.append(pattern)

        if self._max_pattern_lenght < len(pattern.pattern): 
            self._max_pattern_lenght = len(pattern.pattern)   


    def prepare_poi_rating(self, shared_pattern_eval=True):
        """Prepares, poi rating by resetting internal maps
        if shared_pattern_eval is true, merge different patterns 
        """
        print("==Preparing poi rating==")
        
        self.memory_value_map = {}
        self.identifier_map = {}
        
        if shared_pattern_eval:
            self.visited_mem_addr = set()
            self.visited_write_instr_addr = set()
            self.visited_read_instr_addr = set()
            self.searched_patterns = set()
            self.pois_to_rate: Dict[int, InstructionInformation] = {} # ip -> Pattern_Bytes_Written, Bytes_Written, r/w, accessed_data
            self.extracted_data = set()
            
            for pattern in self.memory_patterns:
                self.searched_patterns.add(pattern.pattern)
                
                self.visited_mem_addr.update(pattern.memory_locations)
                
                for ip in pattern.read_accessed_instructions:
                    self.visited_read_instr_addr.add(ip[0])
                    
                for ip in pattern.write_accessed_instructions:
                    self.visited_write_instr_addr.add(ip[0])
                    

    def process_traceline(self, traceline: TraceLine, find_pois=True):
        """Processes the tracelines, building the memory map.
        find_pois: If true, find POIs, if false, rate them
        """

        # if traceline.instruction_address not in self.ips_debug:
        #     print("DEBUG", hex(traceline.instruction_address))
        #     self.ips_debug.add(traceline.instruction_address)
        #     if traceline.instruction_address < 0x10007000 and traceline.instruction_address > 0x10000000:
        #         print("MegaDebug", traceline)
        
        if traceline.type != TraceLineType.MEM_R and traceline.type != TraceLineType.MEM_W:
            return

        self._build_memory_map(traceline)

        if find_pois:
            self.search_memory_pattern(traceline)
        else:
            # E.g, an instruction writes a pattern. We are only interested in all writes of the instruction. Not the reads.
            # Thats why this here is splitted
            for ip in self.visited_read_instr_addr:
                if ip == traceline.instruction_address and traceline.type == TraceLineType.MEM_R:
                    self._update_pois(traceline, 'r')
                    break
            
            for ip in self.visited_write_instr_addr:
                if ip == traceline.instruction_address and traceline.type == TraceLineType.MEM_W:
                    self._update_pois(traceline, 'w')
                    break

    def _update_pois(self, traceline: TraceLine, mode='r'):
        other_mode = 'w' if mode == 'r' else 'r'
        
        instr_addr = traceline.instruction_address
        if instr_addr not in self.pois_to_rate:
            self.pois_to_rate[instr_addr] = InstructionInformation(instr_addr, mode)
        if self.pois_to_rate[instr_addr].operation_mode == other_mode:
            self.pois_to_rate[instr_addr].operation_mode = "r/w"
        
        self.pois_to_rate[instr_addr].amount_accessed_bytes += len(traceline.mem_buffer)
        self.pois_to_rate[instr_addr].accessed_data.extend(traceline.mem_buffer) # Results in a log of zero bytes
        self.pois_to_rate[instr_addr].accessed_memory_locations.append(traceline.mem_addr) # Results in a log of zero bytes
        
        # If a searched pattern was accessed
        pattern_data = self._pattern_accessed(traceline)
        if pattern_data:
            accessed_pattern = []
            if traceline.type == TraceLineType.MEM_R:
                for addr, mem in pattern_data:
                    for read_addr in mem[-1]:
                        self.pois_to_rate[read_addr].accessed_pattern_bytes += 1 
            elif traceline.type == TraceLineType.MEM_W:
                for _, mem in pattern_data:
                    self.pois_to_rate[mem[self.INSTRUCTION_ADDR]].accessed_pattern_bytes += 1
                    mem[self.RATED] = True

        
    def _pattern_accessed(self, traceline: TraceLine):
        for mem_addr in self.visited_mem_addr:
            pattern_min_addr = mem_addr
            for pattern in self.searched_patterns:
                pattern_max_addr = mem_addr + len(pattern) - 1
                if pattern_max_addr >= traceline.mem_addr and traceline.mem_addr >= pattern_min_addr: # relevant mem-location is accessed
                    memory_content = self.get_memory_content(pattern_min_addr, len(pattern))
                    if len(memory_content) < len(pattern): # Not enough bytes to hold the pattern, next
                        continue
                    
                    pattern_pos = memory_content.find(pattern) # is pattern there
                    if pattern_pos != -1:
                        relevant_mem_entries = []
                        
                        for i in range(pattern_min_addr+pattern_pos, pattern_min_addr+pattern_pos+len(pattern)):
                            relevant_mem_entries.append((i, self.memory_value_map[i]))
                        # Pattern found, cannot find another one
                        return relevant_mem_entries
        # Not one pattern found at this addr     
        return False


    def _build_memory_map(self, traceline: TraceLine):
        if debug_mode:
            debug_build_memory_map_hook(traceline)
            
        last_identifier = traceline.mem_addr
        regions_to_merge = []
        
        # Check position one before current insert
        if traceline.mem_addr - 1 in self.memory_value_map:
            last_identifier = self.memory_value_map[traceline.mem_addr - 1][self.MEM_REGION]

        regions_to_merge.append(last_identifier)

        # Check obvious positions in map
        for idx, byte in enumerate(traceline.mem_buffer):
            curr_addr = traceline.mem_addr + idx

            # Check if we need to merge regions
            if curr_addr in self.memory_value_map:
                tmp_identifier = self.memory_value_map[curr_addr][self.MEM_REGION]
                if tmp_identifier != last_identifier:
                    regions_to_merge.append(tmp_identifier)
                    last_identifier = tmp_identifier
            # Update range or Create new identifier
            else: 
                if last_identifier in self.identifier_map:
                    self.identifier_map[last_identifier] += 1
                else:
                    self.identifier_map[last_identifier] = 1
                    
            # Update memeory map        
            if traceline.type == TraceLineType.MEM_R and curr_addr in self.memory_value_map:
                old_data = self.memory_value_map[curr_addr]
                if old_data[0] == byte:
                    self.memory_value_map[curr_addr][1] = last_identifier
                    self.memory_value_map[curr_addr][-1].append(traceline.instruction_address) 
                else:
                    self.memory_value_map[curr_addr] = [byte, last_identifier, traceline.instruction_address, False, [traceline.instruction_address]] 
            else:
                self.memory_value_map[curr_addr] = [byte, last_identifier, traceline.instruction_address, False, []] 

        # Check postion one after current insert
        next_address = traceline.mem_addr + len(traceline.mem_buffer)
        if next_address in self.memory_value_map:
            next_identifier = self.memory_value_map[next_address][self.MEM_REGION]
            if next_identifier != last_identifier:
                regions_to_merge.append(next_identifier)

        # Merge identifiers
        while len(regions_to_merge) > 1:
            min_identifier = regions_to_merge.pop(0)
            next_identifier = regions_to_merge.pop(0)
            
            # Update size of identifier
            self.identifier_map[min_identifier] += self.identifier_map[next_identifier]

            # Update identifiers in memory map
            for address in range(next_identifier, next_identifier + self.identifier_map[next_identifier]):
                self.memory_value_map[address][self.MEM_REGION] = min_identifier

            self.identifier_map.pop(next_identifier)
            regions_to_merge.insert(0, min_identifier)        


    def search_memory_pattern(self, traceline: TraceLine):
        last_address = traceline.mem_addr
        instruction_address = traceline.instruction_address
        
        byte_array = bytearray()
        region_identifier = self.memory_value_map[last_address][self.MEM_REGION]
        region_length = self.identifier_map[region_identifier]

        copy_region_length = 0
        min_addr = 0
        max_addr = 0
        
        if debug_mode:
            debug_search_memory_pattern_hook(traceline)

        for pattern_obj in self.memory_patterns:
            if region_length < len(pattern_obj.pattern):
                continue    
            # Identify memory length to copy
            if copy_region_length == 0:
                min_addr = last_address - self._max_pattern_lenght
                if min_addr < region_identifier:
                    min_addr = region_identifier
                max_addr = last_address + len(traceline.mem_buffer) + self._max_pattern_lenght
                if max_addr > region_identifier + region_length:
                    max_addr = region_identifier + region_length
                copy_region_length = max_addr - min_addr

            if copy_region_length < len(pattern_obj.pattern):
                continue

            if not byte_array:
                byte_array = self.get_memory_content(min_addr, copy_region_length)
            
            # Last value was relevant to pattern and region is big enough to hold the pattern
            pos = byte_array.find(pattern_obj.pattern)
            if pos == -1:
                continue
            else:
                pattern_mem_addr = min_addr + pos
                pattern_obj.memory_locations.add(pattern_mem_addr)

                start_pattern_mem_addr = pattern_mem_addr
                end_pattern_mem_addr = pattern_mem_addr + len(pattern_obj.pattern)
                
                if (last_address + len(traceline.mem_buffer)) < start_pattern_mem_addr or last_address >= end_pattern_mem_addr: 
                    print(f"Trailing Pattern")
                    print("Trailing", traceline)
                    continue
                
                print(
                    f"Found Pattern '{pattern_obj.pattern_name}' at {hex(pattern_mem_addr)} IP {hex(instruction_address)} "
                    f"Op {traceline.type} current position {hex(last_address)}"
                )
                print("    Info", traceline)
                
                if traceline.type == TraceLineType.MEM_R:
                    pattern_obj.read_accessed_instructions.add((instruction_address, pattern_mem_addr))
                else:
                    pattern_obj.write_accessed_instructions.add((instruction_address, pattern_mem_addr))
                    
                # Add locations to found:
                for mem_addr in range(start_pattern_mem_addr, end_pattern_mem_addr):
                    instruction_address = self.memory_value_map[mem_addr][2]
                    pattern_obj.write_accessed_instructions.add((instruction_address, pattern_mem_addr))
                    print(f"    Sub {hex(instruction_address)} at {hex(mem_addr)} value {chr(self.memory_value_map[mem_addr][0])} | {hex(self.memory_value_map[mem_addr][0])}")
                                 

    def get_memory_content(self, start_addr, size) -> bytearray:
        byte_array = bytearray()
        for addr in range(start_addr, start_addr + size):
            try:
                byte_array.append(self.memory_value_map[addr][self.MEM_VALUE])
            except KeyError:
                break
        return byte_array

def debug_search_memory_pattern_hook(traceline: TraceLine):
    pass

def debug_build_memory_map_hook(traceline: TraceLine):
    pass


class MemoryPatternExtractorCLI:
    def __init__(self) -> None:
        self._memory_pattern_extractor = MemoryPatternExtractor()
        self._memory_pattern_list :List[MemoryPattern] = []
    
    def add(self, pattern: str, pattern_name: str):
        """memory pattern to search for

        Args:
            pattern (str): Pattern to search for in hex e.g., c0ffe
            pattern_name (str): Pattern name (should be unique)
        """
        patter_to_search = bytes.fromhex(pattern)
        pattern_name = pattern_name

        mp  = MemoryPattern(patter_to_search, pattern_name)
        self._memory_pattern_list.append(mp)
        self._memory_pattern_extractor.add_memory_pattern(mp)
        return self
    
    def file(self, path: str, rate_pois: bool = True, poifilename: str = None, instruction_details_file: str = None):
        """Searches in the specified file for the patterns and than prints the results for all patterns
        Args:
            path (str): Path to traceline file
            rate_pois (bool) 0 = False, 1 = True: POIs are searched and rated. If false POIs are only searched
            poifilename (str) json: Filename for POI file
            instruction_details_file (str) json: Filename for instruction details, e.g., what the POIs have read or written
        """
        print(path, rate_pois, poifilename, instruction_details_file)

        print("Beginning POI extraction")
        print("Tracefile:" , path)
        print("Pois will be rated:", rate_pois==True)
        print("Instruction details:", instruction_details_file)

        traceline_gen = all_trace_lines(path, parse_glob=True, use_own_glob=True)
        for pid, tl in traceline_gen:
            self._memory_pattern_extractor.process_traceline(tl)
        
        for m in self._memory_pattern_list:
            print(m)
                  
        if rate_pois:
            self._memory_pattern_extractor.prepare_poi_rating()
            traceline_gen_2 = all_trace_lines(path, parse_glob=True, use_own_glob=True)
            for pid, tl in traceline_gen_2:
                self._memory_pattern_extractor.process_traceline(tl, False)

            if poifilename:
                self.export_pois(poifilename)

        if instruction_details_file:
            with open(instruction_details_file, "w") as f:
                for k, v in self._memory_pattern_extractor.pois_to_rate.items():
                    f.writelines(hex(k))
                    f.write("\n")
                    f.writelines(str(v.accessed_patterns))
                    f.write("\n")
                    f.writelines(str(v.accessed_pattern_bytes))
                    f.write("\n")
                    f.writelines(str(v.accessed_data))
                    f.writelines("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
                
    def export_pois(self, filename: str):
        json_pois = []
        for ip, address_information in self._memory_pattern_extractor.pois_to_rate.items():
            poi = {}
            poi["poi_type"] = "MemoryPoi"
            poi["address"] = hex(ip)
            poi["confidence_score"] = f"{address_information.accessed_pattern_bytes}/{len(address_information.accessed_data)} "
            poi["extractor"] = "CLIContiguousPoiExtractor"
            poi["details"] = f"{address_information.operation_mode}"
            json_pois.append(poi)
            
        data = json.dumps(json_pois, indent=4)
        with open(filename, "w") as f:
            f.write(data)  

"""
Usuage:
Execute from python-puppeteer:
python -m puppeteering.poi.memory_pattern_extractor add 1.2.3.4 IP1 file PATH/TO/FILE

source\tools\InlinedFuncsOpt\inlined_funcs_ia32.asm
\inlined_funcs_ia32
"""    
if __name__ == "__main__":
    fire.Fire(MemoryPatternExtractorCLI)