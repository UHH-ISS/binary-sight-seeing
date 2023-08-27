# python -m puppeteering.poi.tests.test_memory_pattern_poi

from puppeteering.poi.memory_pattern_poi import *
from ipaddress import IPv4Address
HostServiceAddress = Tuple[IPv4Address, int]


class DummyConfig:
    bootstrap_list = set() # HostServiceAddress
    
class DummyAutoPuppet:
    new_peers = set() # HostServiceAddress
    config = DummyConfig()
    
    
def test_memory_patterns_generated_from_ips():
    auto_puppet = DummyAutoPuppet()
    tc = DummyConfig()
    ip1 = IPv4Address("1.2.3.4")
    ip2 = IPv4Address("192.168.0.1")
    ip3 = IPv4Address("5.5.5.5")
    
    tc.bootstrap_list.add((ip1, 1338))
    tc.bootstrap_list.add((ip2, 1338))
    tc.bootstrap_list.add((ip3, 1338))
    auto_puppet.config = tc

    memory_pattern_poi_exr = MemoryPatternPoiExtractor(auto_puppet, "./puppeteering/poi/tests/data_dir", 4)   
    for mem_pat in memory_pattern_poi_exr.all_ips:
        print(mem_pat)
    for poi in memory_pattern_poi_exr.get_pois():
        print(poi)

def memory_pattern_found():
    pass

def memory_pattern_evaluated():
    pass

if __name__ == "__main__":
    test_memory_patterns_generated_from_ips()