import dataclasses
import itertools
import logging
import os
import sys
import select
import functools
import json
import random
import shutil
import multiprocessing
import glob
from abc import ABC
from dataclasses import dataclass, field
from enum import IntEnum

from agent import IpcServer, WrapperFunction
from puppeteering.poi.base import Poi
from puppeteering.poi.memory_pattern_poi import MemoryPatternPoiExtractor
from puppeteering.util import host_address_to_str
from .types import *

from .vm import VirtualMachine
from .router import Router
from .agent_connector import AgentConnector
from .poi.naive import NaivePoiExtractor
from .poi import PoiExtractor
from .trace_reader import TraceLineType, all_trace_lines
from .ins_log_reader import load_ins_log

import time

__all__ = [
    "AutoPuppeteer",
    "AutoPuppeteerConfig",
]

class AutoPuppeteerPhase(IntEnum):
    INFER_BOOTSTRAP_LIST = 0
    SETUP_PUPPET = 1
    COLLECT_DATA = 2
    VERIFY_RETURNS = 3
    CRAWL = 4

def _get_socket_instructions(path: str) -> Tuple[int, List[int]]:
    all_tl = all_trace_lines(path, parse_glob=False)

    pid = 0
    addrs = []
    for p,tl in all_tl:
        pid = p
        if tl.type is TraceLineType.SOCKET_ENTRY \
                or tl.type is TraceLineType.SOCKET_EXIT:
            addrs.append(tl.instruction_address)
    return (pid, addrs)

@dataclass
class AutoPuppeteerConfig:
    vm: VirtualMachine # the puppeteer virtual machine
    agent_snapshot: str # the snapshot of vm where the agent is running
    agent_address: HostServiceAddress # the address under which the agent is reachable
    router: Router # the router
    analysis_package: str # the analysis package to use
    output_folder: str # the output folder
    infer_bootstrap_list: bool # whether to infer the bootstrap list
    create_text_log: bool # whether to create a text log file
    trace_images: List[str] # the images to trace (None for don't care, empty list for none)
    trace_non_image: bool # whether to trace instructions not belonging to any image
    max_trace_count: int # the maximum number of times an instruction is traced (0 for no limit)
    download_setup_output: bool # whether to download the output after running the setup step
    puppet_vm_ip: IPv4Address # the public ip of the puppet
    data_collection_duration: int # number of seconds to run the data colletion step
    dump_processes: bool # whether to dump the processes at the end of data collection
    confidence_score_threshold: float # the confidence score threshold for pois [0.0;1.0]
    mandatory_retry_count: int # the maximum number of times to retry crawling
    crawl_n_times: int # crawl peers from the crawl_n_times_list exactly n-times.
    peer_crawl_timeout: float # time since last message timeout for crawling a peer. if this setting is None, calculate timeout. Is unreliable for TCP.
    peer_crawl_timeout_hard: int # hard timeout for crawling a peer.
    peer_crawl_safety_factor: float # safety factor for calculating the peer_crawl_timeout
    initial_peer: HostServiceAddress # the first peer to crawl
    random_mouse: bool # perform random mouse movements when the VM is running
    learn_ipc_peers: bool # extract peers that are received in ipc messages while crawling
    crawl_ignore_bs: bool # don't crawl peers from the bootstrap list
    crawl_ignore_bs_exceptions: Set[HostServiceAddress] # crawl these peers even if they are on the bootstrap list
    trace_split_limit: int # the number of bbls to trace before splitting the trace file (0 for no splitting)
    parallel_cores: int # the number of processes to use for parallel operations
    poi_extractor_naive: bool # whether to use the NaivePoiExtractor
    poi_extractor_memory_pattern: bool # whether to use the MemoryPatternPoiExtractor
    crawl_n_times_list: Optional[List[HostServiceAddress]] = field(repr=False) # see crawl_n_times
    bootstrap_list: Set[HostServiceAddress] = field(repr=False) # the bootstrap list. not needed if infer_bootstrap_list is true

def _ipc_server_listen(ipc_server: IpcServer, wrapper_callback: Callable[[int, WrapperFunction, IPv4Address, int], Optional[bool]], check: PredicateFunction=lambda: True, timeout: int=None, on_start: Optional[Callable[[], None]]=None):
    until = 0
    opened_atleast_one_buffer = False
    ipc_server.set_redirect_callback(wrapper_callback)
    while not opened_atleast_one_buffer or ((not timeout or time.time() < until) and check()):
        open_buffers, _ = ipc_server.listen(1)
        if not opened_atleast_one_buffer and open_buffers != 0:
            opened_atleast_one_buffer = True
            if on_start is not None:
                on_start()
            if timeout:
                until = time.time() + timeout

def _run_pintool(agent_connection: AgentConnector, config: AutoPuppeteerConfig):
    agent_connection.run_pintool(
        create_text_log=config.create_text_log,
        trace_images=config.trace_images,
        trace_non_image=config.trace_non_image,
        max_trace_count=config.max_trace_count,
        random_mouse=config.random_mouse,
        trace_split_limit=config.trace_split_limit,
        debug=False,
    )

def _convert__ip(address: IPv4Address) -> IPv4Address:
    return IPv4Address(str(address))

class AutoPuppeteer(ABC):
    def __init__(self, config: AutoPuppeteerConfig):
        self.result_counter = 0

        self.config = config
        self.logger = logging.getLogger(__name__)
        self.logger.info(f"Found {len(self.config.bootstrap_list)} predefined bootstrap list entries")

        self.revert_functions: List[Callable[[], None]] = list()

        # Assigned by setup_puppet
        self.replacement_peer: HostServiceAddress = (IPv4Address("0.0.0.0"), 0)
        self.running_snapshot: str = ""

        # Assigned by collect_data
        self.collect_data_ipc_log: List[Tuple[WrapperFunction, IPv4Address, int, float]] = list()
        self.collect_data_path: str = ""

        # Assigned by analyze_data
        self.new_peers: Set[HostServiceAddress] = set()

    @functools.cached_property
    def bs_list_contains_multiple_ports(self) -> bool:
        return len(set(map(lambda x: x[1], self.config.bootstrap_list))) > 1

    @functools.cached_property
    def bs_list_port(self) -> Optional[int]:
        if not self.bs_list_contains_multiple_ports:
            p1 = None
            for _,p2 in self.config.bootstrap_list:
                p1 = p2
                break
            return p1
        return None

    def ignore_ip(self, ip: str) -> bool:
        if ip == "0.0.0.0":
            return True
        elif ip == str(self.config.puppet_vm_ip):
            return True
        elif ip.startswith("127."):
            return True
        elif ip == "255.255.255.255":
            return True
        return False

    def __store_state(self) -> None:
        path = os.path.join(self.config.output_folder, "state.json")
        with open(path, "w") as f:
            res = {
                "replacement_peer": [str(self.replacement_peer[0]), self.replacement_peer[1]],
                "running_snapshot": self.running_snapshot,
                "collect_data_ipc_log": [
                    [x[0].name, str(x[1]), x[2], x[3]]
                    for x in self.collect_data_ipc_log
                ],
                "collect_data_path": self.collect_data_path
            }
            json.dump(res, f)

    def __load_state(self) -> None:
        path = os.path.join(self.config.output_folder, "state.json")
        try:
            with open(path, "r") as f:
                res = json.load(f)
                self.replacement_peer = (IPv4Address(res["replacement_peer"][0]), res["replacement_peer"][1])
                self.running_snapshot = res["running_snapshot"]
                self.collect_data_ipc_log = [
                    (WrapperFunction[x[0]], IPv4Address(x[1]), int(x[2]), x[3])
                    for x in res["collect_data_ipc_log"]
                ]
                self.collect_data_path = res["collect_data_path"]
                self.logger.info("State loaded.")
        except FileNotFoundError:
            self.logger.debug("No state file for loading.")

    def error_handler(self) -> None:
        self.config.vm.stop()
        for revert_function in self.revert_functions:
            revert_function()
        raise RuntimeError("An unexpected error ocurred while puppeteering. All VM's have been stopped.")

    def puppeteer(self, f: AutoPuppeteerPhase=AutoPuppeteerPhase.INFER_BOOTSTRAP_LIST, to: AutoPuppeteerPhase=AutoPuppeteerPhase.CRAWL):
        self.logger.info(f"Automatic Puppeteering! FROM={f.name} TO={to.name}")
        os.makedirs(self.config.output_folder, exist_ok=True)
        self.__load_state()
        try:
            if f <= AutoPuppeteerPhase.INFER_BOOTSTRAP_LIST and AutoPuppeteerPhase.INFER_BOOTSTRAP_LIST <= to:
                if self.config.infer_bootstrap_list:
                    self.infer_bootstrap_list()
                    self.__store_state()
            if f <= AutoPuppeteerPhase.SETUP_PUPPET and AutoPuppeteerPhase.SETUP_PUPPET <= to:
                self.setup_puppet()
                self.__store_state()
            if f <= AutoPuppeteerPhase.COLLECT_DATA and AutoPuppeteerPhase.COLLECT_DATA <= to:
                self.collect_data_path = self.collect_data()
                self.__store_state()
            if f <= AutoPuppeteerPhase.VERIFY_RETURNS and AutoPuppeteerPhase.VERIFY_RETURNS <= to:
                self.verify_returns(self.collect_data_path)
                self.__store_state()
            if f <= AutoPuppeteerPhase.CRAWL and AutoPuppeteerPhase.CRAWL <= to:
                poi_extractors = self.analyze_data(self.collect_data_path)
                self.export_pois(poi_extractors)
                if self.config.crawl_n_times is None:
                    self.crawl(poi_extractors)
                else:
                    self.crawl_n_times(poi_extractors)
                self.__store_state()

        except:
            self.error_handler()

    def infer_bootstrap_list(self):
        self.logger.info(f"(infer_bootstrap_list) Starting VM")
        self.config.vm.start_from(self.config.agent_snapshot)
        
        self.logger.info("(infer_bootstrap_list) Connecting agent")
        agent_connection = AgentConnector(self.config.agent_address)
        self.logger.info("(infer_bootstrap_list) Uploading package")
        agent_connection.upload_package(self.config.analysis_package)
        self.logger.info("(infer_bootstrap_list) Starting packet capture")
        agent_connection.start_dumpcap()
        self.logger.info("(infer_bootstrap_list) Starting sample")
        _run_pintool(agent_connection, self.config)

        ipc_server = agent_connection.get_ipc_server()
        break_flag = False
        ips_ports: List[HostServiceAddress] = []
        ips_last_seen: Dict[str,float] = {}
        ips_first_seen: Dict[str,float] = {}
        mm_interval_length: float = -1
        def check_function() -> bool:
            nonlocal break_flag
            return not break_flag
        def wrapper_callback(pid: int, function: WrapperFunction, ip: IPv4Address, port: int) -> Optional[bool]:
            nonlocal break_flag, mm_interval_length
            if self.ignore_ip(str(ip)):
                pass
            elif str(ip) in ips_last_seen:
                time_since = time.time() - ips_last_seen[str(ip)]
                if time_since > 60:
                    break_flag = True
                    mm_interval_length = time.time() - ips_first_seen[str(ip)]
                ips_last_seen[str(ip)] = time.time()
            else:
                ips_ports.append((_convert__ip(ip), port))
                ips_last_seen[str(ip)] = time.time()
                ips_first_seen[str(ip)] = time.time()
                self.logger.debug(f"(infer_bootstrap_list) New bootstrap peer \"{str(ip)}\" ({len(ips_ports)} total)!")
            return True
        _ipc_server_listen(ipc_server, wrapper_callback, check=check_function)
        self.logger.info(f"(infer_bootstrap_list) Stopping VM")
        self.config.vm.stop()
        self.logger.info(f"(infer_bootstrap_list) Identified {len(ips_ports)} bootstrap peers and an MM-interval length of {mm_interval_length:.2f}s")
        path = os.path.join(self.config.output_folder, "bootstrap_list.txt")
        self.logger.info(f"(infer_bootstrap_list) Writing inferred bootstrap list to \"{path}\"")
        with open(path, "w") as f:
            for ip, port in ips_ports:
                f.write(f"{str(ip)}:{port}\n")
                self.config.bootstrap_list.add((ip, port))

    def setup_puppet(self):
        self.logger.info("(setup_puppet) Starting VM")
        self.config.vm.start_from(self.config.agent_snapshot)
        
        self.logger.info("(setup_puppet) Connecting agent")
        agent_connection = AgentConnector(self.config.agent_address)
        self.logger.info("(setup_puppet) Uploading package")
        agent_connection.upload_package(self.config.analysis_package)
        self.logger.info("(setup_puppet) Starting packet capture")
        agent_connection.start_dumpcap()
        self.logger.info("(setup_puppet) Starting sample")
        _run_pintool(agent_connection, self.config)

        ipc_server = agent_connection.get_ipc_server()
        break_flag = False
        def check_function() -> bool:
            nonlocal break_flag
            return not break_flag
        def wrapper_callback(pid: int, function: WrapperFunction, ip: IPv4Address, port: int) -> Optional[bool]:
            nonlocal break_flag
            self.logger.debug(f"(setup_puppet) IPC Message: {str(ip)}:{str(port)} {{{function.verbose()}}}")
            if function.outgoing() and _convert__ip(ip) in [x[0] for x in self.config.bootstrap_list]:
                self.replacement_peer = (_convert__ip(ip), port)
                break_flag = True
            else: return True
        _ipc_server_listen(ipc_server, wrapper_callback, check=check_function)
        
        self.running_snapshot = self.config.vm.get_random_snapshot_id()
        self.logger.info(f"(setup_puppet) Creating working snapshot {{{self.running_snapshot}}}")
        # close connection before taking the snapshot
        # otherwise reconnecting won't be possible
        agent_connection.close()
        self.config.vm.take_snapshot(self.running_snapshot)
        if self.config.download_setup_output:
            path = os.path.join(self.config.output_folder, "setup_output")
            shutil.rmtree(path, ignore_errors=True)
            self.logger.info(f"(setup_puppet) Downloading output to \"{path}\"")
            agent_connection = AgentConnector(self.config.agent_address)
            agent_connection.download_output(path)
        self.logger.info(f"(setup_puppet) Stopping VM")
        self.config.vm.stop()

    def collect_data_pre_process_dump(self) -> None:
        pass

    def collect_data(self) -> str:
        self.logger.debug(f"(collect_data) Starting VM from running snapshot")
        self.config.vm.start_from(self.running_snapshot)
        self.logger.info("(collect_data) Connecting agent")
        agent_connection = AgentConnector(self.config.agent_address)
 
        ipc_server = agent_connection.get_ipc_server()
        def check_function() -> bool:
            if len(select.select([sys.stdin], [], [], 0)[0]) == 1:
                sys.stdin.readline()
                return False
            return True
        def wrapper_callback(pid: int, function: WrapperFunction, ip: IPv4Address, port: int) -> Optional[bool]:
            self.logger.debug(f"(collect_data) IPC Message: {str(ip)}:{str(port)} {{{function.verbose()}}}")
            self.collect_data_ipc_log.append((
                WrapperFunction(function.value),
                _convert__ip(ip),
                port,
                time.time()
            ))
            return True
        self.logger.info(f"(collect_data) Collecting data for {self.config.data_collection_duration:.2f}s. Press enter to cancel early.")
        _ipc_server_listen(ipc_server, wrapper_callback, timeout=self.config.data_collection_duration, check=check_function)

        self.collect_data_pre_process_dump()

        if self.config.dump_processes:
            self.logger.info("(collect_data) Dumping processes")
            for i in range(10):
                self.logger.debug(f"(collect_data) Trying {i}...")
                success = agent_connection.dump_processes()
                if success:
                    self.logger.debug("(collect_data) Dumping successful!")
                    break
                if not success:
                    self.logger.info("(collect_data) Process dumping failes 10 times. Not retrying...")

        path = os.path.join(self.config.output_folder, "collected_data")
        shutil.rmtree(path, ignore_errors=True)
        self.logger.info(f"(collect_data) Downloading output to \"{path}\"")
        agent_connection.download_output(path)
   
        self.logger.info(f"(collect_data) Stopping VM")
        self.config.vm.stop()

        if self.config.peer_crawl_timeout is None:
            ip_times: Dict[IPv4Address, List[float]] = {}
            for _,ip,_,t in self.collect_data_ipc_log:
                if ip == self.config.puppet_vm_ip or str(ip) == "0.0.0.0": continue
                if ip not in ip_times:
                    ip_times[ip] = []
                ip_times[ip].append(t)
            ip_deltas: List[float] = []
            for ip,times in ip_times.items():
                for i in range(0, len(times) - 1):
                    delta = times[i+1] - times[i]
                    if delta <= 60: ip_deltas.append(delta)
            a = 0 if len(ip_deltas) == 0 else max(ip_deltas)
            self.config.peer_crawl_timeout = max(a*self.config.peer_crawl_safety_factor, 5)
            self.logger.info(f"(collect_data) Identified the peer_crawl_timeout (only relevant for UDP): {self.config.peer_crawl_timeout}. Please store the value in the configuration.")
                

        return path

    def verify_returns(self, data_path: str) -> None:
        self.logger.info("(verify_returns) Loading Files")
        proc_pool = multiprocessing.Pool(self.config.parallel_cores)
        trace_files = list(glob.glob(os.path.join(data_path, "trace.*")))
        return_addresses = proc_pool.map(_get_socket_instructions, trace_files)
        proc_pool.close()

        ins_log = load_ins_log(data_path)
        uninstrumented_returns = set()
        total = 0
        i = 0
        for pid,addrs in return_addresses:
            for addr in addrs:
                total += 1
                if addr in ins_log[pid]:
                    i += 1
                else:
                    uninstrumented_returns.add(addr)
        self.logger.info(f"(verify_returns) {i}/{total} returns were traced.")
        if i == 0:
            self.logger.error(f"(verify_returns) Please check the trace filter settings.")

    def analyze_data(self, data_path: str) -> List[PoiExtractor]:
        self.logger.debug("(analyze_data) Identifying new peers")
        bootstrap_ips = set(map(lambda x: x[0], self.config.bootstrap_list))
        for _,ip,port,_ in self.collect_data_ipc_log:
            if not self.ignore_ip(str(ip)) and ip not in bootstrap_ips:
                self.new_peers.add((ip, port))
        self.logger.info(f"(analyze_data) Identified {len(self.new_peers)} new peers")
        for ip,port in self.new_peers:
            self.logger.debug (f"(analyze_data) ~ {ip}:{port}")

        res = []
        if self.config.poi_extractor_naive:
            res.append(NaivePoiExtractor(self, data_path, self.config.parallel_cores))
        if self.config.poi_extractor_memory_pattern:
            res.append(MemoryPatternPoiExtractor(self, data_path, self.config.parallel_cores))

        return res

    def export_pois(self, poi_extractors: List[PoiExtractor]) -> None:
        all_pois: Iterable[Poi] = []
        for extractor in poi_extractors:
            all_pois = itertools.chain(all_pois, extractor.get_pois())
        resulting_list: List[Dict] = list(map(
            lambda x: dataclasses.asdict(x),
            all_pois
        ))
        path = os.path.join(self.config.output_folder, "pois.json")
        with open(path, "w") as f:
            self.logger.info(f"(export_pois) Writing {len(resulting_list)} POIs to {path}.")
            json.dump(resulting_list, f, indent=4)

    def __crawl_peer(self, peer: HostServiceAddress, poi_extractors: List[PoiExtractor]) -> Dict[HostServiceAddress, Dict[str,List[Poi]]]:
        self.logger.info(f"(crawl_peer) Crawling peer {peer[0]}:{peer[1]}")
        self.logger.info(f"(crawl_peer) Setting up router")
        orig_port = None
        new_port = None
        if self.bs_list_contains_multiple_ports:
            orig_port = self.replacement_peer[1]
            new_port = peer[1]
            self.logger.info(f"(crawl_peer) + port redirects {orig_port}->{new_port}")
        revert_map = self.config.router.one_to_one_map(
            self.config.puppet_vm_ip,
            self.replacement_peer[0],
            peer[0],
            orig_port=orig_port,
            new_port=new_port
        )
        revert_block = self.config.router.block(
            self.config.puppet_vm_ip,
            peer[0],
            self.config.agent_address[1]
        )
        self.revert_functions.append(revert_map)
        self.revert_functions.append(revert_block)

        self.logger.debug(f"(crawl_peer) Starting VM from running snapshot")
        self.config.vm.start_from(self.running_snapshot)
        self.logger.info("(crawl_peer) Connecting agent")
        agent_connection = AgentConnector(self.config.agent_address)

        ipc_server = agent_connection.get_ipc_server()
        last_time: float = 0
        resulting_peers: Dict[HostServiceAddress,Dict[str,List[Poi]]] = dict()
        def check_function() -> bool:
            nonlocal last_time
            t = time.time()
            return (t - last_time < self.config.peer_crawl_timeout)
        def wrapper_callback(pid: int, function: WrapperFunction, ip: IPv4Address, port: int) -> Optional[bool]:
            nonlocal last_time
            if str(self.replacement_peer[0]) == str(ip):
                last_time = time.time()
            # if not self.ignore_ip(str(ip)) and self.config.learn_ipc_peers:
            #     peer = (_convert__ip(ip), port)
            #     if peer not in resulting_peers:
            #         resulting_peers[peer] = set()
            #     resulting_peers[peer].add("Ipc")
            return True
        self.logger.info(f"(crawl_peer) Crawling")
        _ipc_server_listen(ipc_server, wrapper_callback, timeout=self.config.peer_crawl_timeout_hard, check=check_function)
        
        path = os.path.join(self.config.output_folder, "tmp_data")
        shutil.rmtree(path, ignore_errors=True)
        self.logger.info(f"(crawl_peer) Downloading output to \"{path}\"")
        agent_connection.download_output(path)
   
        self.logger.info(f"(crawl_peer) Stopping VM")
        self.config.vm.stop()

        self.logger.info(f"(crawl_peer) Reverting router")
        revert_map()
        revert_block()
        self.revert_functions = list()
        for poi_extractor in poi_extractors:
            self.logger.info(f"(crawl_peer) Running POI Extractor: {poi_extractor.NAME}")
            extracted_peers = poi_extractor.extract_ips(path)
            for peer,pois in extracted_peers.items():
                resulting_peers.setdefault(peer, {})
                resulting_peers[peer][poi_extractor.NAME] = pois

        return resulting_peers

    def write_results(self, crawl_results: Dict) -> None:
        path = os.path.join(self.config.output_folder, f"results_{str(self.result_counter)}.json")
        self.result_counter += 1
        with open(path, "w") as f:
            json.dump(crawl_results, f, indent=4)
            self.logger.info(f"(write_results) Results written to {path}.")

    def crawl_n_times(self, poi_extractors: List[PoiExtractor]) -> None:
        assert(self.config.crawl_n_times_list is not None)
        peers_to_query = self.config.crawl_n_times_list
        assert(len(peers_to_query) != 0)
        while len(peers_to_query) < self.config.crawl_n_times:
            peers_to_query += peers_to_query
        random.shuffle(peers_to_query)
        crawl_counter = 0
        for crawl_counter in range(self.config.crawl_n_times):
            self.logger.info(f"(crawl_n_times) Crawl counter: {crawl_counter}")
            current_peer = peers_to_query.pop(0)
            new_peers_raw = self.__crawl_peer(current_peer, poi_extractors)
            new_peers: Dict[HostServiceAddress, Dict[str,List[Poi]]] = dict()
            self.logger.info(f"(crawl_n_times) Extracted {len(new_peers_raw)} peers")
            for peer,srces in new_peers_raw.items():
                if self.config.crawl_ignore_bs \
                    and peer not in self.config.crawl_ignore_bs_exceptions \
                    and peer in self.config.bootstrap_list:
                    continue
                self.logger.debug(f"(crawl_n_times) ~ {peer[0]}:{peer[1]} | {', '.join(srces)}")
                new_peers[peer] = srces

            self.write_results({
                "crawl_counter": crawl_counter,
                "crawl_peer": host_address_to_str(current_peer),
                "new_peers_raw": {
                    host_address_to_str(k): {
                        k2: [dataclasses.asdict(x) for x in v2]
                        for k2,v2 in v.items()
                    }
                    for k,v in new_peers_raw.items()
                },
                # "new_peers": {
                #     host_address_to_str(k): {
                #         k2: [dataclasses.asdict(x) for x in v2]
                #         for k2,v2 in v.items()
                #     }
                #     for k,v in new_peers.items()
                # }
            })

        self.logger.info(f"(crawl_n_times) Done crawling n-times.")

    def crawl(self, poi_extractors: List[PoiExtractor]) -> None:
        known_peers: Dict[HostServiceAddress, Tuple[Set[str], int]] = {self.config.initial_peer: (set(), 0)}
        queried_peers: Set[HostServiceAddress] = set()
        peers_to_query: List[HostServiceAddress] = [self.config.initial_peer]
        mandatory_retry_count = self.config.mandatory_retry_count
        crawl_counter = 0
        while len(peers_to_query) != 0 or mandatory_retry_count > 0:
            self.logger.info(f"(crawl) Crawl counter: {crawl_counter}")
            if len(peers_to_query) == 0:
                queried_peers = set()
                peers_to_query = list(known_peers)
                mandatory_retry_count -= 1
                self.logger.info(f"(crawl) Mandatory retry count: {mandatory_retry_count}")
            current_peer = peers_to_query.pop(0)
            known_peers[current_peer] = (known_peers[current_peer][0], known_peers[current_peer][1]+1)
            queried_peers.add(current_peer)
            new_peers_raw = self.__crawl_peer(current_peer, poi_extractors)
            new_peers: Dict[HostServiceAddress, Dict[str,List[Poi]]] = dict()
            new_peers_used: Dict[HostServiceAddress, Dict[str,List[Poi]]] = dict()
            self.logger.info(f"(crawl) Extracted {len(new_peers_raw)} peers")
            for peer,srces in new_peers_raw.items():
                if self.config.crawl_ignore_bs \
                    and peer not in self.config.crawl_ignore_bs_exceptions \
                    and peer in self.config.bootstrap_list:
                    continue
                self.logger.debug(f"(crawl) ~ {peer[0]}:{peer[1]} | {', '.join(srces)}")
                new_peers[peer] = srces
                if peer not in queried_peers and peer not in peers_to_query:
                    peers_to_query.append(peer)
                    new_peers_used[peer] = srces
                    self.logger.debug("(crawl)   added to crawl queue")
                if peer not in known_peers:
                    known_peers[peer] = (set(), 0)
                known_peers[peer] = (known_peers[peer][0] | set(srces.keys()), known_peers[peer][1])

            self.write_results({
                "crawl_counter": crawl_counter,
                "mandatory_retry_count": mandatory_retry_count,
                "crawl_peer": host_address_to_str(current_peer),
                "known_peers": {
                    host_address_to_str(k): {
                        "sources:": list(v[0]),
                        "crawled": v[1],
                    }
                    for k,v in known_peers.items()
                },
                "new_peers_raw": {
                    host_address_to_str(k): {
                        k2: [dataclasses.asdict(x) for x in v2]
                        for k2,v2 in v.items()
                    }
                    for k,v in new_peers_raw.items()
                },
                "new_peers": {
                    host_address_to_str(k): {
                        k2: [dataclasses.asdict(x) for x in v2]
                        for k2,v2 in v.items()
                    }
                    for k,v in new_peers.items()
                },
                "new_peers_used": {
                    host_address_to_str(k): {
                        k2: [dataclasses.asdict(x) for x in v2]
                        for k2,v2 in v.items()
                    }
                    for k,v in new_peers_used.items()
                }
            })

            crawl_counter += 1
        self.logger.info(f"(crawl) Done crawling. Total known peers:")
        for (ip,port),(srces,counter) in known_peers.items():
            self.logger.info(f"(crawl) ~ {ip}:{port} | {', '.join(srces)} | Crawled {counter} times")