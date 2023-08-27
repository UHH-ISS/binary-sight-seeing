import ipaddress
import logging
import logging.config
import argparse
import configparser
import os
import json
from puppeteering.types import *
import time

from puppeteering.vm import ProxmoxVM, VirtualMachine
from puppeteering.router import SshIptablesRouter
from puppeteering.auto_puppeteer import AutoPuppeteer, AutoPuppeteerConfig, AutoPuppeteerPhase
from puppeteering.util import parse_bootstrap_list_file

def parse_config(config: configparser.ConfigParser, args: argparse.Namespace, connect: bool = True):
    if connect:
        vm = ProxmoxVM(
            config["puppet_vm"].get("host"),
            config["puppet_vm"].get("username"),
            config["puppet_vm"].get("password"),
            config["puppet_vm"].get("node"),
            config["puppet_vm"].getint("vmid"),
            name="puppet_vm"
        )

        router = SshIptablesRouter(
            config["router"].get("host"),
            config["router"].get("user"),
            config["router"].get("password"),
            port=config["router"].getint("port", 22)
        )
    else:
        vm = None
        router = None

    agent_address = (
        ipaddress.IPv4Address(config["agent"].get("host")),
        config["agent"].getint("port", 12345),
    )

    trace_images = config["general"].get("trace_images")
    if trace_images is not None:
        trace_images = json.loads(trace_images)

    bootstrap_list = set()
    path = os.path.join(args.analysis_package, "bootstrap_list.txt")
    if os.path.isfile(path):
        bootstrap_list = parse_bootstrap_list_file(path)

    initial_peer = config["general"].get("initial_peer")
    initial_peer_split = initial_peer.split(":")

    crawl_ignore_bs_exceptions_str: str = config["general"].get("crawl_ignore_bs_exceptions")
    crawl_ignore_bs_exceptions: Set[HostServiceAddress] = set()
    if crawl_ignore_bs_exceptions_str is not None:
        crawl_ignore_bs_exceptions_json = json.loads(crawl_ignore_bs_exceptions_str)
        for a in crawl_ignore_bs_exceptions_json:
            crawl_ignore_bs_exceptions.add((
                ipaddress.IPv4Address(a[0]),
                int(a[1])
            ))

    return AutoPuppeteerConfig(
        vm=vm, # type: ignore
        agent_snapshot=config["puppet_vm"].get("agent_snapshot"),
        agent_address=agent_address,
        router=router, # type: ignore
        analysis_package=args.analysis_package,
        output_folder=args.output_folder,
        infer_bootstrap_list=config["general"].getboolean("infer_bootstrap_list", False),
        create_text_log=config["general"].getboolean("create_text_log", False),
        trace_images=trace_images,
        trace_non_image=config["general"].getboolean("trace_non_image", False),
        max_trace_count=config["general"].getint("max_trace_count", 0),
        download_setup_output=config["general"].getboolean("download_setup_output", False),
        puppet_vm_ip=ipaddress.IPv4Address(config["general"].get("puppet_vm_ip")),
        bootstrap_list=bootstrap_list,
        data_collection_duration=config["general"].getint("data_collection_duration"),
        dump_processes=config["general"].getboolean("dump_processes", False),
        confidence_score_threshold=config["general"].getfloat("confidence_score_threshold"),
        initial_peer=(ipaddress.IPv4Address(initial_peer_split[0]), int(initial_peer_split[1])),
        mandatory_retry_count=config["general"].getint("mandatory_retry_count"),
        crawl_n_times=config["general"].getint("crawl_n_times"),
        crawl_n_times_list=None, # this needs to be set manually
        peer_crawl_timeout=config["general"].getfloat("peer_crawl_timeout"),
        peer_crawl_timeout_hard=config["general"].getint("peer_crawl_timeout_hard"),
        peer_crawl_safety_factor=config["general"].getfloat("peer_crawl_safety_factor", 1.5),
        random_mouse=config["general"].getboolean("random_mouse", False),
        learn_ipc_peers=config["general"].getboolean("learn_ipc_peers", False),
        crawl_ignore_bs=config["general"].getboolean("crawl_ignore_bs", False),
        crawl_ignore_bs_exceptions=crawl_ignore_bs_exceptions,
        trace_split_limit=config["general"].getint("trace_split_limit", 0),
        parallel_cores=config["general"].getint("parallel_cores", 12),
        poi_extractor_naive=config["general"].getboolean("poi_extractor_naive", False),
        poi_extractor_memory_pattern=config["general"].getboolean("poi_extractor_memory_pattern", False),
    )

class LocalBotnetAutoPuppeteer(AutoPuppeteer):
    def __init__(self, config: AutoPuppeteerConfig, vms: List[int], running_snapshot: str, lb_ips_file: Optional[str],
                lb_host: str, lb_node: str, lb_user: str, lb_password: str):
        if lb_ips_file is not None:
            crawl_n_times_set = list(parse_bootstrap_list_file(lb_ips_file))
            config.crawl_n_times_list = list(crawl_n_times_set)
        super().__init__(config)
        self.vms = vms
        self.lb_snapshot = running_snapshot
        self.lb_host = lb_host
        self.lb_node = lb_node
        self.lb_user = lb_user
        self.lb_password = lb_password
        self.local_botnet_running = False

    def __get_vm(self, vmid: int, i: int) -> VirtualMachine:
        return ProxmoxVM(
            self.lb_host,
            self.lb_user,
            self.lb_password,
            self.lb_node,
            vmid,
            name=f"bot-{i}"
        )

    def __start_vms(self) -> None:
        self.local_botnet_running = True
        self.logger.info("Starting local botnet")
        for i,vm in enumerate(self.vms):
            self.__get_vm(vm, i).start_from(self.lb_snapshot)

    def __stop_vms(self) -> None:
        self.logger.info("Stopping local botnet")
        for i,vm in enumerate(self.vms):
            time.sleep(0.1)
            self.__get_vm(vm, i).stop()
        self.local_botnet_running = False

    def error_handler(self) -> None:
        if self.local_botnet_running:
            self.__stop_vms()
        return super().error_handler()

    def collect_data_pre_process_dump(self) -> None:
        self.__stop_vms()
        return super().collect_data_pre_process_dump()

    def collect_data(self) -> str:
        self.__start_vms()
        retval = super().collect_data()
        return retval
    
    def crawl(self, poi_extractors) -> None:
        self.__start_vms()
        super().crawl(poi_extractors)
        self.__stop_vms()
    
    def crawl_n_times(self, poi_extractors) -> None:
        self.__start_vms()
        super().crawl_n_times(poi_extractors)
        self.__stop_vms()

if __name__ == "__main__":
    logging.config.fileConfig("auto_puppeteer_logging.conf")
    logger = logging.getLogger(__name__)

    parser = argparse.ArgumentParser(description="""
        Automatically run a puppeteering package on a puppet VM.
    """)
    parser.add_argument("config", help="The config file used for auto puppeteering.")
    parser.add_argument("analysis_package", help="The folder containing the analysis package for analysis. A package.ini file in the package folder can be used to overwrite the main configuration file.")
    parser.add_argument("output_folder", help="The folder where the results will be written to.")
    parser.add_argument("--f", help="The phase of auto puppeteering to start from [*INFER_BOOTSTRAP_LIST*, SETUP_PUPPET, COLLECT_DATA, CRAWL].", default="INFER_BOOTSTRAP_LIST")
    parser.add_argument("--to", help="The phase of auto puppeteering to stop at [INFER_BOOTSTRAP_LIST, SETUP_PUPPET, COLLECT_DATA, *CRAWL*].", default="CRAWL")
    parser.add_argument("--local_botnet", help="The local botnet to start.")
    args = parser.parse_args()

    config = configparser.ConfigParser()
    config.read([args.config, os.path.join(args.analysis_package, "package.ini")])

    config_class = parse_config(config, args)

    logger.debug(repr(config_class))
    if args.local_botnet:
        botnet_vms_string = config["local_botnets"].get(args.local_botnet)
        botnet_vms_int = list()
        for a in botnet_vms_string.split(","):
            a_split = a.split("-")
            if len(a_split) == 1:
                botnet_vms_int.append(int(a))
            for b in range(int(a_split[0]), int(a_split[1])+1):
                botnet_vms_int.append(b)
        running_snapshot = config["local_botnets"].get(args.local_botnet + "_running")
        lb_ips_file = os.path.join(
            os.path.dirname(args.config),
            config["local_botnets"].get(args.local_botnet + "_ips")
        )
        ap = LocalBotnetAutoPuppeteer(
            config_class, botnet_vms_int, running_snapshot, lb_ips_file,
            config["puppet_vm"].get("host"),
            config["puppet_vm"].get("node"),
            config["puppet_vm"].get("username"),
            config["puppet_vm"].get("password")
        )
    else:
        ap = AutoPuppeteer(config_class)
    ap.puppeteer(f=AutoPuppeteerPhase[args.f], to=AutoPuppeteerPhase[args.to])