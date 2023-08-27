import argparse
import os
import json
import time
import configparser
import subprocess

from numpy import average
from agent import WrapperFunction
import auto_puppeteer
import logging, logging.config
try:    
    import numpy as np
    import seaborn as sns
    import matplotlib.pyplot as plt
    import matplotlib.lines as lines
    import matplotlib.ticker as ticker
    import pandas as pd
except ModuleNotFoundError:
    pass
from math import ceil
from puppeteering.auto_puppeteer import AutoPuppeteerPhase, _run_pintool, _ipc_server_listen
from puppeteering.agent_connector import AgentConnector
from puppeteering.types import *
from puppeteering.poi.base import Poi
from puppeteering.util import host_address_to_str, parse_bootstrap_list_file

MAIN_PATH = os.path.dirname(os.path.abspath(__file__))
MAIN_CONFIG_FILE = os.path.join(MAIN_PATH, "auto_puppeteer.ini")
ANALYSIS_PACKAGE_DIR = os.path.join("..", "analysis-packages")

DELAY_NATIVE_SNAPSHOT = "AgentRunningNoPin"

BOTNETS = {
    "SALITY": {
        "name": "Sality",
        "analysis_package": os.path.join(ANALYSIS_PACKAGE_DIR, "sality"),
        "local_botnet": "sality_large",
        "delay_measure_time": (10*60, 17*60),
        "filter": "udp && !dns && !ssdp && !dhcpv6 && ip.src == 99.99.0.99 && !icmp && !(udp.port == 3702)",
    },
    "ZEROACCESS": {
        "name": "ZeroAccess",
        "analysis_package": os.path.join(ANALYSIS_PACKAGE_DIR, "zeroaccess"),
        "local_botnet": "zeroaccess_large",
        "delay_measure_time": (10*60, 10*60),
        "filter": "udp.port == 16471 && !icmp",
        "break": (40, 110, 128),
        "height_ratio": [1, 1],
    },
    "NUGACHE": {
        "name": "Nugache",
        "analysis_package": os.path.join(ANALYSIS_PACKAGE_DIR, "nugache"),
        "local_botnet": "nugache_large",
        "delay_measure_time": (60*60, 60*60),
        "filter": "tcp.port == 8 && !tcp.analysis.retransmission && !icmp",
    },
    "KELIHOS": {
        "name": "Kelihos",
        "analysis_package": os.path.join(ANALYSIS_PACKAGE_DIR, "kelihos"),
        "local_botnet": "kelihos_large",
        "delay_measure_time": (20*60, 20*60),
        "filter": "tcp.port == 80 && !(tcp.analysis.retransmission) && !icmp",
        "break": (9, 17, 20),
        "height_ratio": [1, 1],
    }
}

def log_with_box(logger, msg: str, before: int=2, after: int=2) -> None:
    for _ in range(before):
        logger.info('#'*len(msg))
    logger.info(msg)
    for _ in range(after):
        logger.info('#'*len(msg))


def run_botnet(output_folder: str, mode: str, analysis_package: str, local_botnet: str):
    config = configparser.ConfigParser()
    config.read([MAIN_CONFIG_FILE, os.path.join(analysis_package, "package.ini")])

    args = argparse.Namespace(
        analysis_package=analysis_package,
        output_folder=output_folder
    )
    config_class = auto_puppeteer.parse_config(config, args)

    f = AutoPuppeteerPhase.SETUP_PUPPET
    t = AutoPuppeteerPhase.CRAWL

    if mode == "pois1":
        config_class.crawl_n_times = 0
        config_class.confidence_score_threshold = -1.0
        t = AutoPuppeteerPhase.VERIFY_RETURNS
    elif mode == "pois2":
        config_class.crawl_n_times = 0
        config_class.confidence_score_threshold = -1.0
        f = AutoPuppeteerPhase.CRAWL
        local_botnet = "dummy"
    elif mode == "crawling":
        config_class.dump_processes = False
        config_class.poi_extractor_memory_pattern = False
    else: raise RuntimeError("Unknown mode.")

    botnet_vms_string = config["local_botnets"].get(local_botnet)
    botnet_vms_int = list()
    for a in botnet_vms_string.split(","):
        a_split = a.split("-")
        if len(a_split) == 1:
            botnet_vms_int.append(int(a))
        for b in range(int(a_split[0]), int(a_split[1])+1):
            botnet_vms_int.append(b)
    running_snapshot = config["local_botnets"].get(local_botnet + "_running")
    lb_ips_file = os.path.join(
        os.path.dirname(MAIN_CONFIG_FILE),
        config["local_botnets"].get(local_botnet + "_ips")
    )
    ap = auto_puppeteer.LocalBotnetAutoPuppeteer(
        config_class, botnet_vms_int, running_snapshot, lb_ips_file,
        config["puppet_vm"].get("host"),
        config["puppet_vm"].get("node"),
        config["puppet_vm"].get("username"),
        config["puppet_vm"].get("password")
    )
    try:
        ap.puppeteer(f=f, to=t)
    except RuntimeError as err:
        logger.error(f"Error while auto puppeteering...")
        raise

def collect_data1(botnet: str, args: argparse.Namespace):
    logger = logging.getLogger("evaluation.collect_data")
    config = BOTNETS[botnet]
    analysis_package = os.path.join(MAIN_PATH, config["analysis_package"])
    output_folder_base = os.path.join(args.working_dir, botnet, "collect_data")
    local_botnet = config["local_botnet"]

    if args.do_pois:
        log_with_box(logger, f"##### Doing first POI run #####", before=1, after=1)
        run_botnet(os.path.join(output_folder_base, "pois"), "pois1", analysis_package, local_botnet)

    if args.do_crawling:
        log_with_box(logger, f"##### Doing crawling run #####", before=1, after=1)
        run_botnet(os.path.join(output_folder_base, f"crawling"), "crawling", analysis_package, local_botnet)

def collect_data2(botnet: str, args: argparse.Namespace):
    logger = logging.getLogger("evaluation.collect_data")
    config = BOTNETS[botnet]
    analysis_package = os.path.join(MAIN_PATH, config["analysis_package"])
    output_folder_base = os.path.join(args.working_dir, botnet, "collect_data")
    local_botnet = config["local_botnet"]

    log_with_box(logger, f"##### Doing second POI run #####", before=1, after=1)
    run_botnet(os.path.join(output_folder_base, "pois"), "pois2", analysis_package, local_botnet)

def poi_to_group(poi):
    if poi["poi_type"] == "PORT":
        return "PORT"
    if poi['extractor'] == "NaivePoiExtractor":
        split_details = poi['details'].split(";")
        if split_details[0].startswith("REG"):
            group = "Register (Standalone)"
            # group = split_details[0].replace("_", "-")
        elif "MEM" in split_details[0]:
            group = "Memory (Standalone)"
        # elif split_details[0] == "MEM_R":
        #     group = "Memory Read"
        # elif split_details[0] == "MEM_W":
        #     group = "Memory Write"
        else: assert(False)
    elif poi['extractor'] == "MemoryPatternPoiExtractor":
        group = "Memory (Contiguous)"
        # if "POI operation:w" in poi["details"]:
        #     group = "Pattern Write"
        # elif "POI operation:r" in poi["details"]:
        #     group = "Pattern Read"
        # else:
        #     raise RuntimeError(poi)
    else: assert(False)
    return group

def get_confidence_class(confidence_score):
    if confidence_score is None:
        return -2
    for i in range(0, 10):
        if i/10 <= confidence_score <= (i+1)/10:
            return i
    return -1

def load_pois(botnet: str, args: argparse.Namespace):
    pois_file = os.path.join(args.working_dir, botnet, "collect_data", "pois", "pois.json")
    with open(pois_file, 'r') as f:
        pois = json.load(f)
    for poi in pois:
        poi["Botnet"] = BOTNETS[botnet]["name"]
        poi["Type"] = poi_to_group(poi)
        poi["Confidence Class"] = get_confidence_class(poi["confidence_score"])
        poi["Number of POIs"] = 1
    return pois

def load_results(botnet: str, i: int, args: argparse.Namespace):
    results_file = os.path.join(args.working_dir, botnet, "collect_data", "crawling", f"results_{i}.json")
    with open(results_file, 'r') as f:
        results = json.load(f)
    return results

def load_poi_to_extracted_ips(botnet: str, args: argparse.Namespace):
    pass

def get_botnet_peers(botnet: str) -> Set[str]:
    config = BOTNETS[botnet]
    analysis_package = os.path.join(MAIN_PATH, config["analysis_package"])
    local_botnet = config["local_botnet"]

    config = configparser.ConfigParser()
    config.read([MAIN_CONFIG_FILE, os.path.join(analysis_package, "package.ini")])
    config_args = argparse.Namespace(
        analysis_package=analysis_package,
        output_folder=""
    )
    config_class = auto_puppeteer.parse_config(config, config_args, connect=False)
    
    botnet_peers_file = os.path.join(os.path.dirname(MAIN_CONFIG_FILE), config["local_botnets"].get(f"{local_botnet}_ips"))
    botnet_peers = set(map(host_address_to_str, parse_bootstrap_list_file(botnet_peers_file))) \
                | set(map(host_address_to_str, config_class.crawl_ignore_bs_exceptions))
    
    return botnet_peers

def get_bootstrap_list(botnet: str) -> Set[str]:
    config = BOTNETS[botnet]
    analysis_package = os.path.join(MAIN_PATH, config["analysis_package"])

    config = configparser.ConfigParser()
    config.read([MAIN_CONFIG_FILE, os.path.join(analysis_package, "package.ini")])
    config_args = argparse.Namespace(
        analysis_package=analysis_package,
        output_folder=""
    )
    config_class = auto_puppeteer.parse_config(config, config_args, connect=False)
    bootstrap_list = set(map(host_address_to_str, config_class.bootstrap_list))
    return bootstrap_list

def iter_results(botnet: str, args: argparse.Namespace) -> Generator[Dict, None, None]:
    for i in range(0, 100):
        yield load_results(botnet, i, args)

def load_all_results(botnet: str, args: argparse.Namespace) -> List[Dict]:
    return list(iter_results(botnet, args))

def graph_data1(logger, botnets: List[str], args: argparse.Namespace):
    log_with_box(logger, "graph_data1", before=1, after=1)
    ######### xy plot of POI confidence score and extraction quality
    resulting_data = []
    for botnet in botnets:
        bootstrap_list = get_bootstrap_list(botnet)
        botnet_peers = get_botnet_peers(botnet)

        poi_data: Dict[str, Dict] = dict()

        for res in iter_results(botnet, args):
            for ip,extractors in res["new_peers_raw"].items():
                for _,pois in extractors.items():
                    for poi in pois:
                        poi_string = poi["poi_type"] + ";" + str(poi["address"]) + ";" + poi["extractor"] + ";" + poi["details"] + ";" + str(poi["confidence_score"])
                        poi_data.setdefault(poi_string, {
                            "Confidence Score": poi["confidence_score"],
                            "Botnet": BOTNETS[botnet]["name"],
                            "ips": set(),
                            "Number of POIs": 1
                        })["ips"].add(ip)
        total_pois = 0
        overestimated_pois = 0
        for poi_string,data in poi_data.items():
            correct_ips = data["ips"] & (bootstrap_list | botnet_peers)
            data["Correctness"] = len(correct_ips) / len(data["ips"])
            resulting_data.append(data)
            total_pois += 1
            if data["Correctness"] < data["Confidence Score"]:
                overestimated_pois += 1
        logger.info(f"[{botnet}] Total POIs: {total_pois} Overestimated POIs: {overestimated_pois}")

    agg_funcs = {"Number of POIs": "sum"}
    df = pd.DataFrame(resulting_data)
    df = df.groupby(["Confidence Score", "Correctness", "Botnet"]).aggregate(agg_funcs).sort_values("Botnet", ascending=False)

    df = df.sort_values("Botnet", ascending=False)
    facet_grid = sns.relplot(x="Confidence Score", y="Correctness", hue="Botnet", style="Botnet", size="Number of POIs", sizes=(50,200), data=df, alpha=0.6, clip_on=False)

    facet_grid.fig.set_size_inches(4.5, 4.5)
    ax = facet_grid.axes[0,0]
    line = lines.Line2D([0, 1], [0, 1], lw=1, color="red", ls="--")
    ax.add_line(line)
    line = lines.Line2D([0.8, 0.8], [0, 2], lw=1, color="green", ls=":")
    ax.add_line(line)
    ax.set_xlim(left=0, right=1.05)
    ax.set_ylim(bottom=0, top=1.05)
    h,l = ax.get_legend_handles_labels()
    lgd = facet_grid.fig.legend(h[1:len(botnets)+1], l[1:len(botnets)+1], loc=10, ncol=10, bbox_to_anchor=(0.50, 0), frameon=True, columnspacing=0.3)
    facet_grid.legend.remove()
    plt.tight_layout()

    
    dest_file = os.path.join(args.working_dir, "graph", "poi_correctness.pdf")
    try:
        os.makedirs(os.path.dirname(dest_file))
    except FileExistsError:
        pass
    plt.savefig(dest_file, bbox_extra_artists=(lgd,), bbox_inches="tight")

def graph_data2(logger, botnets: List[str], args: argparse.Namespace):
    plt.rcParams.update({'font.size': 14})
    log_with_box(logger, "graph_data2", before=1, after=1)
    last_flag = False
    for botnet in botnets + ["LAST"]:
        if botnet == "LAST":
            last_flag = True
            botnet = "ZEROACCESS"
        pois = load_pois(botnet, args)

        # pois = list(filter(lambda x: x["confidence_score"] is not None, pois))
        ip_pois = list(filter(lambda x: x["poi_type"] == "IP", pois))

        # see: https://gist.github.com/pfandzelter/0ae861f0dee1fb4fd1d11344e3f85c9e
        if "break" in BOTNETS[botnet]:
            begin,end,end2 = BOTNETS[botnet]["break"]
            top = 1
            bottom = begin/(end2-end)
            f, (ax1, ax2) = plt.subplots(ncols=1, nrows=2, sharex=True, figsize=(4.2, 4.2), gridspec_kw={'height_ratios': [top, bottom]})
        else:
            f, (ax1) = plt.subplots(ncols=1, nrows=1, sharex=True, figsize=(4.2, 4.2))

        for i in range(10):
            for t in ["Register", "Memory", "Pattern"]:
                ip_pois.append({
                    "Type": t,
                    "Confidence Class": i,
                    "Botnet": BOTNETS[botnet]["name"],
                    "Number of POIs": 0
                })
        df = pd.DataFrame(data=ip_pois).sort_values("Botnet", ascending=False)
        agg_funcs = {"Number of POIs": "sum"}
        df = df.groupby(["Type", "Confidence Class", "Botnet"]).aggregate(agg_funcs)
        df.reset_index(inplace=True)

        ax1 = sns.barplot(x="Confidence Class", y="Number of POIs", hue="Type", hue_order=["Register (Standalone)", "Memory (Standalone)", "Memory (Contiguous)"], data=df, ax=ax1)
        if "break" in BOTNETS[botnet]:
            ax2 = sns.barplot(x="Confidence Class", y="Number of POIs", hue="Type", hue_order=["Register (Standalone)", "Memory (Standalone)", "Memory (Contiguous)"], data=df, ax=ax2)

        if "break" in BOTNETS[botnet]:
            begin,end,end2 = BOTNETS[botnet]["break"]
            ax1.get_legend().remove()
            ax2.get_legend().remove()
            ax1.get_xaxis().set_visible(False)
            ax1.set_ylim(bottom=end, top=end2)
            ax2.set_ylim(0, top=begin)
            ax1.set_ylabel(" ")
            ax2.set_ylabel("")

            f.text(0.03, 0.55, "Number of POIs", va="center", rotation="vertical")

            d = .01  # how big to make the diagonal lines in axes coordinates
            # arguments to pass to plot, just so we don't keep repeating them
            kwargs = dict(transform=ax1.transAxes, color='k', clip_on=False)
            ax1.plot((-d, +d), (-d, +d), **kwargs)        # top-left diagonal
            ax1.plot((1 - d, 1 + d), (-d, +d), **kwargs)  # top-right diagonal

            kwargs.update(transform=ax2.transAxes)  # switch to the bottom axes
            ax2.plot((-d, +d), (1 - d, 1 + d), **kwargs)  # bottom-left diagonal
            ax2.plot((1 - d, 1 + d), (1 - d, 1 + d), **kwargs)  # bottom-right diagonal
            # ax1.get_legend().remove()
            # ax2.get_legend().remove()
            if ax2.get_legend() is not None:
                ax2.get_legend().remove()
        if ax1.get_legend() is not None:
            ax1.get_legend().remove()

        # fd = sns.catplot(x="Confidence Class", y="Number of POIs", hue="Type", col="Botnet", kind="bar", data=df, legend=False, sharey=False, hue_order=["Register", "Memory", "Pattern"])
        # fd.fig.set_size_inches(13, 3.5)
        # handles = fd._legend_data.values()
        # labels = fd._legend_data.keys()

        if last_flag:
            if "break" in BOTNETS[botnet]:
                lgd = ax2.legend(loc=10, ncol=10, bbox_to_anchor=(0.42, -0.7), columnspacing=0.4)
            else:
                lgd = ax1.legend(loc=10, ncol=10, bbox_to_anchor=(0.42, -0.5), columnspacing=0.4)
        plt.tight_layout()

        # for i in range(0, len(botnets)):
        #     ax = fd.axes[0, i]
        #     ax.set_title(ax.get_title().split(" = ")[1])
        #     for axis in [ax.xaxis, ax.yaxis]:
        #         axis.set_major_locator(ticker.MaxNLocator(integer=True))

        dest_file = os.path.join(args.working_dir, "graph", f"pois_plot_{botnet}.pdf")
        try:
            os.makedirs(os.path.dirname(dest_file))
        except FileExistsError:
            pass
        if last_flag:
            dest_file = os.path.join(args.working_dir, "graph", f"pois_plot_LEGEND.pdf")
            plt.savefig(dest_file, bbox_extra_artists=(lgd,), bbox_inches="tight")
        else:
            plt.savefig(dest_file, bbox_inches="tight")

def results_confidence_score_threshold(data, threshold=0.8, single_cycle=False):
    if single_cycle:
        data = [data]
    for crawl_cycle in data:
        crawl_cycle["new_peers_raw"] = {
            ip: {
                extractor: list(filter(lambda x: x["confidence_score"] >= threshold, pois))
                for extractor,pois in extractors.items()
            }
            for ip,extractors in crawl_cycle["new_peers_raw"].items()
        }
        for ip in list(crawl_cycle["new_peers_raw"].keys()):
            pois_found = 0
            for pois in crawl_cycle["new_peers_raw"][ip].values():
                pois_found += len(pois)
            if pois_found == 0:
                del crawl_cycle["new_peers_raw"][ip]

def graph_data3(logger, botnets: List[str], args: argparse.Namespace):
    log_with_box(logger, "graph_data3", before=1, after=1)
    results = []
    results2 = []

    for botnet in botnets:
        logger.info(f"Obtaining data for {botnet}...")
        bootstrap_list = get_bootstrap_list(botnet)
        botnet_peers = get_botnet_peers(botnet)

        scores = {}
        for j,data in enumerate(iter_results(botnet, args)):
            print(str(j) + ' ', end='', flush=True)
            for i in range(0, 101):
                threshold = i/100
                results_confidence_score_threshold(data, threshold=threshold, single_cycle=True)
                extracted_peers = data["new_peers_raw"].keys()
                extracted_peers = set(extracted_peers)
                if len(extracted_peers) == 0:
                    continue
                correct_peers = extracted_peers & (bootstrap_list | botnet_peers)
                scores.setdefault(i, []).append(len(correct_peers)/len(extracted_peers))
                results.append({
                    "Botnet": BOTNETS[botnet]["name"],
                    "Confidence score threshold": threshold,
                    "Correctness": len(correct_peers)/len(extracted_peers)
                })
                results2.append({
                    "Botnet": BOTNETS[botnet]["name"],
                    "Type": "Extracted",
                    "Confidence score threshold": threshold,
                    "Number": len(extracted_peers)                
                })
                results2.append({
                    "Botnet": BOTNETS[botnet]["name"],
                    "Type": "Correct",
                    "Confidence score threshold": threshold,
                    "Number": len(correct_peers)                
                })
        print("")
        scores = [
            (i, np.average(vals))
            for i,vals in scores.items()
        ]
        logger.info(f"Correctnesses: {scores}")
    
    line = lines.Line2D([0.8, 0.8], [0, 1000], lw=1, color="gray")

    df = pd.DataFrame(results).sort_values("Botnet", ascending=False)
    plt.figure(figsize=(4.5, 4.5))
    ax = sns.lineplot(x="Confidence score threshold", y="Correctness", hue="Botnet", data=df)
    ax.set_xlim(left=0, right=1.05)
    ax.set_ylim(bottom=0, top=1.05)
    ax.add_line(line)
    ax.get_legend().remove()
    lgd = ax.legend(loc=10, ncol=10, bbox_to_anchor=(0.45, -0.2))
    plt.tight_layout()
    
    dest_file = os.path.join(args.working_dir, "graph", "threshold_analysis.pdf")
    try:
        os.makedirs(os.path.dirname(dest_file))
    except FileExistsError:
        pass
    plt.savefig(dest_file, bbox_extra_artists=(lgd,), bbox_inches="tight")

    df = pd.DataFrame(results2).sort_values("Botnet", ascending=False)
    fg = sns.relplot(x="Confidence score threshold", y="Number", hue="Type", col="Botnet", col_wrap=2, data=df, kind="line", facet_kws={'sharey': False, 'sharex': True})
    fg.fig.set_size_inches(4.5, 4.5)
    for ax in fg.axes:
        line = lines.Line2D([0.8, 0.8], [0, 1000], lw=1, color="gray")
        ax.add_line(line)
        ax.set_title(ax.get_title().split(" = ")[1])
        ax.set_xlim(left=0)
        ax.set_ylim(bottom=0)
        if "Sality" in ax.get_title():
            ax.set_ylim(bottom=740, top=744)
        if "Nugache" in ax.get_title():
            ax.set_ylim(bottom=11, top=14.5)
    

    lgd = fg.fig.legend(loc=10, ncol=10, bbox_to_anchor=(0.5, 0), frameon=True)
    fg.legend.remove()

    # ax = sns.lineplot(x="Confidence score threshold", y="Extracted Peers", hue="Botnet", data=df)
    # ax.get_legend().remove()
    # lgd = ax.legend(loc=10, ncol=10, bbox_to_anchor=(0.52, -0.2))
    # # lgd.set_bbox_to_anchor([0.99,0.9])
    # # lgd.set_frame_on(True)
    # # lgd._loc = 2
    plt.tight_layout()
    
    dest_file = os.path.join(args.working_dir, "graph", "threshold_analysis2.pdf")
    try:
        os.makedirs(os.path.dirname(dest_file))
    except FileExistsError:
        pass
    plt.savefig(dest_file, bbox_extra_artists=(lgd,), bbox_inches="tight")

def graph_data(botnets: List[str], args: argparse.Namespace):
    logger = logging.getLogger("evaluation.graph_data")
    sns.set_style("whitegrid")
    if args.do_poi_correctness:
        graph_data1(logger, botnets, args)
    if args.do_threshold:
        graph_data3(logger, botnets, args)
    if args.do_pois:
        graph_data2(logger, botnets, args)

    if args.show:
        plt.show()

def log_stat(logger, name: str, values, confidence_scores, latex_name: str=None) -> Tuple:
    confidence_score_text = ""
    if confidence_scores is not None:
        confidence_score_text = " Avg. Confidence Score: "
        if len(confidence_scores) == 0:
            confidence_score_text += "n/a"
        else:
            confidence_score_text += f"{np.average(confidence_scores)} (n={len(confidence_scores)}, sigma={np.std(confidence_scores)})"

    logger.info(f"'{name}': {np.average(values)} (n={len(values)}, sigma={np.std(values)}){confidence_score_text}")

    cs_avg = None
    cs_std = None
    if len(confidence_scores) > 0:
        cs_avg = np.average(confidence_scores)
        cs_std = np.std(confidence_scores)

    return (np.average(values), np.std(values), cs_avg, len(confidence_scores), cs_std)

def log_latex(file, latex_name: str, wo_th, w_th, botnet_title: str=None, rows: int=4):
    botnet_title_text = ""
    if botnet_title is not None:
        botnet_title_text = f"\\multirow{{4}}{{*}}{{\\rotatebox[origin=c]{{90}}{{{botnet_title}}}}}"

    confidence_score_text_wo = ""
    if wo_th[2] is not None:
        confidence_score_text_wo = f"${wo_th[2]:.2f}$ ($n={wo_th[3]}$ $\\sigma\\approx{wo_th[4]:.2f}$)"
    else: confidence_score_text_wo = "n/a"
    confidence_score_text_w = ""
    if w_th[2] is not None:
        confidence_score_text_w = f"${w_th[2]:.2f}$ ($n={w_th[3]}$ $\\sigma\\approx{w_th[4]:.2f}$)"
    else: confidence_score_text_w = "n/a"
    latex_line = f"{botnet_title_text} & {latex_name} & ${wo_th[0]:.2f}$ ($\\sigma\\approx{wo_th[1]:.2f}$) & {confidence_score_text_wo} & & ${w_th[0]:.2f}$ ($\\sigma\\approx{w_th[1]:.2f}$) & {confidence_score_text_w} \\\\"
    file.write(latex_line + "\n")

def extract_results(botnet: str, args: argparse.Namespace):
    logger = logging.getLogger("evaluation.extract_results")

    result_data = load_all_results(botnet, args)
    bootstrap_list = get_bootstrap_list(botnet)
    botnet_peers = get_botnet_peers(botnet)

    crawl_data = result_data

    # def f_correct_non_bs_shared_peers(x):
    #     new_peers_raw: Dict[str, List[str]] = x["new_peers_raw"]
    #     return len(set(new_peers_raw.keys()) & (botnet_peers - bootstrap_list))
    # correct_non_bs_shared_peers = list(map(f_correct_non_bs_shared_peers, crawl_data))
    # log_stat(logger, "correct_non_bs_shared_peers", correct_non_bs_shared_peers)

    confidence_scores = []

    def get_confidence_scores(new_peers_raw, peers):
        res = []
        for peer in peers:
            for _,pois in new_peers_raw[peer].items():
                for poi in pois:
                    res.append(poi["confidence_score"])
        return res


    def f_extracted_peers(x):
        nonlocal confidence_scores
        cs = get_confidence_scores(x["new_peers_raw"], x["new_peers_raw"].keys())
        if len(cs) != 0:
            confidence_scores.append(np.average(cs))
        return len(x["new_peers_raw"])

    def f_correct_peers(x):
        nonlocal confidence_scores
        new_peers_raw: Dict[str, List[Poi]] = x["new_peers_raw"]
        correct_peers = set(new_peers_raw.keys()) & botnet_peers
        cs = get_confidence_scores(new_peers_raw, correct_peers)
        if len(cs) != 0:
            confidence_scores.append(np.average(cs))
        return len(correct_peers)

    def f_non_botnet_bs_peers(x):
        nonlocal confidence_scores
        new_peers_raw: Dict[str, List[Poi]] = x["new_peers_raw"]
        non_botnet_bs_peers = set(new_peers_raw.keys()) & (bootstrap_list - botnet_peers)
        cs = get_confidence_scores(new_peers_raw, non_botnet_bs_peers)
        if len(cs) != 0:
            confidence_scores.append(np.average(cs))
        return len(non_botnet_bs_peers)

    def f_wrong_peers(x):
        nonlocal confidence_scores
        new_peers_raw: Dict[str, List[Poi]] = x["new_peers_raw"]
        wrong_peers = set(new_peers_raw.keys()) - (bootstrap_list | botnet_peers)
        cs = get_confidence_scores(new_peers_raw, wrong_peers)
        if len(cs) != 0:
            confidence_scores.append(np.average(cs))
        return len(wrong_peers)



    log_with_box(logger, "Without confidence score threshold", before=1, after=1)

    confidence_scores = []
    extracted_peers = list(map(f_extracted_peers, crawl_data))
    res1_wo = log_stat(logger, "extracted_peers", extracted_peers, confidence_scores)

    confidence_scores = []
    correct_peers = list(map(f_correct_peers, crawl_data))
    res2_wo = log_stat(logger, "correct_peers", correct_peers, confidence_scores)

    confidence_scores = []
    non_botnet_bs_peers = list(map(f_non_botnet_bs_peers, crawl_data))
    res3_wo = log_stat(logger, "non_botnet_bs_peers", non_botnet_bs_peers, confidence_scores)

    confidence_scores = []
    wrong_peers = list(map(f_wrong_peers, crawl_data))
    res4_wo = log_stat(logger, "wrong_peers", wrong_peers, confidence_scores)



    log_with_box(logger, "With confidence score threshold", before=1, after=1)
    results_confidence_score_threshold(crawl_data)

    confidence_scores = []
    extracted_peers = list(map(f_extracted_peers, crawl_data))
    res1_w = log_stat(logger, "extracted_peers", extracted_peers, confidence_scores)

    confidence_scores = []
    correct_peers = list(map(f_correct_peers, crawl_data))
    res2_w = log_stat(logger, "correct_peers", correct_peers, confidence_scores)

    confidence_scores = []
    non_botnet_bs_peers = list(map(f_non_botnet_bs_peers, crawl_data))
    res3_w = log_stat(logger, "non_botnet_bs_peers", non_botnet_bs_peers, confidence_scores)

    confidence_scores = []
    wrong_peers = list(map(f_wrong_peers, crawl_data))
    res4_w = log_stat(logger, "wrong_peers", wrong_peers, confidence_scores)

    dest_file = os.path.join(args.working_dir, botnet, "table.txt")
    with open(dest_file, "w") as f:
        log_latex(f, r"$|\EP|$", res1_wo, res1_w, botnet_title=BOTNETS[botnet]["name"])
        log_latex(f, r"$|\mathrm{CORRECT}|$", res2_wo, res2_w)
        log_latex(f, r"$|\mathrm{BOOTSTRAP}|$", res3_wo, res3_w)
        log_latex(f, r"$|\mathrm{WRONG}|$", res4_wo, res4_w)
        f.write(r"\midrule")

def run_sample_for_delay(i: int, botnet: str, native: bool, args: argparse.Namespace):
    logger = logging.getLogger("evaluation.run_sample_for_delay")
    analysis_package = BOTNETS[botnet]["analysis_package"]
    output_folder = os.path.join(args.working_dir, botnet, "delay", f"{'native' if native else 'pin'}_{i}")

    config = configparser.ConfigParser()
    config.read([MAIN_CONFIG_FILE, os.path.join(analysis_package, "package.ini")])

    args = argparse.Namespace(
        analysis_package=analysis_package,
        output_folder=output_folder
    )
    config_class = auto_puppeteer.parse_config(config, args)

    logger.info("Starting VM")
    if native:
        snapshot = DELAY_NATIVE_SNAPSHOT
    else:
        snapshot = config_class.agent_snapshot
    config_class.vm.start_from(snapshot)

    logger.info("Connecting Agent")
    agent_connection = AgentConnector(config_class.agent_address)
    logger.info("Uploading package")
    agent_connection.upload_package(analysis_package)
    logger.info("Starting packet capture")
    agent_connection.start_dumpcap()
    logger.info("Starting sample")
    _run_pintool(agent_connection, config_class)

    sleep_time = BOTNETS[botnet]["delay_measure_time"][0 if native else 1]
    logger.info(f"Waiting for {sleep_time} seconds...")

    if native:
        time.sleep(sleep_time)
    else:
        ipc_server = agent_connection.get_ipc_server()
        def wrapper_callback(pid: int, function: WrapperFunction, ip: IPv4Address, port: int) -> Optional[bool]:
            return True
        _ipc_server_listen(ipc_server, wrapper_callback, timeout=sleep_time)

    logger.info(f"Downloading output to \"{output_folder}\"")
    agent_connection.download_output(output_folder)

    logger.info(f" Stopping VM")
    config_class.vm.stop()


def measure_delay(botnet: str, args: argparse.Namespace):
    logger = logging.getLogger("evaluation.measure_delay")
    begin = args.begin if args.begin is not None else 0
    end = args.end if args.end is not None else args.n-1

    log_with_box(logger, "Native", before=1, after=1)
    for i in range(begin, end+1):
        log_with_box(logger, str(i), before=0, after=0)
        run_sample_for_delay(i, botnet, True, args)

    log_with_box(logger, "With Pin", before=1, after=1)
    for i in range(begin, end+1):
        log_with_box(logger, str(i), before=0, after=0)
        run_sample_for_delay(i, botnet, False, args)

def stat_col(table, i: int):
    col = list(map(lambda x: x[i], table))
    return (
        np.average(col),
        np.std(col)
    )

def analyze_delay(botnet: str, args: argparse.Namespace):
    logger = logging.getLogger("evaluation.analyze_delay")
    begin = args.begin if args.begin is not None else 0
    end = args.end if args.end is not None else args.n-1

    results_native = []
    results_pin = []

    log_with_box(logger, "Native", before=1, after=1)
    for i in range(begin, end+1):
        log_with_box(logger, str(i), before=0, after=0)

        pcap_file = os.path.join(args.working_dir, botnet, "delay", f"native_{i}", "dump.pcapng")
        output = subprocess.check_output(f"tshark -T fields -n -r {pcap_file} -E separator=, -e _ws.col.Time -e ip.src -e ip.dst -e tcp.dstport -e udp.dstport \"{BOTNETS[botnet]['filter']}\"", shell=True)
        output = output.decode("utf-8")
        parsed_output = [x.split(",") for x in output.split("\n")]
        logger.info(f"Example line: {parsed_output[10]}")

        T_0 = float(parsed_output[0][0])
        T_1 = float(parsed_output[20][0])
        T_2 = float(parsed_output[40][0])
        results_native.append([T_0, T_1, T_2])

    log_with_box(logger, "With Pin", before=1, after=1)
    for i in range(begin, end+1):
        log_with_box(logger, str(i), before=0, after=0)

        pcap_file = os.path.join(args.working_dir, botnet, "delay", f"pin_{i}", "dump.pcapng")
        output = subprocess.check_output(f"tshark -T fields -n -r {pcap_file} -E separator=, -e _ws.col.Time -e ip.src -e ip.dst -e tcp.dstport -e udp.dstport \"{BOTNETS[botnet]['filter']}\"", shell=True)
        output = output.decode("utf-8")
        parsed_output = [x.split(",") for x in output.split("\n")]
        logger.info(f"Example line: {parsed_output[10]}")

        T_0 = float(parsed_output[0][0])
        T_1 = float(parsed_output[20][0])
        T_2 = float(parsed_output[40][0])
        results_pin.append([T_0, T_1, T_2])

    def format_stats(table):
        res = ""
        for i in range(6):
            stats = stat_col(table, i)
            if i == 3:
                res += " &"
            res += f" & ${stats[0]:.2f}$ ($\\sigma\\approx{stats[1]:.2f}$)"
        return res
        # line = line.copy()
        # line.insert(3, None)
        # return " & ".join(list(map(
        #     lambda x: f"{x:.2f}s" if x is not None else "",
        #     line
        # )))


    table = []
    outfile = os.path.join(args.working_dir, botnet, "delay", "out.txt")
    with open(outfile, "w") as f:
        for i,(r_native,r_pin) in enumerate(zip(results_native, results_pin)):
            row = r_native + r_pin
            row[5] = row[5] - row[4]
            row[4] = row[4] - row[3]
            row[2] = row[2] - row[1]
            row[1] = row[1] - row[0]
            table.append(row)
        f.write(f"{BOTNETS[botnet]['name']}{format_stats(table)}\\\\\n")
    logger.info(f"Wrote output to {outfile}")

if __name__ == "__main__":
    logging.config.fileConfig("evaluation_logging.conf")
    logger = logging.getLogger(__name__)
    def botnet_verifier(val):
        if val not in BOTNETS:
            raise ValueError(f"{val} is not a valid botnet.")
        return val
    parser = argparse.ArgumentParser(prog='python3 evaluation.py')
    parser.add_argument("-b", "--botnet", action="append", help="The botnets to use.", type=botnet_verifier, default=[], dest="botnets")
    parser.add_argument("working_dir", help="The directory where all files being processed by this tool will be place/loaded from.")

    subparsers = parser.add_subparsers(help='The operation to perform.', required=True, dest="subparser_name")

    parser_collect = subparsers.add_parser('collect1', help='Run the data collection. Step 1.')
    parser_collect.add_argument("--skip_pois", help="Skip the POI collection run with the MemoryPatternPoiExtractor.", action="store_false", dest="do_pois")
    parser_collect.add_argument("--skip_crawling", help="Skip the crawling run w/o the MemoryPatternPoiExtractor.", action="store_false", dest="do_crawling")

    parser_collect = subparsers.add_parser('collect2', help='Run the data collection. Step 2 (a lot of RAM required).')

    parser_graph = subparsers.add_parser('graph', help='Generate the graphs.')
    parser_graph.add_argument("--show", help="Show the resulting graphs.", action="store_true")
    parser_graph.add_argument("--skip_poi_correctness", action="store_false", dest="do_poi_correctness")
    parser_graph.add_argument("--skip_pois", action="store_false", dest="do_pois")
    parser_graph.add_argument("--skip_threshold", action="store_false", dest="do_threshold")

    parser_delay = subparsers.add_parser('delay', help='Measure the delay introduced by the PinPuppet pintool.')
    parser_delay.add_argument("-n", help="The number of repetitions.", type=int, default=5)
    parser_delay.add_argument("--begin", type=int)
    parser_delay.add_argument("--end", type=int)

    parser_delay_analysis = subparsers.add_parser('analyze_delay', help='Analyze the delay measurement results from "delay".')
    parser_delay_analysis.add_argument("-n", help="The number of repetitions.", type=int, default=5)
    parser_delay_analysis.add_argument("--begin", type=int)
    parser_delay_analysis.add_argument("--end", type=int)


    parser_results = subparsers.add_parser('results', help='Extract the results.')

    args = parser.parse_args()
    loop = True
    print(args)
    if args.subparser_name == "collect1":
        fun = collect_data1
    elif args.subparser_name == "collect2":
        fun = collect_data2
    elif args.subparser_name == "graph":
        fun = graph_data
        loop = False
    elif args.subparser_name == "results":
        fun = extract_results
    elif args.subparser_name == "delay":
        fun = measure_delay
    elif args.subparser_name == "analyze_delay":
        fun = analyze_delay
    else: assert(False)
    if loop:
        for botnet in args.botnets:
            log_with_box(logger, f"########## Running {args.subparser_name} for {botnet} ##########")
            fun(botnet, args)
            log_with_box(logger, f"########## Done with {args.subparser_name} for {botnet} ##########")
    else:
        log_with_box(logger, f"########## Running {args.subparser_name} for {args.botnets} ##########")
        fun(args.botnets, args)
        log_with_box(logger, f"########## Done with {args.subparser_name} for {args.botnets} ##########")