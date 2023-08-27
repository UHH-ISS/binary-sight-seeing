import pve_qm
import argparse

parser = argparse.ArgumentParser(description="Start all VMIDs within a range.")

parser.add_argument("first", type=int, help="The first VMID to start.")
parser.add_argument("last", type=int, help="The last VMID to start.")

args = parser.parse_args()

for i in range(args.first, args.last + 1):
    print(f"Starting {i}")
    pve_qm.start(i)