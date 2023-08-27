import pve_qm
import argparse

parser = argparse.ArgumentParser(description="Stop all VMIDs within a range.")

parser.add_argument("first", type=int, help="The first VMID to stop.")
parser.add_argument("last", type=int, help="The last VMID to stop.")

args = parser.parse_args()

for i in range(args.first, args.last + 1):
    print(f"Stoping {i}")
    pve_qm.stop(i)