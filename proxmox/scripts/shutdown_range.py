import pve_qm
import argparse

parser = argparse.ArgumentParser(description="Shutdown all VMIDs within a range.")

parser.add_argument("first", type=int, help="The first VMID to shutdown.")
parser.add_argument("last", type=int, help="The last VMID to shutdown.")

args = parser.parse_args()

for i in range(args.first, args.last + 1):
    print(f"Shutting down {i}")
    pve_qm.shutdown(i)