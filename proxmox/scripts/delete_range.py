import pve_qm
import argparse

parser = argparse.ArgumentParser(description="Delete all VMIDs within a range.")

parser.add_argument("first", type=int, help="The first VMID to delete.")
parser.add_argument("last", type=int, help="The last VMID to delete.")
parser.add_argument("--dont_purge", help="Don't purge.", action="store_true")

args = parser.parse_args()

for i in range(args.first, args.last + 1):
    pve_qm.destroy(i, not args.dont_purge)
    print(f"Deleting {i}")