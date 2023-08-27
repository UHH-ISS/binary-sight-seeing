import pve_qm
import argparse

parser = argparse.ArgumentParser(description="Create snapshots for all VMIDs within a range.")

parser.add_argument("first", type=int, help="The first VMID to create a snapshot for.")
parser.add_argument("last", type=int, help="The last VMID to create a snapshot for.")
parser.add_argument("snapname", help="The name of the snapshot to be created.")
parser.add_argument("--live", "-l", help="Create a live snapshot (include RAM).", action="store_true")

args = parser.parse_args()

for i in range(args.first, args.last + 1):
    print(f"Creating snapshot for {i}")
    pve_qm.snapshot(i, args.snapname, live=args.live)