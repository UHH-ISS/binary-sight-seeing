import pve_qm
import argparse

parser = argparse.ArgumentParser(description="Delete a snapshot from all VMIDs within a range.")

parser.add_argument("first", type=int, help="The first VMID to delete the snapshot from.")
parser.add_argument("last", type=int, help="The last VMID to delete the snapshot from.")
parser.add_argument("snapname", help="The snapshot to delete.")

args = parser.parse_args()

for i in range(args.first, args.last + 1):
    print(f"Deleting {args.snapname} from {i}")
    pve_qm.delsnapshot(i, args.snapname)