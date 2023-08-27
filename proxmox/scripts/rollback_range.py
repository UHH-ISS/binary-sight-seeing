import pve_qm
import argparse

parser = argparse.ArgumentParser(description="Rollback all VMIDs within a range.")

parser.add_argument("first", type=int, help="The first VMID to rollback.")
parser.add_argument("last", type=int, help="The last VMID to rollback.")
parser.add_argument("snapname", help="The snapshot to rollback to.")

args = parser.parse_args()

for i in range(args.first, args.last + 1):
    print(f"Rolling back {i} to {args.snapname}")
    pve_qm.rollback(i, args.snapname)