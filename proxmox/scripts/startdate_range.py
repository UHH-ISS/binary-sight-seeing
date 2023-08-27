import pve_qm
import argparse

parser = argparse.ArgumentParser(description="Sets the startdate of VMID range to the first of september 2020.")

parser.add_argument("first", type=int, help="The first VMID to set the startdate.")
parser.add_argument("last", type=int, help="The last VMID to set the startdate.")

args = parser.parse_args()

for i in range(args.first, args.last + 1):
    print(f"Shutting down {i}")
    pve_qm.set_startdate(i, "2020-09-01")
