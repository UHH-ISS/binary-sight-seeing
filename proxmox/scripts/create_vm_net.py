import argparse
import subprocess
import pve_qm

def get_ip_string(ip_block, n, sym=True):
    octetts = [str(ip_block+n)]*4
    if not sym: octetts[2] = "0"
    return ".".join(octetts)

parser = argparse.ArgumentParser(description="Clone a VM/Template n times and set the IPs in Windows.")

parser.add_argument("n", type=int, help="The number of cloned VMs.")
parser.add_argument("base", type=int, help="The VMID of to VM/Template clone.")
parser.add_argument("new_name", help="The name of the new VM (get's appended with the number).")
parser.add_argument("new_ip", type=int, help="The IP of the new VM (e.g. 10 for 10.10.10.10). This value gets incremented after every clone.")
parser.add_argument("new_id", type=int, help="The VMID of the new VM. This value gets incremented after every clone.")

parser.add_argument("--ip_sym", help="Make the IP non symmetric.", action="store_false")
parser.add_argument("--cont", type=int, help="Continue in this iteration.", default=0)
parser.add_argument("--rename", type=str, help="Rename the PC")

args = parser.parse_args()


n = args.n
base_id = args.base
new_name = args.new_name
new_ip_block = args.new_ip
new_id = args.new_id

for i in range(args.cont, n):
    print(f"Cloning {base_id}->{new_id+i} ({new_name+str(i)})")
    with open(f"clone_{base_id}_{new_id+i}.log", "w+") as f:
        pve_qm.clone(base_id, new_id+i, new_name+str(i), log=f)
    print(f"Starting {new_id+i}")
    pve_qm.start(new_id+i, wait=True)
    print(f"Started...")
    print(f"Setting IP of {new_id+i} to {get_ip_string(new_ip_block,i,args.ip_sym)}")
    with open(f"set_ip_{new_id+i}.log", "w+") as f:
        pve_qm.win_set_ip(new_id+i, get_ip_string(new_ip_block,i,args.ip_sym), log=f)
    if args.rename is not None:
        with open(f"rename_{new_id+i}.log", "w+") as f:
            pve_qm.win_set_computername(new_id+i, args.rename, "pc"+str(i), log=f)
    print(f"Shutting {new_id+i} down")
    pve_qm.shutdown(new_id+i)
