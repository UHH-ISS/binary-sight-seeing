from proxmoxer import ProxmoxAPI
import time
import pve_qm

# create botnet with:
# create_vm_net.py N 110 NEW_NAME NEW_IP FIRST
# N has to be LAST-FIRST+1
# 110 is the template that matches the start script
# (mouse movements etc.)

FIRST = 200
LAST = 219
BOOTSTRAP = 220
BOOTSTRAP_OTHER_DELAY = 5*60
BASE_SNAPSHOT = "Base"
NODE = "proxmox"
proxmox = ProxmoxAPI("10.16.1.1", user="api@pve", password="apiapi", verify_ssl=False)

def login(vmid):
    monitor = proxmox.nodes(NODE).qemu(int(vmid)).monitor

    monitor.post(command="sendkey a")
    monitor.post(command="sendkey d")
    monitor.post(command="sendkey m")
    monitor.post(command="sendkey i")
    monitor.post(command="sendkey n")
    monitor.post(command="sendkey kp_enter")

def start_zeroaccess(vmid):
    monitor = proxmox.nodes(NODE).qemu(int(vmid)).monitor

    for i in range(20):
        monitor.post(command="mouse_move -10 10")
    for i in range(2):
        monitor.post(command="mouse_move 0 10")
    monitor.post(command="mouse_button 1")
    monitor.post(command="mouse_button 0")
    time.sleep(3)
    for i in range(37):
        monitor.post(command="mouse_move 0 -10")
    for i in range(5):
        monitor.post(command="mouse_move 10 0")
    monitor.post(command="mouse_button 1")
    monitor.post(command="mouse_button 0")
    monitor.post(command="mouse_button 1")
    monitor.post(command="mouse_button 0")
    time.sleep(1)
    for i in range(2):
        monitor.post(command="mouse_move 0 10")
    monitor.post(command="mouse_button 1")
    monitor.post(command="mouse_button 0")
    monitor.post(command="mouse_button 1")
    monitor.post(command="mouse_button 0")

print("Rolling back VMs...")
for i in range(FIRST, LAST + 1):
    print(f"Rolling back {i}")
    pve_qm.rollback(i, BASE_SNAPSHOT)
print(f"Rolling back {BOOTSTRAP}")
pve_qm.rollback(BOOTSTRAP, BASE_SNAPSHOT)
print()

print("Starting VMs...")
for i in range(FIRST, LAST + 1):
    print(f"Starting {i}")
    pve_qm.start(i)
print(f"Starting {BOOTSTRAP}")
pve_qm.start(BOOTSTRAP, wait=True)
print()

print("Starting ZeroAccess on Bootstrap...")
pve_qm.wait_for_agent(BOOTSTRAP)
login(BOOTSTRAP)
time.sleep(60)
start_zeroaccess(BOOTSTRAP)
print()

print(f"Sleeping for {0.5*BOOTSTRAP_OTHER_DELAY}s")
time.sleep(0.5*BOOTSTRAP_OTHER_DELAY)
print()

print(f"Logging in on Peers...")
for i in range(FIRST, LAST + 1):
    print(f"Logging in on {i}")
    login(i)

print(f"Sleeping for {0.5*BOOTSTRAP_OTHER_DELAY}s")
time.sleep(0.5*BOOTSTRAP_OTHER_DELAY)
print()

print(f"Starting ZeroAccess on Peers...")
for i in range(FIRST, LAST + 1):
    print(f"Starting ZeroAccess on {i}")
    start_zeroaccess(i)

print("\nDONE!")