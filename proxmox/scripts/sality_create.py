from proxmoxer import ProxmoxAPI
import time
import pve_qm

# create botnet with:
# create_vm_net.py N 110 NEW_NAME NEW_IP FIRST
# N has to be LAST-FIRST+1
# 110 is the template that matches the start script
# (mouse movements etc.)

FIRST = 400
LAST = 419
BOOTSTRAP1 = 420
BOOTSTRAP2 = 421
BASE_SNAPSHOT = "Base"
NODE = "proxmox"
BOOTSTRAP_OTHER_DELAY = 30*60
proxmox = ProxmoxAPI("10.16.1.1", user="api@pve", password="apiapi", verify_ssl=False)

def login(vmid):
    monitor = proxmox.nodes(NODE).qemu(int(vmid)).monitor

    monitor.post(command="sendkey a")
    monitor.post(command="sendkey d")
    monitor.post(command="sendkey m")
    monitor.post(command="sendkey i")
    monitor.post(command="sendkey n")
    monitor.post(command="sendkey kp_enter")

def start_sality(vmid):
    monitor = proxmox.nodes(NODE).qemu(int(vmid)).monitor

    for i in range(20):
        monitor.post(command="mouse_move -10 10")
        time.sleep(0.1)
    for i in range(2):
        monitor.post(command="mouse_move 0 10")
        time.sleep(0.1)
    monitor.post(command="mouse_button 1")
    monitor.post(command="mouse_button 0")
    time.sleep(3)
    for i in range(37):
        monitor.post(command="mouse_move 0 -10")
        time.sleep(0.1)
    for i in range(5):
        monitor.post(command="mouse_move 10 0")
        time.sleep(0.1)
    monitor.post(command="mouse_button 1")
    monitor.post(command="mouse_button 0")
    monitor.post(command="mouse_button 1")
    monitor.post(command="mouse_button 0")
    time.sleep(1)
    # Uncomment for Sality Local Botnet V1
    # for i in range(2):
    #     monitor.post(command="mouse_move 0 10")
    #     time.sleep(0.1)
    monitor.post(command="mouse_button 1")
    monitor.post(command="mouse_button 0")
    monitor.post(command="mouse_button 1")
    monitor.post(command="mouse_button 0")

def start_wireshark(vmid):
    monitor = proxmox.nodes(NODE).qemu(int(vmid)).monitor

    for i in range(5):
        monitor.post(command="mouse_move -20 20")
        time.sleep(0.1)
    for i in range(6):
        monitor.post(command="mouse_move 0 20")
        time.sleep(0.1)
    monitor.post(command="mouse_button 1")
    monitor.post(command="mouse_button 0")

    time.sleep(10)
    monitor.post(command="sendkey r")
    monitor.post(command="sendkey u")
    monitor.post(command="sendkey n")
    monitor.post(command="sendkey kp_enter")
    time.sleep(5)
    monitor.post(command="sendkey w")
    monitor.post(command="sendkey i")
    monitor.post(command="sendkey r")
    monitor.post(command="sendkey e")
    monitor.post(command="sendkey s")
    monitor.post(command="sendkey h")
    monitor.post(command="sendkey a")
    monitor.post(command="sendkey r")
    monitor.post(command="sendkey k")
    monitor.post(command="sendkey dot")
    monitor.post(command="sendkey e")
    monitor.post(command="sendkey x")
    monitor.post(command="sendkey e")
    monitor.post(command="sendkey spc")
    monitor.post(command="sendkey slash") # slash is - on german layout
    monitor.post(command="sendkey i")
    monitor.post(command="sendkey spc")
    monitor.post(command="sendkey 5")
    monitor.post(command="sendkey spc")
    monitor.post(command="sendkey slash")
    monitor.post(command="sendkey k")
    time.sleep(5)
    monitor.post(command="sendkey kp_enter")

print("Rolling back VMs...")
for i in range(FIRST, LAST + 1):
    print(f"Rolling back {i}")
    pve_qm.rollback(i, BASE_SNAPSHOT)
print(f"Rolling back {BOOTSTRAP2}")
pve_qm.rollback(BOOTSTRAP2, BASE_SNAPSHOT)
print()

print("Starting VMs...")
for i in range(FIRST, LAST + 1):
    print(f"Starting {i}")
    pve_qm.start(i)
print(f"Starting {BOOTSTRAP1}")
pve_qm.start(BOOTSTRAP1)
print()

print("Logging in on Bootstrap 1 and 2...")
pve_qm.wait_for_agent(BOOTSTRAP1)
time.sleep(5)
login(BOOTSTRAP1)
print()


time.sleep(60)
print("Starting Sality on Bootstrap 1 and 2...")
start_sality(BOOTSTRAP1)
time.sleep(1)
start_wireshark(BOOTSTRAP1)
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

print(f"Starting Sality on Peers...")
for i in range(FIRST, LAST + 1):
    print(f"Starting Sality on {i}")
    start_sality(i)
    time.sleep(60)
    print(f"Starting Wireshark on {i}")
    start_wireshark(i)
    time.sleep(60)
print()

print("\nDONE!")
