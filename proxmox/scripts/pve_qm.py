import subprocess

def bool_to_conf(b):
    if b: return "true"
    else: return "false"

def start(vmid, wait=False):
    cmd = ["qm", "start", str(vmid)]
    print(" ".join(cmd))
    subprocess.run(cmd, check=True)
    if wait:
        wait_for_agent(vmid)

def wait_for_agent(vmid):
    while True:
        exception_thrown = False
        try:
            subprocess.run(
                ["qm", "agent", str(vmid), "ping"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True
            )
        except subprocess.CalledProcessError:
            exception_thrown = True
        if not exception_thrown: break


def shutdown(vmid):
    cmd = ["qm", "shutdown", str(vmid)]
    subprocess.run(cmd, check=True)
    print(" ".join(cmd))

def win_set_ip(id, ip, ifc="Local Area Connection", log=subprocess.DEVNULL):
    cmd = f"qm guest exec {id} netsh interface ip set address \"{ifc}\" static {ip} 255.255.255.255 1.1.1.1"
    print(cmd)
    if log is not subprocess.DEVNULL:
        log.write(cmd + '\n')
    subprocess.run(cmd.split(" "), stdout=log, check=True)

def win_set_computername(id, oldname, newname, log=subprocess.DEVNULL):
    cmd = f"qm guest exec {id} wmic computersystem where caption='{oldname}' rename {newname}"
    print(cmd)
    if log is not subprocess.DEVNULL:
        log.write(cmd + '\n')
    subprocess.run(cmd.split(" "), stdout=log, check=True)

def clone(src, dst, newname, log=subprocess.DEVNULL):
    cmd = ["qm", "clone", str(src), str(dst), "--name", newname]
    print(" ".join(cmd))
    subprocess.run(cmd, stdout=log, check=True)

def destroy(vmid, purge=True):
    cmd = ["qm", "destroy", str(vmid), "--purge", bool_to_conf(purge)]
    print(" ".join(cmd))
    subprocess.run(cmd, check=True)

def delsnapshot(vmid, snapshot):
    cmd = ["qm", "delsnapshot", str(vmid), snapshot]
    print(" ".join(cmd))
    subprocess.run(cmd, check=True)

def rollback(vmid, snapshot):
    cmd = ["qm", "rollback", str(vmid), snapshot]
    print(" ".join(cmd))
    subprocess.run(cmd, check=True)

def snapshot(vmid, snapshot, live=True):
    cmd = ["qm", "snapshot", str(vmid), snapshot, "--vmstate", bool_to_conf(live)]
    print(" ".join(cmd))
    subprocess.run(cmd, check=True)

def stop(vmid):
    cmd = ["qm", "stop", str(vmid)]
    print(" ".join(cmd))
    subprocess.run(cmd, check=True)

def set_startdate(vmid, startdate):
    cmd = ["qm", "set", str(vmid), "-startdate", startdate]
    print(" ".join(cmd))
    subprocess.run(cmd, check=True)
