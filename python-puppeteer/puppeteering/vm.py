import abc
import uuid

# Make Proxmoxer an optional import.
# Otherwise it would need to be installed
# for using the agent.
try:
    from proxmoxer import ProxmoxAPI
    import proxmoxer
except ModuleNotFoundError:
    pass
import time
import logging

__all__ = [
    "VirtualMachine",
    "ProxmoxVM",
]

class VirtualMachine(abc.ABC):
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    @staticmethod
    @abc.abstractmethod
    def get_random_snapshot_id() -> str:
        pass

    # Starts the VM.
    # This call does not need to block.
    @abc.abstractmethod
    def start(self):
        self.logger.info("%s - start", str(self))

    # Rolls the VM back to a snapshot and starts it.
    # When wait_for_started is true, the call blocks
    # until the VM is started.
    @abc.abstractmethod
    def start_from(self, snapshot_id: str):
        self.logger.info("%s - start from \"%s\"", str(self), snapshot_id)

    # Takes a snapshot with the ID snapshot_id.
    # The call blocks until the snapshot is done.
    @abc.abstractmethod
    def take_snapshot(self, snapshot_id: str, description: str=None):
        self.logger.info("%s - take snapshot \"%s\"", str(self), snapshot_id)

    # Deletes a snapshot based on its ID.
    @abc.abstractmethod
    def delete_snapshot(self, snapshot_id: str):
        self.logger.info("%s - delete snapshot \"%s\"", str(self), snapshot_id)

    # Stops the VM.
    @abc.abstractmethod
    def stop(self):
        self.logger.info("%s - stop", str(self))

    @abc.abstractmethod
    def __str__(self) -> str:
        pass

class ProxmoxVM(VirtualMachine):
    def __init__(self, host: str, user: str, password: str, node: str, vmid: int, name: str=None):
        super().__init__()
        self.host = host
        self.node = node
        self.vmid = vmid
        self.user = user
        self.password = password
        self.proxmox_time = time.time()
        self.proxmox_ = ProxmoxAPI(host, user=user, password=password, verify_ssl=False)
        self.name = name
        self.random_mouse_movements = False

    def proxmox(self):
        if time.time() - self.proxmox_time > 3600:
            self.proxmox_ = ProxmoxAPI(self.host, user=self.user, password=self.password, verify_ssl=False)
            self.proxmox_time = time.time()
        return self.proxmox_

    def vm(self):
        return self.proxmox().nodes(self.node).qemu(self.vmid)

    def __is_locked(self):
        return "lock" in self.vm().status.current.get()

    # Wait for the VM to be unlocked in Proxmox
    def __wait_for_unlock(self):
        was_locked = False
        for _ in range(1000):
            is_locked = self.__is_locked()
            if was_locked and not is_locked:
                return
            elif not was_locked and is_locked:
                was_locked = True
            time.sleep(0.01)
        raise RuntimeError("VM never unlocked")

    # Wait for the VM to be started in Proxmox.
    # This is done by continously checking if the
    # QEMU Agent is running.
    def __wait_for_started(self, timeout: float=None) -> bool:
        start_time = time.time()
        while True:
            online = True
            try:
                self.vm().agent.ping.post()
            except proxmoxer.core.ResourceException as e:
                if e.args[0].split(" ")[0] == "500":
                    online = False
                else:
                    raise e
            if online: return True
            if timeout and (time.time() - start_time) > timeout: return False
            time.sleep(0.2)

    @staticmethod
    def get_random_snapshot_id() -> str:
        return "tmp_" + str(uuid.uuid4()).replace("-", "_")

    def start(self):
        super().start()
        self.vm().status.start.post()
        self.__wait_for_started()

    def start_from(self, snapshot_id: str):
        super().start_from(snapshot_id)
        success = False
        while not success:
            self.vm().snapshot(snapshot_id).rollback.post()
            # TODO: make this an argument if needed
            # self.vm().status.start.post()
            success = self.__wait_for_started(timeout=600)

    def take_snapshot(self, snapshot_id: str, description: str=""):
        super().take_snapshot(snapshot_id, description=description)
        # Always try to create live snapshots.
        # If the VM is not running this is not a problem.
        self.vm().snapshot.post(snapname=snapshot_id, vmstate=1, description=description)
        self.__wait_for_unlock()

    def delete_snapshot(self, snapshot_id: str):
        super().delete_snapshot(snapshot_id)
        self.vm().snapshot(snapshot_id).delete()
        self.__wait_for_unlock()

    def stop(self):
        super().stop()
        i = 0
        while True:
            try:
                self.vm().status.stop.post()
            except proxmoxer.ResourceException as err:
                if "500 Internal Server Error: got no worker upid" in err.args[0]:
                    i += 1
                    if i == 10:
                        raise
                    time.sleep(1)
                else:
                    raise
            else:
                break


    def __str__(self) -> str:
        res = f"ProxmoxVM({self.host}/{self.node}/{self.vmid}"
        if self.name:
            res += f", {self.name}"
        return res + ")"
