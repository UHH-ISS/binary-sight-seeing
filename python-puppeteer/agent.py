import rpyc
import tempfile
import threading
import tarfile
import os
import mmap
import subprocess
import time
import ipaddress
import re
import random
import ctypes
import psutil
import glob
from distutils import dir_util
import importlib.util
import ctypes

from puppeteering.util import RpycEnum
from puppeteering.types import *

class POINT(ctypes.Structure):
    _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]

if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv(verbose=True)

    # Disable the Windows error box that appears when a subprocess crashes.
    # https://www.activestate.com/blog/supressing-windows-error-report-messagebox-subprocess-and-ctypes/
    SEM_NOGPFAULTERRORBOX = 0x0002
    ctypes.windll.kernel32.SetErrorMode(SEM_NOGPFAULTERRORBOX) # type: ignore

    PINPATH = os.environ['PINPATH']
    PINTOOL = os.environ['PINTOOL']
    DUMPIF = os.environ['DUMPIF']
    print(f"PINPATH: {PINPATH}\nPINTOOL: {PINTOOL}\nDUMPIF: {DUMPIF}\n")

    lock = threading.Lock()

def run_with_uac(cmd):
    ctypes.windll.shell32.ShellExecuteW(None, "runas", cmd[0], ' '.join(cmd[1:]), None, 1) # type: ignore

def load_package_scripts(package_dir):
    spec = importlib.util.spec_from_file_location("package_scripts", os.path.join(package_dir, "package.py"))
    scripts = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(scripts) # type: ignore
    return scripts

class WrapperFunction(RpycEnum):
    SENDTO = 0x00
    WSA_SENDTO = 0x01
    WSA_CONNECT = 0x02
    CONNECT = 0x03
    RECVFROM = 0x04
    WSA_RECVFROM = 0x05
    ACCEPT = 0x06
    WSA_ACCEPT = 0x07

    def outgoing(self) -> bool:
        if self == WrapperFunction.SENDTO: return True
        if self == WrapperFunction.WSA_SENDTO: return True
        if self == WrapperFunction.CONNECT: return True
        if self == WrapperFunction.WSA_CONNECT: return True
        return False
    
    def incoming(self) -> bool:
        if self == WrapperFunction.RECVFROM: return True
        if self == WrapperFunction.WSA_RECVFROM: return True
        if self == WrapperFunction.CONNECT: return True
        if self == WrapperFunction.WSA_CONNECT: return True
        return False

    def verbose(self):
        return self.name.lower()

# A class used for opening the memory mapped IPC files
# and receiving/replying messages.
class IpcServer:
    def __init__(self, ipc_file_path):
        self.wrapper_callback = lambda pid, ip, port, function: (ip, port)
        self.ipc_file_path = ipc_file_path
        self.buffers = {}
        self.fds = {}

    def set_resend_callbacks(self):
        self.wrapper_callback = lambda *args: None

    def set_nop_callbacks(self):
        self.wrapper_callback = lambda pid, ip, port, function: (ip, port)

    def set_redirect_callback(self, callback: Callable[[int, WrapperFunction, IPv4Address, int], Optional[bool]]):
        self.redirect_callback = callback

    def __find_new_ipc_files(self):
        for file in glob.glob(self.ipc_file_path + '.*'):
            pid = int(file.split('.')[-1])
            if pid not in self.buffers:
                print(f"OPEN({pid})")
                self.fds[pid] = os.open(file, os.O_RDWR)
                self.buffers[pid] = mmap.mmap(self.fds[pid], 128, access=mmap.ACCESS_WRITE)

    def __check_open_buffers(self):
        pids_to_close = []
        did_something = False
        for (pid, buffer) in self.buffers.items():
            # When the state indicates a message sent by the pintool
            if buffer[0] == 0x01:
                print(f"IN({pid}):\t{buffer[:].hex()}")
                handled = self.__handle_msg(pid)
                did_something = True
                # Make the state byte indicate that the server
                # has sent a reply
                if handled:
                    buffer[0] = 0x02
                else:
                    buffer[0] = 0x03
                print(f"OUT({pid}):\t{buffer[:].hex()}")
            elif buffer[0] == 0xff:
                pids_to_close.append(pid)
        for pid in pids_to_close:
            print(f"CLOSE({pid})")
            self.buffers[pid].close()
            os.close(self.fds[pid])
            del self.buffers[pid]
            del self.fds[pid]
            os.remove(self.ipc_file_path + '.' + str(pid))
        return did_something

    def listen(self, timeout, find_new_interval=1000) -> Tuple[int, bool]:
        until = time.time() + timeout
        self.__find_new_ipc_files()

        i = 0
        while time.time() < until and len(self.buffers) != 0:
            if self.__check_open_buffers():
                return (len(self.buffers), True)
            i += 1
            if i == find_new_interval:
                self.__find_new_ipc_files()
                i = 0
        return (len(self.buffers), False)

    def __try_callback(self, wrapper, callback, pid, name):
        if callback is None:
            raise RuntimeError(f"No callback for {name}")
        else:
            return wrapper(pid)

    def __handle_msg(self, pid):
        # The second byte of the message sent by the pintool
        # indicates the message type. Do a case distinction 
        # over all known message types...
        buffer = self.buffers[pid]
        msg_type = buffer[1]
        if msg_type == 0x01:
            return self.__try_callback(self.__handle_redirect_msg, self.redirect_callback, pid, "redirect_callback")
        else:
            raise RuntimeError(f"Unknown Message Type: {hex(msg_type)}")

    def __handle_redirect_msg(self, pid):
        # Decode the message and call the callback
        buffer = self.buffers[pid]
        msg = buffer[2:9] # Cut off state and msg type
        call_type = WrapperFunction(msg[0])
        ip = ipaddress.IPv4Address(f'{msg[1]}.{msg[2]}.{msg[3]}.{msg[4]}')
        port = (msg[5] << 8) | msg[6]

        reply = self.redirect_callback(pid, call_type, ip, port)
        if reply is None:
            return False

        return True

# Object used for downloading a tarball
# in chunks.
class TarFileDownload:
    def __init__(self, source, regex=None):
        self._done = False
        self.file = tempfile.NamedTemporaryFile()
        filter_function = None
        if regex is not None:
            def filter_function_impl(tar_info):
                name = tar_info.name
                if re.search(regex, name) is not None:
                    return tar_info
                else: return None
            filter_function = filter_function_impl
        with tempfile.TemporaryDirectory() as folder:
            dir_util.copy_tree(source, folder)
            tar = tarfile.TarFile(fileobj=self.file, mode='w')
            tar.add(folder, arcname='.', filter=filter_function)
        tar.close()
        self.file.seek(0)

    def exposed_read(self, n):
        return self.file.read(n)

    def exposed_finish(self):
        self.file.close()
        self._done = True

    def _is_done(self):
        return self._done

# Object used for uploading a tarball
# in chunks.
class TarFileUpload:
    def __init__(self, extract_to):
        self.extract_to = extract_to
        self._done = False
        self.file = tempfile.TemporaryFile()

    def exposed_write(self, b):
        self.file.write(b)

    def exposed_finish(self):
        self.file.seek(0)
        tar = tarfile.TarFile(fileobj=self.file)
        tar.extractall(self.extract_to)
        tar.close()
        self.file.close()
        self._done = True

    def _is_done(self):
        return self._done


class AgentService(rpyc.Service):
    initialized: bool = False
    working_dir: Optional[tempfile.TemporaryDirectory] = None
    package_dir: str = ""
    output_dir: str = ""
    package_dir_transfer: Optional[TarFileUpload] = None
    dumpcap_process = None
    ipc_server = None

    def on_connect(self, conn):
        # Only one connection can be active at a time.
        self.was_lock_acquired = lock.acquire(blocking=False)
        if not self.was_lock_acquired:
            conn.close()
            return
        print("!! Connected")
        if AgentService.initialized: return

        # Set up directories...
        AgentService.working_dir = tempfile.TemporaryDirectory()
        print(f"Working directory: {AgentService.working_dir.name}")
        AgentService.package_dir = os.path.join(AgentService.working_dir.name, "package")
        os.mkdir(AgentService.package_dir)
        AgentService.output_dir = os.path.join(AgentService.working_dir.name, "output")
        os.mkdir(AgentService.output_dir)

        AgentService.initialized = True
        print("Initialized temporary directory")

    def on_disconnect(self, conn):
        if not self.was_lock_acquired: return
        # When disconnecting, set the PIPC server
        # to use a NOP callback (i.e., all messages
        # will be replied in such a way that there 
        # is no modification happening).
        AgentService.ipc_server.set_nop_callbacks()
        print("!! Disconnected")
        lock.release()

    # Allows uploading an analysis package.
    def exposed_upload_package(self):
        print("=> upload_package")
        if AgentService.package_dir_transfer is not None:
            print("Package already uploaded!")
            raise RuntimeError("Package already uploaded!")
        print(f"Uploading package to {AgentService.package_dir}")
        AgentService.package_dir_transfer = TarFileUpload(AgentService.package_dir)
        return AgentService.package_dir_transfer
    
    def exposed_get_working_dir(self):
        return os.path.abspath(AgentService.working_dir.name)
    
    def exposed_get_package_dir(self):
        return os.path.abspath(AgentService.package_dir)

    def exposed_get_output_dir(self):
        return os.path.abspath(AgentService.output_dir)

    # Allows downloading the puppets output.
    def exposed_download_output(self, regex=None):
        print("=> download_output")
        return TarFileDownload(AgentService.output_dir, regex=regex)

    # Returns the PIPC server (the wrapper).
    def exposed_get_ipc_server(self):
        print("=> get_ipc_server")
        if AgentService.ipc_server is None:
            AgentService.ipc_server = IpcServer(os.path.join(
                AgentService.output_dir, "ipc") # type: ignore
            )
        return AgentService.ipc_server

    # Runs the Pintool with the JSON puppet config
    # given in config.
    def exposed_run_pintool(self, create_text_log=False, trace_images: List[str]=None, trace_non_image=False, max_trace_count: int=0, random_mouse: bool=False, trace_split_limit: int=0, debug: bool=False):
        print("=> run_pintool")

        def mouse_move():
            while True:
                pt = POINT()
                ctypes.windll.user32.GetCursorPos(ctypes.byref(pt)) # type: ignore
                x_offset = random.randint(-40, 40)
                y_offset = random.randint(-40, 40)
                ctypes.windll.user32.SetCursorPos( # type: ignore
                    pt.x + x_offset,
                    pt.y + y_offset
                )
                time.sleep(0.2)
        if random_mouse:
            threading.Thread(target=mouse_move).start()

        scripts = load_package_scripts(AgentService.package_dir)
        pin_args = scripts.get_pin_args() # type: ignore
        tool_args = scripts.get_tool_args() # type: ignore
        suffix = ""
        proc = scripts.pre_pin() # type: ignore
        if isinstance(proc, int):
            pin_args.append(f"-pid {proc}")
        else:
            suffix = f"-- {os.path.join(AgentService.package_dir, proc)}"

        ipc_file = os.path.join(AgentService.output_dir, "ipc")
        text_log_file = os.path.join(AgentService.output_dir, "out.log")
        trace_file = os.path.join(AgentService.output_dir, "trace")
        ins_log_file = os.path.join(AgentService.output_dir, "ins_log")

        if create_text_log: tool_args.append("-o " + text_log_file)
        tool_args.append("-ipc " + ipc_file) 
        tool_args.append("-trace " + trace_file)
        tool_args.append("-ins_log " + ins_log_file)
        if trace_images is not None:
            tool_args.append("-trace_image_filter 1")
            for image in trace_images:
                tool_args.append("-trace_image " + image)
        else:
            tool_args.append("-trace_image_filter 0")
        tool_args.append("-trace_non_image " + ("1" if trace_non_image else "0"))
        tool_args.append("-max_trace_count " + str(max_trace_count))
        tool_args.append("-trace_split " + str(trace_split_limit))
        pin_args.append("-smc_strict 1")
        if debug:
            pin_args.append("-pause_tool 30")

        cmd = f"{PINPATH} {' '.join(pin_args)} -t {PINTOOL} {' '.join(tool_args)} {suffix}"

        print(f"Pintool command: {cmd}")

        privilege_level = scripts.get_privilege_level() # type: ignore
        if privilege_level == 0:
            # run as normal user
            subprocess.Popen(cmd.split(' '))
        elif privilege_level == 1:
            # run with admin privileges
            run_with_uac(cmd.split(' '))
        elif privilege_level == 2:
            # run on session 0 using psexec
            new_cmd = "psexec -i 0 -d " + cmd
            run_with_uac(new_cmd.split(' '))

        scripts.post_pin() # type: ignore

    # Start dumpcap process for creating a packet capture.
    def exposed_start_dumpcap(self):
        print("=> start_dumpcap")
        if AgentService.dumpcap_process is not None:
            raise RuntimeError("A dumpcap process is already running!")
        AgentService.dumpcap_process = subprocess.Popen(
            ["dumpcap", "-i", DUMPIF, "-w", os.path.join(AgentService.output_dir, "dump.pcapng")] # type: ignore
        )
    
    # Dump processes using the pd32.exe. This has a tendency
    # to crash, which is why we return the success status
    # as a boolean.
    def exposed_dump_processes(self):
        print("=> dump_processes")
        files = glob.glob(os.path.join(AgentService.output_dir, "ipc.*")) # type: ignore
        # Find all PIDs instrumented by the Pintool. 
        # This is done using the names of the IPC files.
        pids = []
        for file in files:
            new_pid = int(file.split(".")[-1])
            # Check whether the PID is still running.
            if psutil.pid_exists(new_pid):
                pids.append(new_pid)

        dump_dir = os.path.join(AgentService.output_dir, "dump") # type: ignore
        os.mkdir(dump_dir)

        # Dump every PID
        for pid in pids:
            cmd = f"pd32 -o {dump_dir} -pid {pid}"
            print(cmd)
            try:
                subprocess.run(cmd.split(" "), creationflags=subprocess.CREATE_NO_WINDOW) # type: ignore
            except subprocess.CalledProcessError:
                os.rmdir(dump_dir)
                print("Process dumping failed...")
                return False
        return True

if __name__ == "__main__":
    from rpyc.utils.server import ThreadedServer
    t = ThreadedServer(AgentService, port=12345, protocol_config={
        'allow_public_attrs': True,
    })
    t.start()
