import rpyc
import os
import tempfile
import tarfile
from .types import *
from agent import IpcServer, TarFileDownload, TarFileUpload

TRANSFER_CHUNK_SIZE = 1024**2

__all__ = [
    "AgentConnector",
]

class AgentConnector:
    def __init__(self, address: HostServiceAddress):
        self.address = address
        self.remote = rpyc.connect(str(address[0]), address[1], config={
            # Allow the RPyC client to access all public attributed
            # on the remote side (otherwise ONLY attributes prefixed with
            # exposed_ are accessible).
            'allow_public_attrs': True,
            # Increase the timeout. Dumping processes and downloading 
            # the output (can exceed 3GB) takes a while over 100Mbit ethernet.
            'sync_request_timeout': 60*10,
        })

    def close(self):
        self.remote.close()
        
    # Validate that the file names in a downloaded
    # tarball are valid (e.g., no .. or ~).
    def _validate_tar_names(self, tar: tarfile.TarFile, dst: str) -> None:
        dst_abs = os.path.abspath(dst)
        # For each file in the tarball...
        for name in tar.getnames():
            # Calculate the resulting path (where it would be placed
            # when unpacking the tarball).
            resulting_path = os.path.join(dst, name)
            # Check whether the resulting path is still
            # in the destination directory.
            resulting_path_abs = os.path.abspath(resulting_path)
            if not resulting_path_abs.startswith(dst_abs):
                raise RuntimeError("Invalid name in tar achive")

    # Download a TarFileDownload to dst_folder.
    # TarFileDownload is, for example, returned by 
    # conn.root.download_ouput().
    def _download_folder(self, src_file: TarFileDownload, dst_folder: str) -> None:
        # Create a new temporary file for locally storing
        # the tarball.
        with tempfile.NamedTemporaryFile() as temp:
            # Read from the src_file in chunks.
            # Store the results in the temp file.
            while True:
                data = src_file.read(TRANSFER_CHUNK_SIZE) # type: ignore
                if not data: break
                temp.write(data)
            # Seek to the beginning. Writing has advanced 
            # the cursor.
            temp.seek(0)
            # Interpret the temp file as a tarball.
            tar = tarfile.TarFile(fileobj=temp)
            # Validate the paths in the tarball.
            self._validate_tar_names(tar, dst_folder)
            # Extract all files from the tarball.
            tar.extractall(dst_folder)
            tar.close()
        src_file.finish() # type: ignore

    # Uploads a folder to a opened TarFileUpload.
    # Such a TarFileUpload is, for example, returned
    # by conn.root.upload_package().
    def _upload_folder(self, src_folder: str, dst_file: TarFileUpload) -> None:
        # Create a new temporary file for locally storing
        # the tarball.
        with tempfile.TemporaryFile() as temp:
            tar = tarfile.TarFile(fileobj=temp, mode='w')
            # Add all files in src_folder to the tarball.
            # Don't keep the whole path (arcname='.')
            tar.add(src_folder, arcname='.')
            tar.close()
            # The tar.add operations wrote to the temp file.
            # Seek back to the beginning.
            temp.seek(0)
            while True:
                # Read a chunk from the tarball at a time.
                data = temp.read(TRANSFER_CHUNK_SIZE)
                # Stop when the tarball is fully uploaded.
                if not data: break
                # There is still data available. Upload the
                # chunk that was just read.
                dst_file.write(data) # type: ignore
        dst_file.finish() # type: ignore

    # Downloads the output generated on the agent's machine.
    # If makedirs is true, the dst_folder is first created
    # before downloading.
    def download_output(self, dst_folder: str, makedirs: bool=False) -> None:
        if makedirs:
            try:
                os.makedirs(dst_folder)
            except FileExistsError: pass
        transfer_file = self.remote.root.download_output()
        self._download_folder(transfer_file, dst_folder)

    # Uploads a folder to the package folder on the agent's
    # machine.
    def upload_package(self, src_folder: str) -> None:
        transfer_file = self.remote.root.upload_package()
        self._upload_folder(src_folder, transfer_file)

    def start_dumpcap(self) -> None:
        self.remote.root.start_dumpcap()

    def dump_processes(self) -> bool:
        return self.remote.root.dump_processes()

    def run_pintool(self, create_text_log=False,
            trace_images: List[str]=None, trace_non_image=False,
            max_trace_count: int=0, random_mouse=False,
            trace_split_limit: int=0, debug: bool=False) -> None:
        self.remote.root.run_pintool(
            create_text_log=create_text_log,
            trace_images=trace_images,
            trace_non_image=trace_non_image,
            max_trace_count=max_trace_count,
            random_mouse=random_mouse,
            trace_split_limit=trace_split_limit,
        )

    def get_ipc_server(self) -> IpcServer:
        return self.remote.root.get_ipc_server()