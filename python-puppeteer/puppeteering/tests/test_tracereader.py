from enum import unique
from os import terminal_size
from puppeteering.trace_reader import get_tracelines
import ipaddress


def print_socket_tracelines():
    tracelines = get_tracelines("./puppeteering/tests/local_data", parse_glob=True)
    
    for tl in tracelines:
        if tl.type == tl.type.SOCKET_ENTRY:
            print("Socket Entry", tl.destination_ip, tl)

    
print_socket_tracelines()