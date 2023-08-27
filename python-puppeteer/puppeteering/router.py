from abc import ABC
from .types import *
import abc
import paramiko

__all__ = [
    "Router",
    "SshIptablesRouter",    
]

# An abstract class representing the router.
class Router(ABC):
    # Create a one-to-one mapping:
    #  - Packets coming from own_ip to orig_ip get
    #    their destination set to new_ip (DNAT).
    #  - Packets coming from new_ip to own_ip get
    #    their source set to orig_ip (SNAT).
    # This method returns a callback function which,
    # when called, reverts the one-to-one map.
    @abc.abstractmethod
    def one_to_one_map(self, own_ip: IPv4Address, orig_ip: IPv4Address, new_ip: IPv4Address, orig_port: Optional[int], new_port: Optional[int]) -> VoidFunction:
        pass

    # Creates rules to block all traffic to own_ip
    # except for traffic over the agent_port (TCP)
    # and traffic coming from/to allow_ip.
    @abc.abstractmethod
    def block(self, own_ip: IPv4Address, allow_ip: IPv4Address, agent_port: int) -> VoidFunction:
        pass

# The router class for a router that is configured using
# SSH and iptables.
class SshIptablesRouter(Router):
    def __init__(self, host: str, username: str, password: str, port: int=22):
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy)
        self.ssh.connect(
            host,
            port=port,
            username=username,
            password=password
        )

    def __del__(self):
        self.ssh.close()

    def one_to_one_map(self, own_ip: IPv4Address, orig_ip: IPv4Address, new_ip: IPv4Address, orig_port: int=None, new_port: int=None) -> VoidFunction:
        commands = []
        if orig_port is not None and new_port is not None:
            commands.append(f"PREROUTING -p tcp -s {str(own_ip)} -d {str(orig_ip)} --dport {orig_port} -j DNAT --to-destination {str(new_ip)}:{new_port}")
            commands.append(f"PREROUTING -p udp -s {str(own_ip)} -d {str(orig_ip)} --dport {orig_port} -j DNAT --to-destination {str(new_ip)}:{new_port}")
            commands.append(f"POSTROUTING -p tcp -s {str(new_ip)} -d {str(own_ip)} --sport {new_port} -j SNAT --to-source {str(orig_ip)}:{new_port}")
            commands.append(f"POSTROUTING -p udp -s {str(new_ip)} -d {str(own_ip)} --sport {new_port} -j SNAT --to-source {str(orig_ip)}:{new_port}")
        commands.append(f"PREROUTING -s {str(own_ip)} -d {str(orig_ip)} -j DNAT --to-destination {str(new_ip)}")
        commands.append(f"POSTROUTING -s {str(new_ip)} -d {str(own_ip)} -j SNAT --to-source {str(orig_ip)}")
        for command in commands:
            self.ssh.exec_command("iptables -t nat -A " + command)
        self.ssh.exec_command("conntrack -F")

        def revert():
            for command in commands:
                self.ssh.exec_command("iptables -t nat -D " + command)
            self.ssh.exec_command("conntrack -F")

        return revert
    
    def block(self, own_ip: IPv4Address, allow_ip: IPv4Address, agent_port: IPv4Address) -> VoidFunction:
        commands = [
            f"iptables -I FORWARD -s {str(allow_ip)} -d {str(own_ip)} -j ACCEPT",
            f"iptables -I FORWARD -s {str(own_ip)} -d {str(allow_ip)} -j ACCEPT",
            f"iptables -I FORWARD -d {str(own_ip)} -p tcp --dport {str(agent_port)} -j ACCEPT",
            f"iptables -I FORWARD -s {str(own_ip)} -p tcp --sport {str(agent_port)} -j ACCEPT",
            f"iptables -I FORWARD -d {str(own_ip)} -j DROP",
            f"iptables -I FORWARD -s {str(own_ip)} -j DROP"
        ]
        for cmd in commands[::-1]:
            self.ssh.exec_command(cmd)
            self.ssh.exec_command("conntrack -F")

        def revert():
            commands = [
                f"iptables -D FORWARD -s {str(allow_ip)} -d {str(own_ip)} -j ACCEPT",
                f"iptables -D FORWARD -s {str(own_ip)} -d {str(allow_ip)} -j ACCEPT",
                f"iptables -D FORWARD -d {str(own_ip)} -p tcp --dport {str(agent_port)} -j ACCEPT",
                f"iptables -D FORWARD -s {str(own_ip)} -p tcp --sport {str(agent_port)} -j ACCEPT",
                f"iptables -D FORWARD -d {str(own_ip)} -j DROP",
                f"iptables -D FORWARD -s {str(own_ip)} -j DROP"
            ]
            for cmd in commands:
                self.ssh.exec_command(cmd)
                self.ssh.exec_command("conntrack -F")
        
        return revert