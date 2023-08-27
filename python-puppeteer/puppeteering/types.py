from typing import Union, Tuple, Optional, Callable, List, Set, Dict, Generator, Any, Iterable
from ipaddress import IPv4Address

HostServiceAddress = Tuple[IPv4Address, int]
VoidFunction = Callable[[], None]
PredicateFunction = Callable[[], bool]