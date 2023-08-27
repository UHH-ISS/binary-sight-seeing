from abc import ABC, abstractmethod
from dataclasses import dataclass
import enum
#from ..auto_puppeteer import AutoPuppeteer
from ..types import *

__all__ = [
    "Poi",
    "PoiExtractor",
]

@dataclass
class Poi:
    class PoiType(str, enum.Enum):
        # This works:
        # https://hultner.se/quickbits/2018-03-12-python-json-serializable-enum.html
        IP: str = "IP" # type: ignore
        PORT: str = "PORT" # type: ignore
    poi_type: PoiType
    address: int
    extractor: str
    details: str
    confidence_score: Optional[float]

class PoiExtractor(ABC):
    @abstractmethod
    def __init__(self, auto_puppeteer, data_path: str, cores: int):
        pass

    @abstractmethod
    def extract_ips(self, data_path: str) -> Dict[HostServiceAddress, List[Poi]]:
        pass

    @abstractmethod
    def get_pois(self) -> Iterable[Poi]:
        pass

    @property
    @abstractmethod
    def NAME(self) -> str:
        pass