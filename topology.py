import copy
from dataclasses import dataclass, field
from vuln import Vulnerability, VulnerabilityClass, VulnRegistry
from typing import List, Dict, Tuple, Optional, Any
from operator import itemgetter, attrgetter


@dataclass
class Network:
    router: str
    neighboring_routers: List[str] = field(default_factory=list)
    hosts: List['Host'] = field(default_factory=list)

    def __hash__(self):
        return hash(self.router + ''.join(self.neighboring_routers))

@dataclass
class Host:
    ip_addr: str
    vulns: List[Vulnerability] = field(default_factory=list)
    gateway: str = None
    accessible_from_outside: bool = False
    linked_hosts: List['Host'] = field(default_factory=list)

    def __hash__(self):
        return hash(self.ip_addr)

    def __eq__(self, other):
        if not isinstance(other, Host):
            raise ValueError('Can only compare Host objects to each other!')
        return self.ip_addr == other.ip_addr

    @property
    def max_privilege_vulnerability(self) -> Vulnerability:
        return max(
            self.vulns,
            key=attrgetter('type')
        )

    def set_default_gateway(self, networks: List[Network]):
        for net in networks:
            host_list = [host.ip_addr for host in net.hosts]
            if self.ip_addr in list(h.ip_addr for h in net.hosts):
                self.gateway = net.router

    def set_linked_hosts(self, networks: List[Network], hosts: List['Host']):
        my_network = [net for net in networks if self.gateway == net.router][0]
        for net in networks:
            if self in net.hosts:
                for host in net.hosts:
                    if host.ip_addr != self.ip_addr:
                        self.linked_hosts.extend(
                            [h for h in hosts if h.ip_addr == host.ip_addr]
                        )

            if net.router in my_network.neighboring_routers:
                for host in net.hosts:
                    if host.accessible_from_outside:
                        self.linked_hosts.extend(
                            [h for h in hosts if h.ip_addr == host.ip_addr]
                        )
