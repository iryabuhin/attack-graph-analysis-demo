import collections
from typing import List, Generator, Dict
from vuln import VulnRegistry, Vulnerability, VulnerabilityClass
from topology import Host, Network


class Parser:
    @staticmethod
    def parse_vulnerabilities(filename: str) -> Generator[Vulnerability, None, None]:
        """
        Generator that yields instances of Vulnerability after parsing a file
        :param str filename: Path to vulns file
        :return:
        """
        with open(filename, 'r') as f:
            for line in f.readlines():
                name, level = [part.strip() for part in line.split(':')]
                try:
                    yield Vulnerability(name.strip(), VulnerabilityClass[level.strip()])
                except KeyError:
                    raise ValueError(f'Vulnerability class with name "{level}" does not exist!')

    @staticmethod
    def parse_hosts_file(filename: str) -> List[Host]:
        with open(filename, 'r+') as f:
            nodes = list()
            for line in f.readlines():
                line = line.strip('\n')
                if not line:
                    continue

                ip, vuln_str = line.split(':')

                ip = ip.strip()
                vulns = [v.strip() for v in vuln_str.split(',')]

                host = Host(ip, vulns=vulns)
                nodes.append(host)
        return nodes

    @staticmethod
    def parse_topology_file(filename: str) -> List[Network]:
        networks = list()
        with open(filename, 'r+') as f:
            current_network = None
            for line in f:
                line = line.rstrip('\n').strip()

                if line.endswith(':'):
                    current_network = Network(router=line.rstrip(':').rstrip())
                    networks.append(current_network)
                    continue

                if line.startswith('>'):
                    router_ip = line.lstrip('>').strip()
                    current_network.neighboring_routers.append(router_ip)

                if line[0] in '+-':
                    sign = line[0]
                    host_ip = line[1:].strip()

                    host = Host(host_ip)
                    if sign == '+':
                        host.accessible_from_outside = True
                    current_network.hosts.append(host)
            # networks.append(current_network)
        return networks
