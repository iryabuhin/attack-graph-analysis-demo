import itertools
import igraph
import os
import collections
from typing import Dict, List, Optional, Generator

import util
from vuln import VulnRegistry, Vulnerability, VulnerabilityClass
from topology import Host, Network
from parse import Parser


HOSTS_FILE_NAME = 'hosts.txt'
TOPOLOGY_FILE_NAME = 'topology.txt'
VULNS_FILE_NAME = 'vulns.txt'


class ReachabilityMatrix:
    nodes: List[str]
    matrix: Dict[str, Dict[str, int]]

    def __init__(self, node_list: List[str]) -> None:
        self.nodes = node_list
        self.matrix = {}
        for node in node_list:
            self.matrix[node] = dict()
            self.matrix[node][node] = collections.defaultdict(int)

    def is_reachable(self, a: str, b: str) -> bool:
        return bool(self.matrix[a][b])

    def get_reachable_hosts(self, host: str) -> List[str]:
        rv = list()
        for host, reachable in self.matrix[host].items():
            if reachable:
                rv.append(host)
        return rv


class AttackGraph:
    G: igraph.Graph
    networks: List[Network]
    hosts: List[Host]

    def __init__(
            self,
            graph: igraph.Graph,
            networks: List['Network'],
            hosts: List['Host']
    ) -> None:
        self.G = graph
        self.networks = networks
        self.hosts = hosts

    def generate_attack_paths(self, initial_host: Host) -> List[Host]:
        visited = set()
        stack = [initial_host]
        path = []

        while stack:
            v = stack.pop()

            if v in visited:
                continue

            visited.add(v)

            if not any(vuln.type >= VulnerabilityClass.user for vuln in v.vulns):
                continue

            path.append(v)

            for linked_host in v.linked_hosts:
                stack.append(linked_host)

        return path

    def get_attack_graph_edges(self, initial_host: Host) -> Generator[Host, None, None]:
        visited = set()
        stack = [initial_host]
        prev = None
        while stack:
            v = stack.pop()

            if v in visited:
                continue

            visited.add(v)

            if not any(vuln.type >= VulnerabilityClass.user for vuln in v.vulns):
                continue

            yield prev, v

            for host in v.linked_hosts:
                yield v, host

            for linked_host in v.linked_hosts:
                stack.append(linked_host)


if __name__ == '__main__':
    hosts = Parser.parse_hosts_file(HOSTS_FILE_NAME)

    print('Обработка файла с уязвимостями...')

    for vulnerability in Parser.parse_vulnerabilities(VULNS_FILE_NAME):
        VulnRegistry.add(vulnerability.name, vulnerability)

    for host in hosts:
        vulns_list = list()
        for vuln_name in host.vulns:
            vuln_obj = VulnRegistry.get(vuln_name)
            if vuln_obj is None:
                raise ValueError(f'Unknown vulnerability identifier "{vuln_name}"!')
            vulns_list.append(vuln_obj)
        host.vulns.clear()
        for v in vulns_list:
            host.vulns.append(v)

    networks = Parser.parse_topology_file(TOPOLOGY_FILE_NAME)

    print('Обработка файла сетевой топологии...')

    for host in hosts:
        host.set_default_gateway(networks)
        host.set_linked_hosts(networks, hosts)


    G = igraph.Graph(directed=True)

    print('Построение графа сети...')

    for host in hosts:
        G.add_vertex(host.ip_addr)

    for host in hosts:
        for linked_host in host.linked_hosts:
            G.add_edge(host.ip_addr, linked_host.ip_addr)

    G = util.set_graph__display_attributes(G)

    A = AttackGraph(G, networks, hosts)

    initial_host = input('Введите IP-дарес начальной вершины: ')
    while not initial_host in [h.ip_addr for h in hosts]:
        print('Хост с таким адресом не найден в файле сетевой топологии!')
        print('Попробуйте еще раз')
        initial_host = input('> ')

    print('Обход графа...')

    count = 0
    initial_host = [h for h in hosts if h.ip_addr == initial_host][0]
    for parent, child in A.get_attack_graph_edges(initial_host):
        if parent is None or parent.ip_addr == child.ip_addr:
            G.vs.find(name_eq=child.ip_addr)['color'] = 'yellow'
            continue
        eid = G.get_eid(parent.ip_addr, child.ip_addr)
        G.es[eid]['width'] *= 3
        G.es[eid]['color'] = 'purple'
        G.es[eid]['arrow_size'] = 1.2
        target = G.es[eid].target_vertex
        source = G.es[eid].source_vertex
        source['color'] = 'red'
        target['color'] = 'red'

        count += 1
        util.save_graph(G, layout_name='kk', filename=f'img/gif/kk_{str(count)}.png')

    # util.make_gif_from_plots()

    print('Сохранение результатов...')

    for layout_name in ['grid', 'star', 'circle', 'kk', 'grid_fr', 'drl']:
        util.save_graph(G, layout_name=layout_name)