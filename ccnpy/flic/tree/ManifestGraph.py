#  Copyright 2024 Marc Mosko
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
from dataclasses import dataclass
from typing import List, Optional, Dict, Set

import networkx as nx
from matplotlib import pyplot as plt
from networkx.drawing.nx_agraph import graphviz_layout

from ccnpy.core.DisplayFormatter import DisplayFormatter
from ccnpy.core.HashValue import HashValue
from ccnpy.core.Name import Name
from ccnpy.flic.tlvs.Node import Node


class ManifestGraph:
    """
    Based on manifest structure, generate a graphviz graph

    TODO: Finish graph construction with pygraphviz
    """

    @dataclass
    class EntryRecord:
        is_data: bool
        parent: HashValue
        children: Optional[List[HashValue]] = None

    def __init__(self):
        self._entries: Dict[HashValue, ManifestGraph.EntryRecord] = {}
        self._graph = nx.DiGraph()
        self._not_child: Set[HashValue] = set()
        self._is_child: Set[HashValue] = set()
        self._is_data: Set[str] = set()

    def add_manifest(self, hash_value: HashValue, node: Node, name: Name):
        # self._entries[hash_value] = ManifestGraph.EntryRecord(is_data=False, parent=hash_value, children=[x for x in node.hash_values()])
        if hash_value not in self._is_child:
            self._not_child.add(hash_value)

        parent_name = self._hash_to_name(hash_value)
        for child_hash in node.hash_values():
            self._graph.add_edge(parent_name, self._hash_to_name(child_hash))
            try:
                self._not_child.remove(child_hash)
            except KeyError:
                pass
            self._is_child.add(child_hash)

        if name is not None:
            nx.set_node_attributes(self._graph, {parent_name: name}, "label")

    def add_data(self, data_hash: HashValue):
        # TODO: colorize the nodes so we see which are data
        # self._entries[hash_value] = ManifestGraph.EntryRecord(is_data=True, parent=hash_value)
        self._is_data.add(self._hash_to_name(data_hash))

    def save(self, path):
        """
        Writes a DOT file to the given path.  You can then plot it with a command like
            dot -Tpng -ofoo.png foo.dot
        """
        nx.nx_pydot.write_dot(self._graph, path='tree.dot')

    def _get_color(self, node_name):
        if node_name in self._is_data:
            return 'green'
        return 'blue'

    def plot(self):
        options = {
            "font_size": 9,
            "node_size": 3000,
            "node_color": "white",
            "edgecolors": "black",
            "linewidths": 5,
            "width": 1
        }
        # A = nx.nx_agraph.to_agraph(self._graph)
        # A.layout(prog="dot")
        # A.
        colors=[self._get_color(n) for n in self._graph.nodes]
        pos =  graphviz_layout(self._graph, prog="dot")
        nx.draw_networkx(self._graph, pos, node_color=colors, with_labels=True)
        plt.show()
        # ax = plt.gca()
        # ax.margins(0.20)
        # plt.axis("off")
        # plt.show()

    @staticmethod
    def _hash_to_name(hash_value: HashValue) -> str:
        # only include the first 4 bytes
        return DisplayFormatter.hexlify(hash_value.value())[0:8]
