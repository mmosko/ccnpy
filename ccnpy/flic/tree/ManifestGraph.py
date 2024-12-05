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
from ccnpy.core.Name import Name, NameComponent
from ccnpy.flic.tlvs.Node import Node


class ManifestGraph:
    """
    Based on manifest structure, generate a graphviz graph

    TODO: Finish graph construction with pygraphviz
    """

    _DATA_SIZE = 1000
    _DATA_SHAPE = 'o'
    _MANIFEST_SIZE = 1000
    _MANIFEST_SHAPE = 's'
    _FONT_SIZE = 9

    @dataclass
    class EntryRecord:
        is_data: bool
        parent: HashValue
        parent_name: Optional[str] = None
        children: Optional[List[HashValue]] = None

    def __init__(self):
        self._entries: Dict[HashValue, ManifestGraph.EntryRecord] = {}
        self._graph = None
        self._not_child: Set[HashValue] = set()
        self._is_child: Set[HashValue] = set()
        self._is_data: Set[str] = set()
        self._paused = False

    def _invalidate_graph(self):
        self._graph = None

    def pause(self):
        """Stop adding to the graph"""
        self._paused = True
    def resume(self):
        """Resume adding to the graph"""
        self._paused = False

    @classmethod
    def _label_from_name(cls, hash_value: HashValue, name: Name):
        if name is not None:
            last_segment = name.component(name.count()-1)
            if last_segment.type() in [NameComponent.manifest_id_type(), NameComponent.chunk_id_type()]:
                return str(last_segment.value_as_number())
            else:
                return name.as_uri()
        return cls._hash_to_name(hash_value)

    def add_manifest(self, hash_value: HashValue, node: Node, name: Optional[Name]):
        if self._paused:
            return

        self._invalidate_graph()
        children = [x for x in node.hash_values()]
        parent_name = self._label_from_name(hash_value, name)
        self._entries[hash_value] = ManifestGraph.EntryRecord(
            is_data=False,
            parent=hash_value,
            parent_name=parent_name,
            children=children)

    def add_data(self, data_hash: HashValue, name: Optional[Name]):
        if self._paused:
            return
        self._invalidate_graph()
        parent_name = self._label_from_name(data_hash, name)
        self._entries[data_hash] = ManifestGraph.EntryRecord(
            is_data=True,
            parent=data_hash,
            parent_name=parent_name,
            children=[])

    def save(self, path):
        """
        Writes a DOT file to the given path.  You can then plot it with a command like
            dot -Tpng -ofoo.png foo.dot
        """
        if self._graph is None:
            self._create_graph()
        nx.nx_pydot.write_dot(self._graph, path=path)
    #
    # def _get_color(self, node_name):
    #     if node_name in self._is_data:
    #         return 'green'
    #     return 'blue'

    def _create_graph(self):
        self._graph = nx.DiGraph()
        for entry in self._entries.values():
            entry_name = self._hash_to_name(entry.parent)
            if entry.is_data:
                options = {
                    'color': 'green',
                    'size': self._DATA_SIZE,
                    'shape': self._DATA_SHAPE,
                    'label': entry.parent_name
                }
            else:
                options = {
                    'color': 'blue',
                    'size': self._MANIFEST_SIZE,
                    'shape': self._MANIFEST_SHAPE,
                    'label': entry.parent_name
                }
            self._graph.add_node(entry_name, **options)
            for child_hash in entry.children:
                child_name = self._hash_to_name(child_hash)
                self._graph.add_edge(entry_name, child_name, weight=0.2)

    def plot(self):
        if self._graph is None:
            self._create_graph()

        # options = {
        #     "font_size": 9,
        #     "node_size": 3000,
        #     "node_color": "white",
        #     "edgecolors": "black",
        #     "linewidths": 5,
        #     "width": 1
        # }
        # options = {
        #     "font_size": 9,
        #     "node_size": 3000,
        #     "edgecolors": "black",
        # }
        # colors=[self._get_color(n) for n in self._graph.nodes]
        # pos =  graphviz_layout(self._graph, prog="dot")
        # nx.draw_networkx(self._graph, pos, node_color=colors, with_labels=True)
        # plt.show()
        # ax = plt.gca()
        # ax.margins(0.20)
        # plt.axis("off")
        # plt.show()

        nodes = self._graph.nodes(data=True)
        for x in nodes:
            print(x)

        colors=[n[1]['color'] for n in nodes]
        pos = graphviz_layout(self._graph, prog="dot", args="-Gsplines=curved")
        labels = dict((n[0], '\n\n\n%r' % n[1]['label']) for n in nodes)

        nx.draw_networkx(self._graph, pos,
                         node_color=colors, with_labels=True, node_shape='s', node_size=300,
                         alpha=0.4,
                         font_size=10,
                         font_weight='bold',
                         labels=labels)
        # nx.draw_networkx_nodes()

        # Draw the edges between the nodes and label them
        nx.draw_networkx_edges(self._graph, pos)
        nx.draw_networkx_labels(self._graph, pos)

        plt.show()

    @staticmethod
    def _hash_to_name(hash_value: HashValue) -> str:
        # only include the first 4 bytes
        name = DisplayFormatter.hexlify(hash_value.value())[0:8]
        return name
