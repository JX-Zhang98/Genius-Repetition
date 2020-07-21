#!/home/xianglin/.virtualenvs/angr/bin/ python
# -*- coding: utf-8 -*-
__Auther__ = 'xianglin'

import angr
import networkx as nx
import NumericFeatureExtractor
import capstone
# from NumericFeatureExtractor import *
from tools.image import Image
from tools.util.asm import is_jump


class RawFeatureGraph:
    """a graph to extract raw features of a cfg

    Attributes:
        img(tools.image.Image)
        func_name(string)
        old_cfg
        g(networkx.Digraph)
        entry(int): entry addr
    """
    def __init__(self, func_name, img, entry):
        self.img = img
        self.func_name = func_name
        self.old_cfg = self.img.get_cfg(func_name)
        self.g = nx.DiGraph()
        self.entry = entry
        self.init_graph()

    def __len__(self):
        return len(self.g)

    def init_graph(self):
        """init all property for raw feature graph"""
        self.old_cfg.normalize()
        # add all nodes and edges to graph
        print("start to init graph...")
        for n in self.old_cfg.nodes():
            if n.function_address == self.entry:
                if n.block is not None:
                    self.g.add_node(n.block)
                    print("add {} block to graph...".format(hex(n.addr)))
                    succ = n.successors
                    for offs in succ:
                        if offs.block is not None:
                            self.g.add_edge(n.block, offs.block)
        # add all features to every node
        betweenness = nx.betweenness_centrality(self.g)
        print("start to add properties to all blocks...")
        for node in self.g.nodes():
            string_consts, num_consts = NumericFeatureExtractor.get_BB_consts(self.img, node)
            self.g.nodes[node]['str_consts'] = string_consts
            self.g.nodes[node]['num_consts'] = num_consts
            self.g.nodes[node]['call_insts'] = NumericFeatureExtractor.cal_call_insts(node)
            self.g.nodes[node]['trans_insts'] = NumericFeatureExtractor.cal_transfer_insts(node)
            self.g.nodes[node]['insts'] = NumericFeatureExtractor.cal_insts(node)
            self.g.nodes[node]['arithmetic_insts'] = NumericFeatureExtractor.cal_arithmetic_insts(node)
            self.g.nodes[node]['betweenness'] = betweenness[node]
            self.g.nodes[node]['offs'] = self.g.out_degree(node)
        print("init graph successfully...")

    def feature_vec(self, block):
        """retrive raw feature vector"""
        feature_vec = []
        # 0 string consts 10.82
        feature_vec.append(self.g.nodes[block]['str_consts'])
        # 1 numeric consts 14.47
        feature_vec.append(self.g.nodes[block]['num_consts'])
        # 2 transfer instruction num 6.54
        feature_vec.append(self.g.nodes[block]['trans_insts'])
        # 3 call instruction num 66.22
        feature_vec.append(self.g.nodes[block]['call_insts'])
        # 4 instruction num 41.37
        feature_vec.append(self.g.nodes[block]['insts'])
        # 5 arithmetic instruction num 55.65
        feature_vec.append(self.g.nodes[block]['arithmetic_insts'])
        # 6 offspring num 198.67
        feature_vec.append(self.g.nodes[block]['offs'])
        # 7 betweenness 30.66
        feature_vec.append(self.g.nodes[block]['betweenness'])
        return feature_vec

    @property
    def graph(self):
        """the networkx graph of cfg"""
        return self.g


def get_func_cfg(path, func_name):
    """get the raw features vector of a function"""
    img = Image(path)
    entry_base = img.get_symbol_addr(func_name)
    features = []
    if not entry_base:
        print("not entry base!")
        return
    gra = RawFeatureGraph(func_name, img, entry_base)
    for node in gra.graph.nodes():
        features.append(gra.feature_vec(node))
    return features

def main():
    debug_vmlinux = "../testcase/2423496af35d94a87156b063ea5cedffc10a70a1/vmlinux"
    # debug_vmlinux="../testcase/x86_add"
    # debug_vmlinux = "/home/xianglin/Graduation/executables/x64_a"
    img = Image(debug_vmlinux)
    # func_name = "dccp_rcv_state_process"
    func_name = "show_stat"
    entry_base = img.get_symbol_addr(func_name)
    f = []
    if not entry_base:
        return
    gra = RawFeatureGraph(func_name, img, entry_base)
    for node in gra.graph.nodes():
        node.pp()
        print(gra.feature_vec(node))
        f.append(gra.feature_vec(node))


if __name__ == "__main__":
    main()
