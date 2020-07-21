#!/home/xianglin/.virtualenvs/angr/bin/ python
# -*- coding: utf-8 -*-
__Auther__ = 'xianglin', 'Zhang_JX'


import angr
import capstone
import claripy
from tools.image import Image
from tools.util.asm import is_jump
import numpy as np
from sklearn.cluster import spectral_clustering
from sklearn.metrics import jaccard_score
import CodebookGenerator
import RawFeatureGraph
import os
import json


def processing_grouping(res, matrix): # grouping res and similarity matrix
    # return center for each group
    center = []
    # for each group, find the one that is most similar to other points
    for group in res:
        now_center = group[0]
        now_sim = -1
        for inner_center in group:
            inner_similarity_sum = 0
            for other in group:
                inner_similarity_sum += matrix[inner_center, other]
            if inner_similarity_sum > now_sim:
                now_sim = inner_similarity_sum
                now_center = inner_center
        center.append(now_center)
    return center


def gen_codebook(graphs, W_matrix, group_num=16):
    m = len(W_matrix)
    res = spectral_clustering(W_matrix, n_clusters=group_num)
    group_res = []
    for i in range(group_num):
        group_res.append([])
    for i in range(m):
        group_res[res[i]].append(i)
    centers = processing_grouping(group_res, W_matrix)
    codebook = []
    for i in centers:
        codebook.append(graphs[i])
    return codebook


def get_func():
    f = open("/home/codesim/xl/config/func_list")
    funcs = []
    for line in f.readlines():
        func = line.split("\n")[0]
        funcs.append(func)
    return funcs


def get_graphs():
    f = open("../graphs.json", "r")
    a_dict = json.load(f)
    graphs = []
    for graph in a_dict.values():
        graphs.append(graph)
    return graphs


def get_W():
    w = np.load("../data_W.npy")
    return w


def main():
    graphs = get_graphs()
    W = get_W()
    codebook = gen_codebook(graphs, W, group_num=16)
    code_dict = dict()
    for i in range(len(codebook)):
        code_dict[i] = codebook[i]
    with open("../codebook.json", "w") as f:
        json.dump(code_dict, f)


if __name__ == "__main__":
    # debug_vmlinux = "../testcase/2423496af35d94a87156b063ea5cedffc10a70a1/vmlinux"
    # img = Image(debug_vmlinux)
    # funcs = img.funcs
    # graphs = []
    # for i in range(32):
    #     func = funcs.pop()
    #     graphs.append(RawFeatureGraph.get_func_cfg(debug_vmlinux, func))
    # print(graphs)
    # graphs = codebook.codebook8
    # codebook = gen_codebook(graphs, group_num=8)
    # print(codebook)
    main()

