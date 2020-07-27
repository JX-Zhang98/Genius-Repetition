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
import multiprocessing as mp

o1 = lambda commit: os.path.join("/mnt", "panda", "kernel", "arm64-testcase-new", commit.split('/')[0], "out_dir", "O1", "vmlinux")
o2 = lambda commit: os.path.join("/mnt", "panda", "kernel", "arm64-testcase", commit, "vmlinux")
o3 = lambda commit: os.path.join("/mnt", "panda", "kernel", "arm64-testcase-new", commit.split('/')[0], "out_dir", "O1", "vmlinux")

def get_funcs():
    f = open("../config/func_list")
    funcs = []
    for line in f.readlines():
        func = line.split("\n")[0]
        funcs.append(func)
    return funcs


def get_commits():
    f = open("../config/commit_list")
    commits = []
    for line in f.readlines():
        commit = line.split("\n")[0]
        commits.append(commit)
    return commits


def get_graph(path, func):
    graph = RawFeatureGraph.get_func_cfg(path, func)
    return [path, func, graph]


def get_op_graphs(com, path, func, ty):
    name = ".".join((func, com, ty))
    graph = RawFeatureGraph.get_func_cfg(path, func)

    return [name, graph]


def get_diff_graphs(commit, func, opt):
    # return a vector for each commit
    c = commit.split("/")[0]
    name = ".".join((func, c, opt))
    # path = os.path.join("/mnt", "panda", "kernel", "arm64-testcase", commit, "vmlinux")
    if opt == 'O1':
        optimization = o1
    elif opt == 'O2':
        optimization =  o2
    else:
        optimization = o3
    path = optimization(commit)
    graph = RawFeatureGraph.get_func_cfg(path, func)

    return [name, graph]


def gen_graphs():
    # generate a dataset by ../config/funclist and ../config commitlist

    funcs = get_funcs()[0:10]
    commits = get_commits()[0:10]
    opts = ['O1', 'O2', 'O3']

    a_dict = dict()

    pool = mp.Pool(mp.cpu_count())
    result = [pool.apply_async(get_diff_graphs, args=(committ, func, opt))
                            for committ in commits for func in funcs for opt in opts]
    pool.close()
    ans2 = [p.get() for p in result]


    for an in ans2:
        a_dict[an[0]] = an[1]

    f = open("../all_data_graphs_diff.json", "a+")
    json.dump(a_dict, f)
    f.close()
    '''
    "ion_ioctl.f719ff9bcee2a422647790f12d53d3755f47c727.O2": 
    [[[], [16, 14, 32], 0, 1, 3, 0, 2, 0.23809523809523808], [[], [1], 1, 1, 2, 0, 1, 0.17857142857142855], [[], [30], 0, 0, 1, 0, 1, 0.03571428571428571], [[], [18695, 49160], 5, 1, 14, 0, 2, 0.0], [[], [21, 112], 1, 0, 7, 0, 0, 0.0], [[], [18689, 491^C
    '''
    return a_dict


def gen_data1_graphs(commit):
    graphs = []

    O2_path = os.path.join("/mnt", "panda", "kernel", "arm64-testcase", commit, "vmlinux")

    funcs = get_funcs()

    pool = mp.Pool(mp.cpu_count())

    result = [pool.apply_async(get_graph, args=(O2_path, func)) for func in funcs]

    pool.close()

    ans = [p.get() for p in result]

    a = dict()

    for an in ans:
        func = an[1]
        graph = an[2]
        a[func] = graph

    f = open("../O2_graphs.json", "w")
    json.dump(a, f)

    return ans


def get_Wi(graphs, i):
    wi = []
    m = len(graphs)
    for j in range(m):
        try:
            s = CodebookGenerator.normalized_ACFG_similarity(graphs[i], graphs[j])
        except:
            s = 0
        wi.append(s)
    print(i)
    return [i, wi]


def get_W():
    f = open("../O2_graphs.json", "r")
    a_dict = json.load(f)
    graphs = []
    for graph in a_dict.values():
        graphs.append(graph)

    m = len(graphs)
    # similarity socre matrix
    W_matrix = np.zeros((m, m))

    pool = mp.Pool(mp.cpu_count())
    result = [pool.apply_async(get_Wi, args=(graphs, i))
              for i in range(m)]
    pool.close()
    ans = [p.get() for p in result]

    for an in ans:
        for j in range(m):
            W_matrix[an[0]] = an[1]

    np.save("../data1_W.npy", W_matrix)

    return graphs, W_matrix


def main():
    commit = "e8a732d1bc3ac313e22249c13a153c3fe54aa577/e250c366ecc267a5eaa18e8caa3c938f7e850456"
    # gen_data1_graphs(commit)
    g, w = get_W()
    # print(w)



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

