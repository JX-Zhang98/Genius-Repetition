#!/home/xianglin/.virtualenvs/angr/bin/ python
# -*- coding: utf-8 -*-
__Auther__ = 'xianglin'


import angr
import capstone
import claripy
from tools.image import Image
from tools.util.asm import is_jump
import numpy as np
from sklearn.cluster import spectral_clustering
from sklearn.metrics import jaccard_score
import CodebookGenerator
import heapq
import os
import RawFeatureGraph
import json
import multiprocessing as mp
import signal


def signal_handler(signum, frame):
    raise Exception("Timed out!")


def feature_encode(name, graph, cb, codebook_dim=16, nn=10):
    """encode raw feature vector to high-level numeric vector"""
    signal.signal(signal.SIGALRM, signal_handler)
    signal.alarm(600)
    scores = [0 for i in range(codebook_dim)]
    scores_h = []
    for i in range(len(cb)):
        try:
            score = CodebookGenerator.normalized_ACFG_similarity(graph, cb[i])
        except Exception:
            score = -1
        heapq.heappush(scores_h, (score, i))
    # pop codebook_dim - nn elements
    for i in range(codebook_dim - nn):
        heapq.heappop(scores_h)
    while len(scores_h) > 0:
        score, index = heapq.heappop(scores_h)
        scores[index] = score

    a_file = open("../fVec.json", "r")
    json_object = json.load(a_file)
    a_file.close()

    json_object[name] = scores

    a_file = open("../fVec.json", "w")
    json.dump(json_object, a_file)
    a_file.close()
    print(name, scores)
    return [name, scores]


def ACFG_sim(i, j, g1, g2):
    if g1 is None or g2 is None or g1 == [] or g2 == []:
        score = -1
    else:
        score = CodebookGenerator.normalized_ACFG_similarity(g1, g2)
    print(i, j, score)
    return score


def get_funcs():
    f = open("/home/codesim/xl/config/func_list")
    funcs = []
    for line in f.readlines():
        func = line.split("\n")[0]
        funcs.append(func)
    return funcs


def get_commits():
    f = open("/home/codesim/xl/config/commit_list")
    commits = []
    for line in f.readlines():
        commit = line.split("/")[0]
        commits.append(commit)
    return commits


def op(com, path, func, ty):
    name = ".".join((func, com, ty))
    try:
        graph = RawFeatureGraph.get_func_cfg(path, func)
        fvector = feature_encode(graph, codebook, codebook_dim=16, nn=10)
    except:
        fvector = [0 for i in range(16)]
    return [name, fvector]


def diff_commits(commit, func):

    c = commit.split("/")[0]
    name = ".".join((func, c, "O2"))
    path = os.path.join("/mnt", "panda", "kernel", "arm64-testcase", commit, "vmlinux")
    try:
        graph = RawFeatureGraph.get_func_cfg(path, func)
        fvector = feature_encode(graph, codebook, codebook_dim=16, nn=10)
    except:
        fvector = [0 for i in range(16)]
    return [name, fvector]


def main():
    # commit = "e8a732d1bc3ac313e22249c13a153c3fe54aa577/e250c366ecc267a5eaa18e8caa3c938f7e850456"
    # com = "e8a732d1bc3ac313e22249c13a153c3fe54aa577"
    # O2_path = os.path.join("/mnt", "panda", "kernel", "arm64-testcase", commit, "vmlinux")
    # commit_path = commit.split("/")[0]
    # O1_path = os.path.join("/mnt", "panda", "kernel", "arm64-testcase-new", commit_path, "out_dir", "O1", "vmlinux")
    # O3_path = os.path.join("/mnt", "panda", "kernel", "arm64-testcase-new", commit_path, "out_dir", "O3", "vmlinux")
    # Os_path = os.path.join("/mnt", "panda", "kernel", "arm64-testcase-new", commit_path, "out_dir", "Os", "vmlinux")
    # paths = [O1_path, O2_path, O3_path, Os_path]
    # path_ty = ["O1", "O2", "O3", "Os"]
    # funcs = get_funcs()
    # commits = get_commits()

    f = open("../codebook.json")
    cb = json.load(f)
    codebook = []
    for i in range(len(cb.keys())):
        codebook.append(cb[str(i)])

    f = open("../all_data_graphs.json")
    all_data = json.load(f)

    a_dict = dict()

    pool = mp.Pool(mp.cpu_count())
    result = [pool.apply_async(feature_encode, args=(graph, all_data[graph], codebook)) for graph in all_data.keys()]
    pool.close()
    ans1 = [p.get() for p in result]

    # pool = mp.Pool(mp.cpu_count())
    # result = [pool.apply_async(diff_commits, args=(committ, func)) for committ in commits for func in funcs]
    # pool.close()
    # ans2 = [p.get() for p in result]

    # # diff_optimizaiton
    # for i in range(len(paths)):
    #     for func in funcs:
    #         name = ".".join((func, com, path_ty[i]))
    #         try:
    #             graph = RawFeatureGraph.get_func_cfg(paths[i],func)
    #             fvector = feature_encode(graph, codebook, codebook_dim=16, nn=10)
    #         except Exception:
    #             fvector = [0 for j in range(len(codebook))]
    #         a_dict[name] = fvector
    #
    # # diff_commits
    # commits = get_commits()
    #
    # for commit in commits:
    #      for func in funcs:
    #          c = commit.split("/")[0]
    #          name = ".".join((func, c, "O2"))
    #          path = os.path.join("/mnt", "panda", "kernel", "arm64-testcase", commit, "vmlinux")
    #          try:
    #              graph = RawFeatureGraph.get_func_cfg(path, func)
    #              fvector = feature_encode(graph, codebook, codebook_dim=16, nn=10)
    #          except Exception:
    #              fvector = [0 for j in range(len(codebook))]
    #          a_dict[name] = fvector

    # for an in ans1:
    #     a_dict[an[0]] = an[1]
    #
    # f = open("../fVec.json", "w")
    # json.dump(a_dict, f)


if __name__ == "__main__":
    # f = open("../codebook.json")
    # cb = json.load(f)
    # codebook = []
    # for i in range(len(cb.keys())):
    #     codebook.append(cb[str(i)])
    #
    # f = open("../all_data_graphs.json")
    # all_data = json.load(f)
    #
    # pool = mp.Pool(mp.cpu_count())
    # result = [pool.apply_async(ACFG_sim, args=(graph, i, all_data[graph], codebook[i])) for graph in all_data.keys() for i in range(len(codebook))]
    # pool.close()
    # ans1 = [p.get() for p in result]
    main()



