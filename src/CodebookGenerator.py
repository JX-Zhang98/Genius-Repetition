#!/home/xianglin/.virtualenvs/angr/bin/ python
# -*- coding: utf-8 -*-
__Auther__ = 'xianglin'

INF = 0x3fffffff
EPS = 1e-10

import angr
import capstone
import claripy
from tools.image import Image
from tools.util.asm import is_jump
import numpy as np
from sklearn.cluster import spectral_clustering
from collections import Counter


def jaccard_similarity(a, b):
    """
    calculate the similarity between two consts list, jaccard distance
    Args:
        a(list): a list of string consts
        b(list)
    Returns:
        similarity(float)
    """
    if len(a) == 0 and len(b) == 0:
        return 1.0
    if len(a) == 0 or len(b) == 0:
        return 0.0
    _a = Counter(a)
    _b = Counter(b)
    c = (_a - _b) + (_b - _a)
    intersection = (len(a) + len(b) - sum(c.values())) / 2
    similarity = intersection / (len(a) + len(b) - intersection)
    return similarity


def jaccard_distance(a, b):
    """
        calculate the distance between two consts list, jaccard distance is set to be 1 - jaccard similarity
        Args:
            a(list): a list of string consts
            b(list)
        Returns:
            distance(float)
        """
    similarity  = jaccard_similarity(a, b)
    distance = 1 - similarity
    return distance


def BB_distance(v1, v2):
    """
    calculate the distance between two raw feature vector

    Args:
        v1(list):[str_consts, numeric_consts, trans, call, insts, arithmetic, offspring, betweenness]
        v2(list)

    Returns:
        cost(float)

    """
    alpha = np.array([10.82, 14.47, 6.54, 66.22, 41.37, 55.65, 198.67, 30.66])
    max_a = np.hstack((np.array([1.0, 1.0]), np.maximum(v1[2:], v2[2:])))
    str_d = jaccard_distance(v1[0], v2[0])
    num_d = jaccard_distance(v1[1], v2[1])
    distance_a = np.hstack((np.array([str_d, num_d]),  np.abs(np.array(v1[2:])-np.array(v2[2:]))))
    distance = np.sum(np.multiply(alpha, distance_a)) / np.sum(np.multiply(alpha, max_a))
    return distance


def dfs(now, depth=0):
    global n, m, w, lx, ly, vx, vy, delta, aim
    vx[now] = True
    for i in range(m):
        if not vy[i]:
            if abs(lx[now] + ly[i] - w[now][i]) < EPS:
                vy[i] = True
                if aim[i] == -1 or dfs(aim[i], depth+1):
                    aim[i] = now
                    return True
            else:
                delta = min(lx[now] + ly[i] - w[now][i], delta)
    return False


# max cost match
def km(weight):
    global n, m, w, lx, ly, vx, vy, delta, aim
    n = len(weight)
    m = len(weight[0])
    if n < m:
        transpose = False
        w = [list(line) for line in weight]
    else:
        transpose = True
        n, m = m, n
        w = [[0] * m for _ in range(n)]
        for i in range(n):
            for j in range(m):
                w[i][j] = weight[j][i]

    lx = [0] * n
    ly = [0] * m
    aim = [-1] * m
    for i in range(n):
        lx[i] = max(w[i])

    for k in range(n):
        while True:
            vx = [False] * n
            vy = [False] * m
            delta = INF
            if dfs(k):
                break
            for i in range(n):
                if vx[i]:
                    lx[i] -= delta
            for i in range(m):
                if vy[i]:
                    ly[i] += delta

    match = []
    ans = 0
    for i in range(m):
        if aim[i] != -1:
            ans += w[aim[i]][i]
            if transpose:
                match.append((i, aim[i]))
            else:
                match.append((aim[i], i))
    return ans, match


def count_weight(g1, g2):
    """
    count the weight between two graph
    Args:
        g1(list): a list of raw features vectors
        g2
    Returns:
        weight(matrix):each element is the distance between two nodes in two graph
    """
    weight = []
    for v1 in g1:
        wi = []
        for v2 in g2:
            # to make km suitable for minimum cost generation
            wi.append(-BB_distance(v1, v2))
        weight.append(wi)
    return weight


def ACFG_distance(g1, g2):
    """
    count the distance between two ACFGs
    Args:
        g1(list): a list of raw features vectors
        g2
    Returns:
        cost(float):the minimum cost to match two ACFGs (bipartite graph matching)

    we need to change km algorithm, which is for generate maximum cost, to suit our purpose(minimum cost)
    """
    #
    weight = count_weight(g1, g2)
    ans, match = km(weight)
    return -ans


def ACFG_distance_with_N(g):
    """count the distance between a graph and an empty graph"""
    empty_V = [[], [], 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
    ans = 0
    for v in g:
        ans = ans + BB_distance(v, empty_V)
    return ans


def normalized_ACFG_similarity(g1, g2):
    cost = ACFG_distance(g1, g2)
    cost1 = ACFG_distance_with_N(g1)
    cost2 = ACFG_distance_with_N(g2)
    distance = 1 - cost / max(cost1, cost2)
    return distance


if __name__ == "__main__":
    v1 = [['control/shutdown', ''], [0, 760], 1, 1, 7, 1, 1, 0.00013061650992685477]
    v2 = [[''], [2992], 1, 1, 15, 5, 1, 0.00013061650992685477]
    v3 = [['', '', ''], [0, 2912, 0, 0, 232, 2832], 3, 0, 20, 3, 1, 0.0]
    q = BB_distance(v1, v1)
    j = jaccard_similarity(v1[0], v1[0])
    g1 = [v2, v3]
    g2 = [v1, v3]
    b = ACFG_distance_with_N(g1)
    c = ACFG_distance_with_N(g2)
    d = ACFG_distance(g1, g2)
    a = normalized_ACFG_similarity(g1, g2)
    print(a, b, c, d, end=" ")



