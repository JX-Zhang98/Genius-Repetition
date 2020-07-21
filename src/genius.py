#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
import CodebookGenerator
import gen_dataset
import multiprocessing as mp 
import signal 
import time
import json
import glob

def signal_handler(signum, frame):
    raise Exception("Timed out!")

def compare_two_func(commit1, opt1, func1, commit2, opt2, func2):
    # search in database directly
    signal.signal(signal.SIGALRM, signal_handler)
    signal.alarm(600)
    dataset_file = open('../all_data_graphs_diff.json', 'r')
    '''
    "ion_ioctl.f719ff9bcee2a422647790f12d53d3755f47c727.O2": 
    [[[], [16, 14, 32], 0, 1, 3, 0, 2, 0.23809523809523808], [[], [1], 1, 1, 2, 0, 1, 0.17857142857142855], [[], [30], 0, 0, 1, 0, 1, 0.03571428571428571], [[], [18695, 49160], 5, 1, 14, 0, 2, 0.0], [[], [21, 112], 1, 0, 7, 0, 0, 0.0], [[], [18689, 491^C
    '''

    obj1 = '.'.join((func1, commit1, opt1))
    obj2 = '.'.join((func2, commit2, opt2))

    dataset = json.load(dataset_file)
    t0 = time.time()
    try:
        sim = CodebookGenerator.normalized_ACFG_similarity(dataset[obj1], dataset[obj2])
    except Exception:
        sim = "Error!"
    
    t1 = time.time()
    with open('exec_result', 'a+') as f:
        f.write('------------------------\n')
        f.write('func1: {}\n'.format(obj1))
        f.write('func2: {}\n'.format(obj2))
        f.write('sim: {}\n'.format(sim))
        f.write('time cost: {}s\n'.format(t1-t0))

    return sim

def list_average(sim_list):
    available_count = 0
    sum = 0
    for i in sim_list:
        if not isinstance(i, str):
            sum += i
            available_count += 1
    return sum/available_count



if __name__ == '__main__':
    # generate a dataset named ../all_data_graphs_diff.json
    # based on ../config/func_list and ../config/commit_list
    
    ## gen_dataset.get_diff_graphs()

    funcs = gen_dataset.get_funcs()
    commits = gen_dataset.get_commits()    
    # this experiment will test similarities among 5 commits with all optimizations
    # 5 funcs are tested

    funcs = funcs[0:5]
    commits = commits[0:5]

    # different funcs 
    sim_list = []
    pool = mp.Pool(5)
    result = [pool.apply_async(compare_two_func, args=(commits[0], 'O2',funcs[i], commits[0], 'O2',funcs[j]))
        for i in range(5) for j in range(i, 5)]
    pool.close()
    sim_list += [p.get() for p in result]

    average_sim = list_average(sim_list)
    print('average similarity among different funcs: {}'.format(average_sim))

    # same func among different commits
    opt = ['Os', 'O2', 'O3']
    sim_list = []
    pool = mp.Pool(5)
    result = [pool.apply_async(compare_two_func, args=(commits[i], 'O2', funcs[t], commits[j], 'O2', funcs[t]))
        for i in range(5) for j in range(i, 5) for t in range(len(funcs))]
    pool.close()
    sim_list += [p.get() for p in result]

    average_sim = list_average(sim_list)
    print('average similarity among different commits with optimization in O2: {}'.format(average_sim))


    # same func among different optimizations in same commit




