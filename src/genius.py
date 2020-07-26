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
import os

o1 = lambda commit: os.path.join("/mnt", "panda", "kernel", "arm64-testcase-new", commit.split('/')[0], "out_dir", "O1", "vmlinux")
o2 = lambda commit: os.path.join("/mnt", "panda", "kernel", "arm64-testcase", commit, "vmlinux")
o3 = lambda commit: os.path.join("/mnt", "panda", "kernel", "arm64-testcase-new", commit.split('/')[0], "out_dir", "O1", "vmlinux")


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

    obj1 = '.'.join((func1, commit1.split("/")[0], opt1))
    obj2 = '.'.join((func2, commit2.split("/")[0], opt2))

    dataset = json.load(dataset_file)
    t0 = time.time()
    try:
        sim = CodebookGenerator.normalized_ACFG_similarity(dataset[obj1], dataset[obj2])
    except Exception:
        sim = "Error!"
    
    t1 = time.time()
    with open('exec_record', 'a+') as f:
        f.write('------------------------\n')
        f.write('func1: {}\n'.format(obj1))
        f.write('func2: {}\n'.format(obj2))
        f.write('sim: {}\n'.format(sim))
        f.write('time cost: {}s\n'.format(t1-t0))
    
    dic = {}
    subdic = {}
    subdic['sim'] = sim
    subdic['timeuse'] = t1-t0
    dic[''.join((obj1, "@", func1, ":", obj2, "@", func2))] = subdic

    return sim,dic

def list_average(sim_list):
    available_count = 0
    sum = 0
    for i in sim_list:
        if not isinstance(i, str):
            sum += i
            available_count += 1
    return sum/available_count if available_count>0 else 0



if __name__ == '__main__':
    # generate a dataset named ../all_data_graphs_diff.json
    # based on ../config/func_list and ../config/commit_list
    
    ## gen_dataset.get_diff_graphs()

    funcs = gen_dataset.get_funcs()
    commits = gen_dataset.get_commits()
    funcs = funcs[0:10]
    '''
    dccp_rcv_state_process
    ext4_collapse_range
    ext4_insert_range
    ext4_page_mkwrite
    ext4_punch_hole
    ext4_setattr
    init_once
    follow_page_pte
    hmac_create
    ion_ioctl
    '''
    commits = commits[0:10]
    # take the first function in first commit as an example
    sim_data = {}
    threads = 10
    choosen_func = 0
    choosen_commit = 0
    choosen_opt = 'O2'
    optlist = ['O1', 'O2', 'O3']

    ## optimization
    # compare one func among different optimization
    for opt in optlist:
        sim_list = []
        pool = mp.Pool(threads)        
        result = [pool.apply_async(compare_two_func, args=(commits[choosen_commit], choosen_opt, funcs[choosen_func],
                                                            commits[choosen_commit], opt, funcs[choosen_func]))]
        pool.close()
        for p in result:
            res = p.get()
            sim_list.append(res[0])
            sim_data = {**sim_data, **res[1]}
        # sim_list += [p.get() for p in result]
        average_sim = list_average(sim_list)
        with open('conclusion', 'a+') as f:
            f.write('similarity of one func between 2 opt is {}\n'.format(average_sim))

    
    # different funcs
    # compare the first func with other funcs
    for opt in optlist: # compare them in 3 optimizations
        sim_list = []
        pool = mp.Pool(threads)
        result = [pool.apply_async(compare_two_func, args=(commits[choosen_commit], choosen_opt, funcs[choosen_func], 
                                                            commits[choosen_commit], opt, funcs[i]))
                                                            for i in range(10) if i!=choosen_func]
        pool.close()
        for p in result:
            res = p.get()
            sim_list.append(res[0])
            sim_data = {**sim_data, **res[1]}
        # sim_list += [p.get() for p in result]
        average_sim = list_average(sim_list)
        print('average similarity among different funcs: {}'.format(average_sim))
        with open('conclusion', 'a+') as f:
            f.write('average similarity among different funcs: {}\n'.format(average_sim))
    

    ## commits
    # same func in different commits
    
    sim_list = []
    pool = mp.Pool(threads)
    result = [pool.apply_async(compare_two_func, args=(commits[choosen_commit], choosen_opt, funcs[choosen_func], 
                                                        commits[t], choosen_opt, funcs[choosen_func]))
                                                        for t in range(10)]
    pool.close()
    for p in result:
        res = p.get()
        sim_list.append(res[0])
        sim_data = {**sim_data, **res[1]}
    average_sim = list_average(sim_list)
    print('average similarity among same func different commits with optimization in O2: {}'.format(average_sim))
    with open('conclusion', 'a+') as f:
        f.write('average similarity among same func different commits with optimization in O2: {}\n'.format(average_sim))

    # different commits different funcs

    sim_list = []
    pool = mp.Pool(threads)
    result = [pool.apply_async(compare_two_func, args=(commits[choosen_commit], choosen_opt, funcs[choosen_func], 
                                                        commits[i], choosen_opt, funcs[j]))
                                                        for i in range(5) for j in range(10)]
    pool.close()
    for p in result:
        res = p.get()
        sim_list.append(res[0])
        sim_data = {**sim_data, **res[1]}
    # sim_list += [p.get() for p in result]

    average_sim = list_average(sim_list)
    print('average similarity among different funcs in different commits with optimization as O2: {}'.format(average_sim))
    with open('conclusion', 'a+') as f:
        f.write('average similarity among different funcs in different commits with optimization as O2: {}\n'.format(average_sim))
        f.write('---------------------------------------------------------')


    with open('exec_result.json', 'a+') as f:
        json.dump(sim_data, f)