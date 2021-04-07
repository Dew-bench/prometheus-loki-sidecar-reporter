import os
import psutil

def get_all_procs():
    proc_list = []
    for proc in psutil.process_iter():
        proc_list.append([proc.name, proc.pid])
    return proc_list
