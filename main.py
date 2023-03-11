import sys, os, json
sys.path.append('src')
from sysflow.graphlet import Graphlet
import warnings
import pandas as pd
import numpy as np
import os
os.system("python data/getevents.py")

warnings.filterwarnings("ignore")
pd.set_option('display.max_rows', None)
pd.set_option('display.max_columns', None)
pd.set_option('display.expand_frame_repr', False)
pd.set_option('max_colwidth', None)

cols=['head.ts', 'head.endts', 'head.type', 'file_action.bytes_read', 'file_action.bytes_written', 'file_action.read_ops', 'file_action.write_ops', 'event.opflags', 'process.oid.hpid', 'pprocess.oid.hpid', 'process.exe', 'pprocess.exe','container.name']
ioc = 'process.name = lsblk and container.image.name = attackanalyze:latest'
ioc = 'process.exe = /usr/bin/lsblk and container.image.name = attackanalyze:latest'
ioc = 'file.path = /bin/cat and process.command_line contains cat'
ioc = 'process.oldname = df'
ioc = 'process.oldname = lsblk'
graph = Graphlet('data/events.log', ioc, ['src/policies/ttps.yaml'])
graph.view(withoid=True, peek=True, peeksize=3, flows=True, ttps=True)
graph.data()[cols].to_csv("result/result.csv", sep=",")