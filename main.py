import sys, os, json
sys.path.append('src')
from sysflow.graphlet import Graphlet
import warnings
import pandas as pd
import numpy as np

warnings.filterwarnings("ignore")
pd.set_option('display.max_rows', None)
pd.set_option('display.max_columns', None)
pd.set_option('display.expand_frame_repr', False)
pd.set_option('max_colwidth', None)

cols=['head.ts', 'head.endts', 'head.type', 'event.opflags', 'process.oid.hpid', 'process.tid', 'pprocess.oid.hpid', 'process.exe', 'pprocess.exe','container.name', 'tags']
ioc = 'process.name = cp and container.name = attack'
graph = Graphlet('data/events.log', ioc, ['src/policies/ttps.yaml'])
graph.view(withoid=True, peek=True, peeksize=10, flows=True, ttps=True)
graph.data()[cols].to_csv("result/result.csv", sep=",")