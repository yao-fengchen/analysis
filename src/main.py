import sys, os, json
from sysflow.graphlet import Graphlet
import warnings
import pandas as pd
import numpy as np

warnings.filterwarnings("ignore")
pd.set_option('display.max_rows', None)
pd.set_option('display.max_columns', None)
pd.set_option('display.expand_frame_repr', False)
pd.set_option('max_colwidth', None)
cols=['ts_uts', 'endts_uts', 'type', 'opflags', 'proc.pid', 'proc.tid', 'pproc.pid', 'proc.exe', 'proc.args', 'pproc.exe', 'pproc.args', 'res', 'flow.rbytes', 'flow.rops', 'flow.wbytes', 'flow.wops', 'container.id', 'tags']
# _cols=['ts_uts', 'type', 'opflags', 'proc.pid', 'proc.tid', 'pproc.pid', 'proc.exe', 'proc.args', 'pproc.exe', 'tags']
# evtcols=['ts_uts', 'type', 'opflags', 'proc.pid', 'pproc.pid', 'proc.exe', 'proc.args', 'pproc.exe', 'pproc.args', 'container.id', 'tags']
# entry='proc.aname contains /bin/bash'
# _entry='proc.aname contains apache2'
# _entry_='proc.aname contains httpd and not proc.aname contains /sh and not proc.args pmatch (lesspipe,dircolors) and not proc.aname pmatch (groups,dircolors)'
# ioc = '(proc.cmdline contains exfil or (type = FF and file.path contains exfil and flow.wbytes > 0)) and proc.aname contains node and proc.exe!=/bin/dash'

# g1 = Graphlet('data/attacks/express', ioc, ['policies/ttps.yaml'])
# g1.view(withoid=True, peek=True, peeksize=10, flows=True, ttps=True)

# g1.data()[cols].to_csv("result.csv", sep=",")

ioc = 'process.name = cp and container.name = attack'
g2 = Graphlet('data/sysflow-events.log', ioc, ['policies/ttps.yaml'])
g2.view(withoid=True, peek=True, peeksize=10, flows=True, ttps=False)
# g2.data()[cols].to_csv("result.csv", sep=",")