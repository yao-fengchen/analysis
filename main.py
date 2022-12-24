import sys, os, json
from sysflow.graphlet import Graphlet
import warnings
import pandas as pd

def graph():
    warnings.filterwarnings("ignore")
    pd.set_option('display.max_rows', None)
    pd.set_option('display.max_columns', None)
    pd.set_option('display.expand_frame_repr', False)
    pd.set_option('max_colwidth', None)
    cols=['ts_uts', 'endts_uts', 'type', 'opflags', 'proc.pid', 'proc.tid', 'pproc.pid', 'proc.exe', 'proc.args', 'pproc.exe', 'pproc.args', 'res', 'flow.rbytes', 'flow.rops', 'flow.wbytes', 'flow.wops', 'container.id', 'tags']
    _cols=['ts_uts', 'type', 'opflags', 'proc.pid', 'proc.tid', 'pproc.pid', 'proc.exe', 'proc.args', 'pproc.exe', 'tags']
    evtcols=['ts_uts', 'type', 'opflags', 'proc.pid', 'pproc.pid', 'proc.exe', 'proc.args', 'pproc.exe', 'pproc.args', 'container.id', 'tags']
    entry='proc.aname contains /bin/bash'
    _entry='proc.aname contains apache2'
    _entry_='proc.aname contains httpd and not proc.aname contains /sh and not proc.args pmatch (lesspipe,dircolors) and not proc.aname pmatch (groups,dircolors)'

    g = Graphlet('data/demo/1592328169.sampa.sf', _entry, ['policies/ttps.yaml'])
    g.view(withoid=True, peek=True, peeksize=3)

    g.data()[cols].to_csv("result.csv", sep=",")

if __name__ == "__main__":
    graph()