#!/usr/bin/env python3

import hashlib, json, os, sys
import urllib.request
from functools import reduce
from collections import OrderedDict
import sysflow.utils as utils
import sysflow.opflags as opflags
from sysflow.formatter import _fields, SFFormatter
from sysflow.objtypes import ObjectTypes, OBJECT_MAP
from sysflow.reader import FlattenedSFReader
from sysflow.sfql import SfqlInterpreter
from graphviz import Digraph
import matplotlib.pylab as plt
import matplotlib.dates as mdates
import numpy as np
import pandas as pd
import mitreattack.attackToExcel.attackToExcel as attackToExcel
import mitreattack.attackToExcel.stixToDf as stixToDf

# To silence info logging and progress bar from mitreattack module.
from loguru import logger

logger.remove()
logger.add(sys.stderr, level='ERROR')
from tqdm import tqdm
from functools import partialmethod

tqdm.__init__ = partialmethod(tqdm.__init__, disable=True)

"""
.. module:: sysflow.graphlet
   :synopsis: This module re-interprets SysFlow traces in a compact provenance graph representation
"""

INFSYMB = '&infin;'

FLOW_FIELDS = [
    'head.ts',
    'head.endts',
    'event.type',
    'event.opflags',
    'process.oid.hpid',
    'process.tid',
    'pprocess.oid.hpid',
    'process.exe',
    'process.args',
    'pprocess.exe',
    'pprocess.args',
    'res',
    'file_action.bytes_read',
    'file_action.read_ops',
    'file_action.bytes_written',
    'file_action.write_ops',
    'container.id',
    'tags',
]
EVT_FIELDS = [
    'head.ts',
    'event.sf_type',
    'event.opflags',
    'process.oid.hpid',
    'process.tid',
    'pprocess.oid.hpid',
    'process.exe',
    'process.args',
    'pprocess.exe',
    'tags',
]


class Graphlet(object):
    """
    **Graphlet**

    This class takes a path pointing to a sysflow record or a directory containing sysflow records.

    Example Usage::

         # basic usage
         g1 = Graphlet('data/')
         g1.view()

         # filtering and enrichment with policies
         ioc1 = 'process.exe = /usr/bin/scp'
         g1 = Graphlet('data/', ioc1, ['policies/ttps.yaml'])
         g1.view()

    :param graphlet: A compact provenance graph representation based on sysflow records.
    :type graphlet: sysflow.Graphlet
    """

    attackdata = None
    techniques_normalized = pd.DataFrame()
    mitigations_normalized = pd.DataFrame()
    associated_mitigations_normalized = pd.DataFrame()
    defend_data = {}

    def __init__(self, path, expr=None, defs=[]):
        """Create graphlet object from raw sysflow with optional filters and policy taggers.

        :param path: a path to a sysflow record or directory containing sysflow records.
        :type path: str

        :param expr: sfql style filter.
        :type expr: str

        :param defs: a list of paths for yaml policies that enrich graph nodes.
        :type defs: list
        """
        if os.path.isfile(path):
            self.readers = [FlattenedSFReader(path, retEntities=True)]
        elif os.path.isdir(path):
            self.readers = [FlattenedSFReader(f, retEntities=True) for f in _files(path)]
        self.nodes = OrderedDict()
        self.edges = set()
        self.sfqlint = SfqlInterpreter(paths=defs)
        self.fmt = SFFormatter(None)
        for reader in self.readers:
            self.reader = reader
            self.__create(expr)


    def __create(self, expr=None):
        for objtype, head, event, host, container, pod, file, file_action, network, source, destination, process, pprocess in self.sfqlint.filter(self.reader, expr):
            print("==========================")
            print("objtype\t",objtype)
            print("head\t", head)
            print("event\t", event)
            print("host\t", host)
            print("container\t", container)
            print("pod\t", pod)
            print("file\t", file)
            print("file_action\t", file_action)
            print("network\t", network)
            print("source\t", source)
            print("destination\t", destination)
            print("process\t", process)
            print("pprocess\t", pprocess)

            tags = self.sfqlint.enrich((objtype, head, event, host, container, pod, file, file_action, network, source, destination, process, pprocess))

            if objtype == ObjectTypes.PROC_EVT:
                if process.oid.hpid != process.tid or not pprocess:
                    continue
                r = self.fmt._flatten(objtype, head, event, host, container, pod, file, file_action, network, source, destination, process, pprocess, None, tags=tags)
                opflag = utils.getOpFlagsStr(event.opflags_int)

                filt = lambda v: (v.exe, v.args) == (process.exe, process.args) and v.hasProc(
                    pprocess.oid.hpid, pprocess.oid.createTS
                )
                if opflag == utils.getOpFlagsStr(opflags.OP_CLONE) and (process.exe, process.args) == (
                    pprocess.exe, pprocess.args,
                ):
                    self.__addProcEvtEdge(opflag, process, pprocess, r, filt)

                filt = lambda v: (v.exe, v.args) != (process.exe, process.args) and v.hasProc(
                    process.oid.hpid, process.oid.createTS
                )
                if opflag == utils.getOpFlagsStr(opflags.OP_EXEC):
                    self.__addProcEvtEdge(opflag, process, pprocess, r, filt)

                filt = lambda v: (v.exe, v.args) == (process.exe, process.args) and v.hasProc(
                    process.oid.hpid, process.oid.createTS
                )
                if opflag == utils.getOpFlagsStr(opflags.OP_EXIT):
                    self.__addProcEvtEdge(opflag, process, pprocess, r, filt)

            if objtype == ObjectTypes.FILE_FLOW and file.path != process.exe:
                filt = lambda v: (v.exe, v.args) == (process.exe, process.args) and v.hasProc(
                    process.oid.hpid, process.oid.createTS
                )
                r = self.fmt._flatten(objtype, head, event, host, container, pod, file, file_action, network, source, destination, process, pprocess, None, tags=tags)
                self.__addFileFlowEdge(process, pprocess, r, filt)

            if objtype == ObjectTypes.NET_FLOW:
                filt = lambda v: (v.exe, v.args) == (process.exe, process.args) and v.hasProc(
                    process.oid.hpid, process.oid.createTS
                )
                r = self.fmt._flatten(objtype, head, event, host, container, pod, file, file_action, network, source, destination, process, pprocess, None, tags=tags)
                self.__addNetFlowEdge(process, pprocess, r, filt)

    def __addProcEvtEdge(self, opflag, process, pprocess, r, filt):
        n1_k = _hash((process.exe, process.args, pprocess.exe, pprocess.args))
        if n1_k in self.nodes:
            n1_v = self.nodes[n1_k]
        else:
            n1_v = ProcessNode(
                n1_k, process.exe, process.args, process.uid, process.user, process.gid, process.group, process.tty
            )
        n1_v.addProc(process.oid.hpid, process.oid.createTS, r)
        self.nodes[n1_k] = n1_v

        if opflag == utils.getOpFlagsStr(opflags.OP_EXEC):
            p = pprocess
            n2_k, n2_v = self.__findNode(filt)
        if opflag == utils.getOpFlagsStr(opflags.OP_CLONE):
            p = pprocess
            n2_k, n2_v = self.__findNode(filt)
        if opflag == utils.getOpFlagsStr(opflags.OP_EXIT):
            p = process
            n2_k, n2_v = self.__findNode(filt)

        if not n2_k:
            key = self.reader.getProcessKey(pprocess.oid) if pprocess else None
            if key in self.reader.processes:
                pp = self.reader.processes[key]
                n2_k = _hash((p.exe, p.args, pp.exe, pp.args))
            else:
                n2_k = _hash((p.exe, p.args))
            n2_v = ProcessNode(n2_k, p.exe, p.args, p.uid, p.user, p.gid, p.group, p.tty)
            n2_v.addProc(p.oid.hpid, p.oid.createTS, None)
            self.nodes[n2_k] = n2_v
        self.edges.add(EvtEdge(n2_k, n1_k, opflag))

    def __addFileFlowEdge(self, process, pprocess, r, filt):
        if pprocess:
            n1_k = _hash((process.exe, process.args, OBJECT_MAP[ObjectTypes.FILE_FLOW], pprocess.exe, pprocess.args))
        else:
            n1_k = _hash((process.exe, process.args, OBJECT_MAP[ObjectTypes.FILE_FLOW]))
        new = False
        if n1_k in self.nodes:
            n1_v = self.nodes[n1_k]
        else:
            n1_v = FileFlowNode(n1_k, process.exe, process.args)
            new = True
        n1_v.addFlow(r)
        self.nodes[n1_k] = n1_v
        if new:
            n2_k, n2_v = self.__findNode(filt)
            if not n2_k:
                key = self.reader.getProcessKey(pprocess.oid) if pprocess.oid else None
                if key in self.reader.processes:
                    pp = self.reader.processes[key]
                    n2_k = _hash((process.exe, process.args, pp.exe, pp.args))
                else:
                    n2_k = _hash((process.exe, process.args))
                n2_v = ProcessNode(
                    n2_k, process.exe, process.args, process.uid, process.user, process.gid, process.group, process.tty
                )
                n2_v.addProc(process.oid.hpid, process.oid.createTS, None)
                self.nodes[n2_k] = n2_v
            self.edges.add(FlowEdge(n2_k, n1_k, OBJECT_MAP[ObjectTypes.FILE_FLOW]))

    def __addNetFlowEdge(self, process, pprocess, r, filt):
        if pprocess:
            n1_k = _hash((process.exe, process.args, OBJECT_MAP[ObjectTypes.NET_FLOW], pprocess.exe, pprocess.args))
        else:
            n1_k = _hash((process.exe, process.args, OBJECT_MAP[ObjectTypes.NET_FLOW]))
        new = False
        if n1_k in self.nodes:
            n1_v = self.nodes[n1_k]
        else:
            n1_v = NetFlowNode(n1_k, process.exe, process.args)
            new = True
        n1_v.addFlow(r)
        self.nodes[n1_k] = n1_v
        if new:
            n2_k, n2_v = self.__findNode(filt)
            if not n2_k:
                key = self.reader.getProcessKey(pprocess.oid) if pprocess.oid else None
                if key in self.reader.processes:
                    pp = self.reader.processes[key]
                    n2_k = _hash((process.exe, process.args, pp.exe, pp.args))
                else:
                    n2_k = _hash((process.exe, process.args))
                n2_v = ProcessNode(
                    n2_k, process.exe, process.args, process.uid, process.user, process.gid, process.group, process.tty
                )
                n2_v.addProc(process.oid.hpid, process.oid.createTS, None)
                self.nodes[n2_k] = n2_v
            self.edges.add(FlowEdge(n2_k, n1_k, OBJECT_MAP[ObjectTypes.NET_FLOW]))

    def __findNode(self, filt):
        for k, v in reversed(self.nodes.items()):
            if isinstance(v, ProcessNode) and filt(v):
                return (k, v)
        return (None, None)

    def __loadAttackTechniquesOnce(self):
        if not self.techniques_normalized.empty:
            return
        if not self.attackdata:
            self.attackdata = attackToExcel.get_stix_data('enterprise-attack')
        techniques_data = stixToDf.techniquesToDf(self.attackdata, 'enterprise-attack')
        self.techniques_normalized = techniques_data['techniques']

    def __loadAttackMitigationsOnce(self):
        if not self.mitigations_normalized.empty:
            return
        if not self.attackdata:
            self.attackdata = attackToExcel.get_stix_data('enterprise-attack')
        mitigations_data = stixToDf.mitigationsToDf(self.attackdata)
        self.mitigations_normalized = mitigations_data['mitigations']

    def __loadAssociatedAttackMitigationsOnce(self):
        if not self.associated_mitigations_normalized.empty:
            return
        if not self.attackdata:
            self.attackdata = attackToExcel.get_stix_data('enterprise-attack')
        stixToDf.relationshipsToDf(self.attackdata, 'technique')
        associated_mitigations_data = stixToDf.relationshipsToDf(self.attackdata, 'technique')
        self.associated_mitigations_normalized = associated_mitigations_data['associated mitigations']

    def __loadDefendData(self, techniqueID):
        if techniqueID in self.defend_data.keys():
            return
        d3f_url = 'https://d3fend.mitre.org/api/offensive-technique/attack/{0}.json'.format(techniqueID)
        d3f_vars = [
            'def_tactic_label.value',
            'def_tech_parent_label.value',
            'def_tech_label.value',
            'def_artifact_rel_label.value',
            'def_artifact_label.value',
            'off_tech_id.value',
            'off_artifact_label.value',
            'off_artifact_rel_label.value',
            'off_tech_label.value',
            'off_tactic_rel_label.value',
            'off_tactic_label.value',
        ]
        try:
            with urllib.request.urlopen(d3f_url) as url:
                data = json.loads(url.read().decode())
            # normalize data
            df = pd.json_normalize(data["off_to_def"]["results"]["bindings"])
            if df.empty:
                return
            # fill in missing bindings
            for c in d3f_vars:
                if c not in df:
                    df[c] = None
            # rename columns
            defend_data = df[d3f_vars].rename(
                columns={
                    'def_tactic_label.value': 'def_tactic',
                    'def_tech_label.value': 'def_tech',
                    'def_tech_parent_label.value': 'def_tech_parent',
                    'def_artifact_rel_label.value': 'def_artifact_rel',
                    'def_artifact_label.value': 'def_artifact',
                    'off_tech_id.value': 'technique_id',
                    'off_artifact_label.value': 'artifact',
                    'off_artifact_rel_label.value': 'artifact_rel',
                    'off_tech_label.value': 'technique',
                    'off_tactic_rel_label.value': 'tactic_rel',
                    'off_tactic_label.value': 'tactic',
                }
            )
            self.defend_data[techniqueID] = defend_data.dropna(subset=['def_tactic', 'def_tech'])
        except Exception:
            return

    def df(self, oid=None):
        """Returns a dataframe containing a summary of the graph node IDs and process metadata associated with them.

        :param oid: a node ID filter.
        :type oid: object ID string
        """
        data = OrderedDict()
        for idx, r in enumerate(self.nodes.items()):
            if not oid or oid == r[1].oid:
                data[idx] = r
        return pd.DataFrame.from_dict(data, orient='index', columns=['id', 'name'])

    def data(self, oid=None):
        """Returns a dataframe containing the underlying data (sysflow records) of the graph.

        :param oid: a node ID filter.
        :type oid: object ID string
        """
        df = pd.DataFrame()
        for k, r in self.nodes.items():
            if not oid or oid == r.oid:
                df = pd.concat([df, r.df()])
        df.reindex()
        df.sort_values(by=['head.ts'], inplace=True, ignore_index=True)
        return df

    def tags(self, oid=None):
        """Returns a dataframe containing the set of (enrichment) tags in the graph.

        :param oid: a node ID filter.
        :type oid: object ID string
        """
        df = pd.DataFrame()
        for k, r in self.nodes.items():
            if not oid or oid == r.oid:
                tdf = r.df()[['tags']]
                df = pd.concat([df, tdf[tdf['tags'].map(lambda d: len(d)) > 0].reset_index(drop=True)])
                # df['tmp'] = df.apply(lambda row: str(row.tags[1]), axis=1)
        # df = df.drop_duplicates(subset='tmp')[['tags']]
        return df

    def ttps(self, oid=None, details=False):
        """Returns a dataframe containing the set of MITRE TTP tags in the graph (e.g., as enriched by the ttps.yaml policy provided with the SysFlow processor).

        :param oid: a node ID filter.
        :type oid: object ID string

        :param details: indicates whether to include complete TTP metadata in the dataframe.
        :type details: boolean
        """
        df = self.tags(oid)
        ttps = pd.DataFrame()
        for e in df['tags']:
            for s in e[1]:
                t = s.split(':')
                if t[0] == 'mitre':
                    self.__loadAttackTechniquesOnce()
                    tdf = self.techniques_normalized[self.techniques_normalized.ID == t[1]]
                    if not details:
                        tdf = tdf.reindex(['ID', 'name', 'url', 'tactics', 'platforms'], axis=1)
                    ttps = pd.concat([ttps, tdf[tdf.ID == t[1]]])
        return ttps.drop_duplicates(subset='ID').reset_index(drop=True)

    def associatedMitigations(self, oid=None):
        """Returns a dataframe containing the set of MITRE mitigations associated with TTPs annotated in the graph.

        :param oid: a node ID filter.
        :type oid: object ID string
        """
        mitigations = pd.DataFrame()
        ttps = self.ttps(oid)
        for e in ttps['ID']:
            self.__loadAssociatedAttackMitigationsOnce()
            mdf = self.associated_mitigations_normalized[self.associated_mitigations_normalized['target ID'] == e]
            mitigations = pd.concat([mitigations, mdf[mdf['target ID'] == e]])
        return mitigations

    def mitigations(self, oid=None, details=False):
        """Returns a dataframe containing the summary set of MITRE mitigations associated with TTPs annotated in the graph.

        :param oid: a node ID filter.
        :type oid: object ID string
        """
        mitigations = pd.DataFrame()
        rdf = self.associatedMitigations(oid)
        for e in rdf['source ID']:
            self.__loadAttackMitigationsOnce()
            mdf = self.mitigations_normalized[self.mitigations_normalized['ID'] == e]
            if not details:
                mdf = mdf.reindex(['ID', 'name', 'url'], axis=1)
            mitigations = pd.concat([mitigations, mdf[mdf['ID'] == e]])
        return mitigations.drop_duplicates(subset='ID').reset_index(drop=True)

    def countermeasures(self, oid=None):
        """Returns a dataframe containing the set of MITRE d3fend defenses associated with TTPs annotated in the graph.

        :param oid: a node ID filter.
        :type oid: object ID string
        """
        countermeasures = pd.DataFrame()
        ttps = self.ttps(oid)
        for e in ttps['ID']:
            self.__loadDefendData(e)
            if e in self.defend_data.keys():
                def_data = self.defend_data[e]
                cmdf = def_data[def_data['technique_id'] == e]
            countermeasures = pd.concat([countermeasures, cmdf[cmdf['technique_id'] == e]])
        return countermeasures

    def view(self, withoid=False, peek=True, peeksize=3, flows=True, ttps=False):
        """Visualizes the graph in dot format.

        :param withoid: indicates whether to show the node ID.
        :type withoid: boolean

        :param peek: indicates whether to show details about the records associated with the nodes.
        :type peek: boolean

        :param peeksize: the number of underlying sysflow records to show in the node.
        :type peeksize: integer

        :param flows: indicates whether to show flow nodes.
        :type flows: boolean

        :param ttps: indicates whether to show tags.
        :type ttps: boolean
        """
        graph_attr = {'splines': 'true', 'overlap': 'scale', 'rankdir': 'TD'}
        node_attr = {'shape': 'Mrecord', 'fontsize': '9'}
        edge_attr = {'fontsize': '8'}
        base_path = os.path.abspath(__file__)
        result_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(base_path))), 'result')
        g = Digraph('graphlet', directory= result_path, node_attr=node_attr, edge_attr=edge_attr, graph_attr=graph_attr)
        for k, v in self.nodes.items():
            if flows and (isinstance(v, FileFlowNode) or isinstance(v, NetFlowNode)) and len(v.df()) > 0:
                if ttps and v.score() > 0:
                    g.node(
                        str(k),
                        v.dot(withoid, peek, peeksize, ttps),
                        style='filled,bold',
                        color='red',
                        fontcolor='red',
                        fillcolor='#ff000010',
                    )
                else:
                    g.node(str(k), v.dot(withoid, peek, peeksize, ttps), style='bold')
            if isinstance(v, ProcessNode):
                if ttps and v.score() > 0:
                    g.node(
                        str(k),
                        v.dot(withoid, peek, peeksize, ttps),
                        style='filled',
                        color='red',
                        fontcolor='red',
                        fillcolor='#ff000010',
                    )
                else:
                    g.node(str(k), v.dot(withoid, peek, peeksize, ttps))
        for e in self.edges:
            t = self.nodes[e.nto()].interval()
            label = '    {0} ({1},{2})'.format(e.op(), t[0], t[1])
            if isinstance(e, EvtEdge):
                g.edge(str(e.nfrom()), str(e.nto()), label=label)
            if flows and isinstance(e, FlowEdge) and len(self.nodes[e.n2].df()) > 0:
                g.edge(str(e.nfrom()), str(e.nto()), label=label, style='dashed')
        g.view()
        return g

    def compare(self, other, withoid=False, peek=True, peeksize=3, flows=True, ttps=False):
        """Compares the graph to another graph (using a simple graph difference), returning a graph slice.

        :param withoid: indicates whether to show the node ID.
        :type withoid: boolean

        :param peek: indicates whether to show details about the records associated with the nodes.
        :type peek: boolean

        :param peeksize: the number of node records to show.
        :type peeksize: integer

        :param flows: indicates whether to show flow nodes.
        :type flows: boolean

        :param ttps: indicates whether to show tags.
        :type ttps: boolean
        """
        lndiff = set(self.nodes) - set(other.nodes)
        lediff = set(self.edges) - set(other.edges)
        graph_attr = {'splines': 'true', 'overlap': 'scale', 'rankdir': 'TD'}
        node_attr = {'shape': 'Mrecord', 'fontsize': '9'}
        edge_attr = {'fontsize': '8'}
        g = Digraph('graphlet', directory='/tmp/.sf/', node_attr=node_attr, edge_attr=edge_attr, graph_attr=graph_attr)
        for k, v in self.nodes.items():
            if flows and (isinstance(v, FileFlowNode) or isinstance(v, NetFlowNode)) and len(v.df()) > 0:
                if k in lndiff:
                    if ttps and v.score() > 0:
                        g.node(
                            str(k),
                            v.dot(withoid, peek, peeksize, ttps),
                            style='filled,bold',
                            color='red',
                            fontcolor='red',
                            fillcolor='#ff000020',
                        )
                    else:
                        g.node(str(k), v.dot(withoid, peek, peeksize, ttps), style='bold', color='red', fontcolor='red')
                else:
                    if ttps and v.score() > 0:
                        g.node(
                            str(k),
                            v.dot(withoid, peek, peeksize, ttps),
                            style='filled,bold',
                            color='red',
                            fontcolor='red',
                            fillcolor='#ff000020',
                        )
                    else:
                        g.node(str(k), v.dot(withoid, peek, peeksize, ttps), style='bold')
            if isinstance(v, ProcessNode):
                if k in lndiff:
                    if ttps and v.score() > 0:
                        g.node(
                            str(k),
                            v.dot(withoid, peek, peeksize, ttps),
                            style='filled,bold',
                            color='red',
                            fontcolor='red',
                            fillcolor='#ff000020',
                        )
                    else:
                        g.node(str(k), v.dot(withoid, peek, peeksize, ttps), style='bold', color='red', fontcolor='red')
                else:
                    if ttps and v.score() > 0:
                        g.node(
                            str(k),
                            v.dot(withoid, peek, peeksize, ttps),
                            style='filled,bold',
                            color='red',
                            fontcolor='red',
                            fillcolor='#ff000020',
                        )
                    else:
                        g.node(str(k), v.dot(withoid, peek, peeksize, ttps), style='bold')
        for e in self.edges:
            t = self.nodes[e.nto()].interval()
            label = '{0} ({1},{2})'.format(e.op(), t[0], t[1])
            if isinstance(e, EvtEdge):
                if e in lediff:
                    g.edge(str(e.nfrom()), str(e.nto()), label=label, color='red', fontcolor='red')
                else:
                    g.edge(str(e.nfrom()), str(e.nto()), label=label)
            if flows and isinstance(e, FlowEdge) and len(self.nodes[e.n2].df()) > 0:
                if e in lediff:
                    g.edge(str(e.nfrom()), str(e.nto()), label=label, style='dashed', color='red', fontcolor='red')
                else:
                    g.edge(str(e.nfrom()), str(e.nto()), label=label, style='dashed')
        return g

    def __str__(self):
        nodes = reduce(lambda s1, s2: str(s1) + str(s2) + '\n', self.nodes.values(), '')
        edges = reduce(lambda s1, s2: str(s1) + str(s2) + '\n', self.edges, '')
        return 'nodes:\n' + nodes + 'edges:\n ' + edges


class Edge(object):
    """
    **Edge**

    This class represents a graph edge, and acts as a super class for specific edges.

    :param edge: an abstract edge object.
    :type edge: sysflow.Edge
    """

    def __init__(self, n1, n2, label):
        super().__init__()
        self.n1 = n1
        self.n2 = n2
        self.label = label


class EvtEdge(Edge):
    """
    **EvtEdge**

    This class represents a graph event edge. It is used
    for sysflow event objects and subclasses Edge.

    :param evtedge: an edge object representing a sysflow evt.
    :type evtedge: sysflow.EvtEdge
    """

    def __init__(self, n1, n2, label):
        super().__init__(n1, n2, label)

    def nfrom(self):
        return self.n1

    def nto(self):
        return self.n2

    def op(self):
        return self.label

    def __key(self):
        return (self.n1, self.n2, self.label)

    def __hash__(self):
        return _hash(self.__key())

    def __eq__(self, other):
        if isinstance(other, EvtEdge):
            return self.__key() == other.__key()
        return NotImplemented

    def __str__(self):
        return 'edge: [{0}] -- {1} --> [{2}]'.format(self.n1, self.label, self.n2)


class FlowEdge(Edge):
    """
    **FlowEdge**

    This class represents a graph flow edge. It is used
    for sysflow flow objects and subclasses Edge.

    :param flowedge: an edge object representing a sysflow flow.
    :type flowedge: sysflow.FlowEdge
    """

    def __init__(self, n1, n2, label):
        super().__init__(n1, n2, label)

    def nfrom(self):
        return self.n1

    def nto(self):
        return self.n2

    def op(self):
        return self.label

    def __key(self):
        return (self.n1, self.n2, self.label)

    def __hash__(self):
        return _hash(self.__key())

    def __eq__(self, other):
        if isinstance(other, FlowEdge):
            return self.__key() == other.__key()
        return NotImplemented

    def __str__(self):
        return 'edge: [{0}] -- {1} --> [{2}]'.format(self.n1, self.label, self.n2)


class Node(object):
    """
    **Node**

    This class represents a graph node, and acts as a super class for specific nodes.

    :param node: an abstract node object.
    :type node: sysflow.Node
    """

    def __init__(self, oid):
        super().__init__()
        self.oid = oid


class ProcessNode(Node):
    """
    **ProcessNode**

    This class represents a process node.

    :param process: a process node object.
    :type process: sysflow.ProcessNode
    """

    def __init__(self, oid, exe, args, uid, user, gid, group, tty):
        super().__init__(oid)
        self.type = 'P'
        self.exe = exe
        self.args = args
        self.uid = uid
        self.user = user
        self.gid = gid
        self.group = group
        self.tty = tty
        self.procs = set()
        self.data = list()

    def addProc(self, pid, createTS, r):
        self.procs.add((pid, createTS))
        if r:
            self.data.append(r)

    def hasProc(self, pid, createTS):
        return (pid, createTS) in self.procs

    def df(self):
        data = OrderedDict()
        if len(self.data) > 0:
            for idx, r in enumerate(self.data):
                data[idx] = r.values()
            return pd.DataFrame.from_dict(data, orient='index', columns=r.keys() if r else None)
        return pd.DataFrame(columns=_fields)

    def interval(self):
        ts = str(self.df()[['head.ts']].min().to_string(index=False)).strip()
        te = str(self.df()[['head.ts']].max().to_string(index=False)).strip()  # INFSYMB
        return (ts, te)

    def score(self):
        for r in self.data:
            if len(r['tags']) > 0:
                return r['tags'][2]
        return 0

    def tags(self):
        tags = set()
        for r in self.data:
            if len(r['tags']) > 0:
                for t in r['tags'][1]:
                    tags.add(str(t))
        return tags if len(tags) > 0 else None

    def dot(self, withoid=False, peek=True, peeksize=3, showtags=False):
        node = 'P|{{{0} [{1}]|{{{2}|{3}|{4}|{5}|{6}}}{7}}}'
        peeknode = 'P|{{{0} [{1}]|{{{2}}}|{{{3}|{4}|{5}|{6}|{7}}}{8}}}'
        oidnode = 'P|{{{0}|{{{1} [{2}]}}|{{{3}|{4}|{5}|{6}|{7}}}{8}}}'
        peekoidnode = 'P|{{{0}|{{{1} [{2}]}}|{{{3}}}|{{{4}|{5}|{6}|{7}|{8}}}{9}}}'
        reslist = ['{0}, {1}'.format(p[0], p[1]) for p in self.procs]
        details = reslist[-peeksize:] + (reslist[peeksize:] and ['...'])
        peekstr = '\\n'.join(details)
        exe = _escape(self.exe)
        args = _escape(self.args)
        tags = '|{{{0}}}'.format(str(self.tags())) if showtags and self.tags() else ''
        if peek:
            return (
                peekoidnode.format(
                    self.oid, exe, args, peekstr, self.user, self.uid, self.group, self.gid, self.tty, tags
                )
                if withoid
                else peeknode.format(exe, args, peekstr, self.user, self.uid, self.group, self.gid, self.tty, tags)
            )
        else:
            return (
                oidnode.format(self.oid, exe, args, self.user, self.uid, self.group, self.gid, self.tty, tags)
                if withoid
                else node.format(exe, args, self.user, self.uid, self.group, self.gid, self.tty, tags)
            )

    def __key(self):
        return (self.exe, self.args)

    def __hash__(self):
        return _hash(self.__key())

    def __eq__(self, other):
        if isinstance(other, ProcessNode):
            return self.__key() == other.__key()
        return NotImplemented

    def __str__(self):
        return str(self.__key())


class FileFlowNode(Node):
    """
    **FileFlowNode**

    This class represents a fileflow node.

    :param ff: a fileflow node object.
    :type ff: sysflow.FileFlow
    """

    def __init__(self, oid, exe, args):
        super().__init__(oid)
        self.type = 'FF'
        self.exe = exe
        self.args = args
        self.data = list()

    def addFlow(self, r):
        self.data.append(r)

    def hasProc(self, pid, createTS):
        return True

    def df(self):
        data = OrderedDict()
        for idx, r in enumerate(self.data):
            data[idx] = r.values()
        df = pd.DataFrame.from_dict(data, orient='index', columns=r.keys() if r else None)
        # return df[(df['file.path'] != '') & ((df['file_action.read_ops'] > 0) | (df['file_action.write_ops'] > 0))]
        return df[(df['file.path'] != '')]

    def interval(self):
        ts = str(self.df()[['head.ts']].min().to_string(index=False)).strip()
        te = str(self.df()[['head.endts']].max().to_string(index=False)).strip()  # INFSYMB
        return (ts, te)

    def plot(self):
        df = self.df()
        flows = df[(df.type.isin(['FF']))]
        ax = flows[['head.ts', 'file_action.bytes_read', 'file_action.bytes_written']].plot.bar(
            x='head.ts', y=['file_action.bytes_read', 'file_action.bytes_written'], rot=45, figsize=(20, 5)
        )
        ax.xaxis.set_major_locator(mdates.AutoDateLocator())
        plt.gcf().autofmt_xdate()
        plt.show()

    def describe(self):
        # Rank ordering file operations
        _df = self.df().replace('', np.nan).dropna(axis=0, how='any', subset=['file.path'])
        paths = _df.groupby(['file.path']).count()[['head.ts']].rename(columns={"head.ts": "count"})
        return paths.sort_values(by='count', ascending=False)

    def score(self):
        for r in self.data:
            if len(r['tags']) > 0:
                return r['tags'][2]
        return 0

    def tags(self):
        tags = set()
        for r in self.data:
            if len(r['tags']) > 0:
                for t in r['tags'][1]:
                    tags.add(str(t))
        return tags if len(tags) > 0 else None

    def dot(self, withoid=False, peek=True, peeksize=3, showtags=False):
        node = 'FF|{{{0}|{{{1}, {2}, {3}, {4}}}{5}}}'
        peeknode = 'FF|{{{{{0}|{1}, {2}, {3}, {4}}}|{{{5}}}{6}}}'
        oidnode = 'FF|{{{0}|{{{1}|{2}, {3}, {4}, {5}}}{6}}}'
        peekoidnode = 'FF|{{{0}|{{{1}|{2}, {3}, {4}, {5}}}|{{{6}}}{7}}}'
        flowstats = self.df()[['file_action.bytes_read', 'file_action.bytes_written', 'file_action.read_ops', 'file_action.write_ops']].sum(axis=0, skipna=True)
        rb = flowstats['file_action.bytes_read']
        rop = flowstats['file_action.read_ops']
        wb = flowstats['file_action.bytes_written']
        wop = flowstats['file_action.write_ops']
        ufiles = len(self.df()['file.path'].unique())
        res = self.df()[['res', 'head.ts']].groupby(['res']).count()[['head.ts']].rename(columns={'head.ts': 'count'})
        reslist = res.index.tolist()
        details = reslist[-peeksize:] + (reslist[peeksize:] and ['...'])
        peekstr = _escape('\\n'.join(details))
        tags = '|{{{0}}}'.format(str(self.tags())) if showtags and self.tags() else ''
        if peek:
            return (
                peekoidnode.format(self.oid, ufiles, rb, rop, wb, wop, peekstr, tags)
                if withoid
                else peeknode.format(ufiles, rb, rop, wb, wop, peekstr, tags)
            )
        else:
            return (
                oidnode.format(self.oid, ufiles, rb, rop, wb, wop, tags)
                if withoid
                else node.format(ufiles, rb, rop, wb, wop, tags)
            )

    def __key(self):
        return (self.exe, self.args, self.type)

    def __hash__(self):
        return _hash(self.__key())

    def __eq__(self, other):
        if isinstance(other, FileFlowNode):
            return self.__key() == other.__key()
        return NotImplemented

    def __str__(self):
        return str(self.__key())


class NetFlowNode(Node):
    """
    **NetFlowNode**

    This class represents a netflow node.

    :param nf: a netflow node object.
    :type nf: sysflow.NetFlow
    """

    def __init__(self, oid, exe, args):
        super().__init__(oid)
        self.type = 'NF'
        self.exe = exe
        self.args = args
        self.data = list()

    def addFlow(self, r):
        self.data.append(r)

    def hasProc(self, pid, createTS):
        return True

    def df(self):
        data = OrderedDict()
        for idx, r in enumerate(self.data):
            data[idx] = r.values()
        df = pd.DataFrame.from_dict(data, orient='index', columns=r.keys() if r else None)
        # return df
        return df[((df['file_action.read_ops'] > 0) | (df['file_action.write_ops'] > 0))]

    def plot(self):
        df = self.df()
        flows = df[(df.type.isin(['NF']))]
        ax = flows[['head.ts', 'file_action.bytes_read', 'file_action.bytes_written']].plot.bar(
            x='head.ts', y=['file_action.bytes_read', 'file_action.bytes_written'], rot=45, figsize=(20, 5)
        )
        ax.xaxis.set_major_locator(mdates.AutoDateLocator())
        plt.gcf().autofmt_xdate()
        plt.show()

    def interval(self):
        ts = str(self.df()[['head.ts']].min().to_string(index=False)).strip()
        te = str(self.df()[['head.endts']].max().to_string(index=False)).strip()  # INFSYMB
        return (ts, te)

    def score(self):
        for r in self.data:
            if len(r['tags']) > 0:
                return r['tags'][2]
        return 0

    def tags(self):
        tags = set()
        for r in self.data:
            if len(r['tags']) > 0:
                for t in r['tags'][1]:
                    tags.add(str(t))
        return tags if len(tags) > 0 else None

    def dot(self, withoid=False, peek=True, peeksize=3, showtags=False):
        node = 'NF|{{{{{0}|{1}|{2}}}|{{{3}, {4}, {5}, {6}}}{7}}}'
        peeknode = 'NF|{{{{{0}|{1}|{2}}}|{{{3}, {4}, {5}, {6}}}|{{{7}}}{8}}}'
        oidnode = 'NF|{{{0}|{{{1}|{2}|{3}}}|{{{4}, {5}, {6}, {7}}}{8}}}'
        peekoidnode = 'NF|{{{0}|{{{1}|{2}|{3}}}|{{{4}, {5}, {6}, {7}}}|{{{8}}}{9}}}'
        flowstats = self.df()[['file_action.bytes_read', 'file_action.bytes_written', 'file_action.read_ops', 'file_action.write_ops']].sum(axis=0, skipna=True)
        rb = flowstats['file_action.bytes_read']
        rop = flowstats['file_action.read_ops']
        wb = flowstats['file_action.bytes_written']
        wop = flowstats['file_action.write_ops']
        uips = len(pd.unique(self.df()[['net.sip', 'net.dip']].values.ravel('K')))
        uports = len(pd.unique(self.df()[['net.sport', 'net.dport']].values.ravel('K')))
        uprotos = self.df()['net.proto'].unique()
        res = self.df()[['res', 'head.ts']].groupby(['res']).count()[['head.ts']].rename(columns={'head.ts': 'count'})
        reslist = res.index.tolist()
        details = reslist[-peeksize:] + (reslist[peeksize:] and ['...'])
        peekstr = _escape('\\n'.join(details))
        tags = '|{{{0}}}'.format(str(self.tags())) if showtags and self.tags() else ''
        if peek:
            return (
                peekoidnode.format(self.oid, uips, uports, uprotos, rb, rop, wb, wop, peekstr, tags)
                if withoid
                else peeknode.format(uips, uports, uprotos, rb, rop, wb, wop, peekstr, tags)
            )
        else:
            return (
                oidnode.format(self.oid, uips, uports, uprotos, rb, rop, wb, wop, tags)
                if withoid
                else node.format(uips, uports, uprotos, rb, rop, wb, wop, tags)
            )

    def __key(self):
        return (self.exe, self.args, self.type)

    def __hash__(self):
        return _hash(self.__key())

    def __eq__(self, other):
        if isinstance(other, NetFlowNode):
            return self.__key() == other.__key()
        return NotImplemented

    def __str__(self):
        return str(self.__key())


def _hash(o):
    return int(hashlib.md5(json.dumps(o).encode('utf-8')).hexdigest(), 16)


def _escape(s):
    return s.replace('<', '\<').replace('>', '\>').replace('{', '\{').replace('}', '\}')


def _files(path):
    """list files in dir path"""
    for file in os.listdir(path):
        if os.path.isfile(os.path.join(path, file)):
            yield os.path.join(path, file)
