#!/usr/bin/env python3

import os, json, csv
from collections import OrderedDict
from functools import reduce
import sysflow.utils as utils
from sysflow.objtypes import ObjectTypes, OBJECT_MAP
from sysflow.sfql import SfqlInterpreter
import tabulate

tabulate.PRESERVE_WHITESPACE = True
from tabulate import tabulate
from dotty_dict import dotty
import pandas as pd
from sysflow.reader import NestedNamespace

"""
.. module:: sysflow.formatter
   :synopsis: This module allows SysFlow to be exported in formats other than avro including JSON, CSV, and tabular pretty print
.. moduleauthor:: Frederico Araujo, Teryl Taylor
"""

_version = '4'

_default_fields = [
    'event.start',
    'event.sf_type',
    'process.exe',
    'process.args',
    'pprocess.oid.hpid',
    'process.oid.hpid',
    'process.tid',
    'file_action.bytes_read',
    'file_action.bytes_written',
    'container.id',
    'container.name'
]

_fields = {  #   '<key>': (<columnn name>, <column width>, <description>, <query_only>)
    'idx': ('Rec #', 6, 'Record number', False),
    'res': ('Resource', 45, 'File or network resource', False),

    'head.ts': ('head.ts', 10, 'Head ts', False),
    'head.endts': ('head.endts', 10, 'Head endts', False),
    'head.type': ('head.type', 10, 'Head type', False),

    'event.action': ('event.action', 10, 'Event action', False),
    'event.category': ('event.category', 10, 'Event category', False),
    'event.kind': ('event.kind', 10, 'Event kind', False),
    'event.sf_ret': ('event.sf_ret', 10, 'Event sf_ret', False),
    'event.type': ('event.type', 10, 'Event type', False),
    'event.opflags': ('event.opflags', 10, 'Event opflags', False),
    'event.opflags_int': ('event.opflags_int', 10, 'Event opflags_int', False),

    'host.id': ('host.id', 10, 'Host id', False),
    'host.ip': ('host.ip', 10, 'Host ip', False),

    'container.id': ('container.id', 10, 'Container id', False),
    'container.image.id': ('container.image.id', 10, 'Container image', False),
    'container.image.name': ('container.image.name', 10, 'Container image', False),
    'container.name': ('container.name', 10, 'Container name', False),
    'container.runtime': ('container.runtime', 10, 'Container runtime', False),
    'container.privileged': ('container.privileged', 10, 'Container privileged', False),

    'pod.ts': ('pod.ts', 10, 'Pod ts', False),
    'pod.id': ('pod.id', 10, 'Pod id', False),
    'pod.name': ('pod.name', 10, 'Pod name', False),
    'pod.namespace': ('pod.namespace', 10, 'Pod namespace', False),
    'pod.nodename': ('pod.nodename', 10, 'Pod nodename', False),
    'pod.hostip': ('pod.hostip', 10, 'Pod hostip', False),
    'pod.internalip': ('pod.internalip', 10, 'Pod internalip', False),
    'pod.restartcnt': ('pod.restartcnt', 10, 'Pod restartcnt', False),

    'file.directory': ('file.directory', 10, 'File directory', False),
    'file.name': ('file.name', 10, 'File name', False),
    'file.oid': ('file.oid', 16, 'File oid', False),
    'file.path': ('file.path', 10, 'File path', False),
    'file.type': ('file.type', 10, 'File type', False),

    'file_action.bytes_read': ('file_action.bytes_read', 10, 'File_Action bytes_read', False),
    'file_action.read_ops': ('file_action.read_ops', 10, 'File_Action read_ops', False),
    'file_action.bytes_written': ('file_action.bytes_written', 10, 'File_Action bytes_written', False),
    'file_action.write_ops': ('file_action.write_ops', 10, 'File_Action write_ops', False),
    'file_action.gap_time': ('file_action.gap_time', 10, 'File_Action gap_time', False),

    'network.bytes': ('network.bytes', 10, 'Network bytes', False),
    'network.community_id': ('network.community_id', 10, 'Network community_id', False),
    'network.protocol': ('network.protocol', 10, 'Network protocol', False),

    'source.address': ('source.address', 10, 'Source address', False),
    'source.bytes': ('source.bytes', 10, 'Source bytes', False),
    'source.ip': ('source.ip', 10, 'Source ip', False),
    'source.packets': ('source.packets', 10, 'Source packets', False),
    'source.port': ('source.port', 10, 'Source port', False),

    'destination.address': ('destination.address', 10, 'Destination address', False),
    'destination.bytes': ('destination.bytes', 10, 'Destination bytes', False),
    'destination.ip': ('destination.ip', 10, 'Destination ip', False),
    'destination.packets': ('destination.packets', 10, 'Destination packets', False),
    'destination.port': ('destination.port', 10, 'Destination port', False),

    'process.args': ('process.args', 10, 'Process args', False),
    'process.command_line': ('process.command_line', 10, 'Process command_line', False),
    'process.exe': ('process.exe', 10, 'Process exe', False),
    'process.name': ('process.name', 10, 'Process name', False),
    'process.aname': ('process.aname', 10, 'Process ancester name', False),
    'process.tid': ('process.tid', 10, 'Process thread id', False),
    'process.start': ('process.start', 10, 'Process start', False),
    'process.tty': ('process.tty', 10, 'Process tty', False),
    'process.oid.hpid': ('process.oid.hpid', 10, 'Process hpid', False),
    'process.oid.createTS': ('process.oid.createTS', 10, 'Process createTS', False),
    'process.uid': ('process.uid', 10, 'Process user id', False),
    'process.user': ('process.user', 10, 'Process user name', False),
    'process.gid': ('process.gid', 10, 'Process group id', False),
    'process.group': ('process.group', 10, 'Process group name', False),

    'pprocess.args': ('pprocess.args', 10, 'Parent Process args', False),
    'pprocess.command_line': ('pprocess.command_line', 10, 'Parent Process command_line', False),
    'pprocess.exe': ('pprocess.exe', 10, 'Parent Process exe', False),
    'pprocess.name': ('pprocess.name', 10, 'Parent Process name', False),
    'pprocess.start': ('pprocess.start', 10, 'Parent Process start', False),
    'pprocess.tty': ('pprocess.tty', 10, 'Parent Process tty', False),
    'pprocess.oid.hpid': ('pprocess.oid.hpid', 10, 'Parent Process hpid', False),
    'pprocess.oid.createTS': ('pprocess.oid.createTS', 10, 'Parent Process createTS', False),
    'pprocess.uid': ('pprocess.uid', 10, 'Parent Process user id', False),
    'pprocess.user': ('pprocess.user', 10, 'Parent Process user name', False),
    'pprocess.gid': ('pprocess.gid', 10, 'Parent Process group id', False),
    'pprocess.group': ('pprocess.group', 10, 'Parent Process group name', False),
}


class SFFormatter(object):
    """
    **SFFormatter**

    This class takes a `FlattenedSFReader`, and exports SysFlow as either JSON, CSV or Pretty Print .
    Example Usage::

        reader = FlattenedSFReader(trace, False)
        formatter = SFFormatter(reader)
        fields=args.fields.split(',') if args.fields else None
        if args.output == 'json':
            if args.file is not None:
                formatter.toJsonFile(args.file, fields=fields)
            else:
                formatter.toJsonStdOut(fields=fields)
        elif args.output == 'csv' and args.file is not None:
            formatter.toCsvFile(args.file, fields=fields)
        elif args.output == 'str':
            formatter.toStdOut(fields=fields)

    :param reader: A reader representing the sysflow file being read.
    :type reader: sysflow.reader.FlattenedSFReader

    :param defs: A list of paths to filter definitions.
    :type defs: list
    """

    def __init__(self, reader, defs=[]):
        self.reader = reader
        self.sfqlint = SfqlInterpreter()
        self.defs = defs
        self.allFields = False

    # def enableK8sEventFields(self):
    #     """Enables fields related to k8s events be added to the output by default."""
    #     global _default_fields
    #     _default_fields = [
    #         'ts_uts',
    #         'type',
    #         'k8s.action',
    #         'k8s.kind',
    #         'k8s.msg',
    #     ]

    def enablePodFields(self):
        """Enables fields related to pods to be added to the output by default."""
        global _default_fields
        _default_fields.append('pod.name')

    def enableAllFields(self):
        """Enables all available fields to be added to the output by default."""
        self.allFields = True

    def toDataframe(self, fields=None, expr=None):
        """Enables a delegate function to be applied to each JSON record read.

        :param func: delegate function of the form func(str)
        :type func: function

        :param fields: a list of the SysFlow fields to be exported in the JSON.  See
                       formatter.py for a list of fields
        :type fields: list

        :param expr: a sfql filter expression
        :type expr: str
        """
        _r = None
        data = OrderedDict()
        for idx, r in enumerate(self.sfqlint.filter(self.reader, expr, self.defs)):
            _r = self._flatten(*r, fields)
            data[idx] = _r.values()
        return pd.DataFrame.from_dict(data, orient='index', columns=_r.keys() if _r else None)

    def applyFuncJson(self, func, fields=None, expr=None):
        """Enables a delegate function to be applied to each JSON record read.

        :param func: delegate function of the form func(str)
        :type func: function

        :param fields: a list of the SysFlow fields to be exported in JSON. See
                       formatter.py for a list of fields
        :type fields: list

        :param expr: a sfql filter expression
        :type expr: str
        """
        for r in self.sfqlint.filter(self.reader, expr, self.defs):
            record = self._flatten(*r, fields)
            func(json.dumps(record))

    def toJson(self, fields=None, flat=False, expr=None):
        """Writes SysFlow as JSON object.

        :param fields: a list of the SysFlow fields to be exported in JSON. See
                       formatter.py for a list of fields
        :type fields: list
        :flat: specifies if JSON output should be flattened

        :param expr: a sfql filter expression
        :type expr: str
        """
        __format = self._flatten if flat else self._nest
        recs = [__format(*r, fields) for r in self.sfqlint.filter(self.reader, expr, self.defs)]
        return json.dumps(recs)

    def toJsonStdOut(self, fields=None, flat=False, expr=None):
        """Writes SysFlow as JSON to stdout.

        :param fields: a list of the SysFlow fields to be exported in JSON. See
                       formatter.py for a list of fields
        :type fields: list
        :flat: specifies if JSON output should be flattened

        :param expr: a sfql filter expression
        :type expr: str
        """
        __format = self._flatten if flat else self._nest
        for r in self.sfqlint.filter(self.reader, expr, self.defs):
            record = __format(*r, fields)
            print(json.dumps(record))

    def toJsonFile(self, path, fields=None, flat=False, expr=None):
        """Writes SysFlow to JSON file.

        :param path: the full path of the output file.
        :type path: str

        :param fields: a list of the SysFlow fields to be exported in JSON. See
                       formatter.py for a list of fields
        :type fields: list
        :flat: specifies if JSON output should be flattened

        :param expr: a sfql filter expression
        :type expr: str
        """
        __format = self._flatten if flat else self._nest
        with open(path, mode='w') as jsonfile:
            json.dump([__format(*r, fields) for r in self.sfqlint.filter(self.reader, expr, self.defs)], jsonfile)

    def toCsvFile(self, path, fields=None, header=True, expr=None):
        """Writes SysFlow to CSV file.

        :param path: the full path of the output file.
        :type path: str

        :param fields: a list of the SysFlow fields to be exported in the JSON.  See
                       formatter.py for a list of fields
        :type fields: list

        :param expr: a sfql filter expression
        :type expr: str
        """
        with open(path, mode='w') as csv_file:
            for idx, r in enumerate(self.sfqlint.filter(self.reader, expr, self.defs)):
                record = self._flatten(*r, fields)
                if idx == 0:
                    fieldnames = list(record.keys())
                    writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
                    if header:
                        writer.writeheader()
                writer.writerow(record)

    def toStdOut(self, fields=_default_fields, pretty_headers=True, showindex=True, expr=None):
        """Writes SysFlow as a tabular pretty print form to stdout.

        :param fields: a list of the SysFlow fields to be exported in the JSON.  See
                       formatter.py for a list of fields
        :type fields: list

        :param pretty_headers: print table headers in pretty format.
        :type pretty_headers: bool

        :param showindex: show record number.
        :type showindex: bool

        :param expr: a sfql filter expression
        :type expr: str
        """
        fields = _default_fields if fields is None else fields
        headers = self._header_map() if pretty_headers else 'keys'
        colwidths = self._colwidths()
        bulkRecs = []
        first = True
        # compute relative size of columns based on terminal width
        sel = {k: v for (k, v) in colwidths.items() if k in fields}
        tw = reduce(lambda w1, w2: w1 + w2, sel.values())
        pw = len(sel) * 6 + 10
        wf = min((self._get_terminal_size()[0] - pw) / tw, 1.25)

        for idx, r in enumerate(self.sfqlint.filter(self.reader, expr, self.defs)):
            record = self._flatten(*r, fields)
            if showindex:
                record['idx'] = idx
                record.move_to_end('idx', last=False)
            for key, value in record.items():
                sw = int(wf * (colwidths[key]))
                w = sw if sw > 8 else colwidths[key]
                if not isinstance(value, str) and not isinstance(value, int):
                    data = '{0: <{width}}'.format('' if value is None else json.dumps(value), width=w)
                else:
                    data = '{0: <{width}}'.format('' if value is None else value, width=w)
                record[key] = (data[w:] and '..') + data[-w:]
            bulkRecs.append(record)
            if idx > 0 and idx % 1000 == 0:
                if first:
                    print(tabulate(bulkRecs, headers=headers, tablefmt='github'))
                    first = False
                else:
                    print(tabulate(bulkRecs, tablefmt='github'))
                bulkRecs = []

        if len(bulkRecs) > 0:
            if first:
                print(tabulate(bulkRecs, headers=headers, tablefmt='github'))
            else:
                print(tabulate(bulkRecs, tablefmt='github'))

    def getFields(self):
        """Returns a list with available SysFlow fields and their descriptions."""
        return [(k, v[2]) for (k, v) in _fields.items()]

    def _header_map(self):
        return {k: v[0] for (k, v) in _fields.items() if not v[3]}

    def _colwidths(self):
        return {k: v[1] for (k, v) in _fields.items() if not v[3]}

    def _get_terminal_size(self, fallback=(80, 24)):
        for i in range(0, 3):
            try:
                columns, row = os.get_terminal_size(i)
            except OSError:
                continue
            break
        else:  # set default if the loop completes which means all failed
            columns, row = fallback
        return columns, row

    def _flatten(self, objtype, head, event, host, container, pod, file, file_action, network, source, destination, process, pprocess, fields, tags=None):
        _flat_map = OrderedDict()
        _flat_map['type'] = OBJECT_MAP.get(objtype, '?')
        if object in [ObjectTypes.FILE_FLOW, ObjectTypes.FILE_EVT]:
            _flat_map['res'] = file.path if file else ''
        elif objtype in [ObjectTypes.NET_FLOW]:
            _flat_map['res'] = source.ip + ":" + str(source.port) + "-" + destination.ip + ":" + str(destination.port)
        else:
            _flat_map['res'] = ''

        _flat_map['head.ts'] = head.ts if head else ''
        _flat_map['head.endts'] = head.endts if head else ''
        _flat_map['head.type'] = head.type if head else ''

        _flat_map['event.actoin'] = event.action if event else ''
        _flat_map['event.category'] = event.category if event else ''
        _flat_map['event.kind'] = event.kind if event else ''
        _flat_map['event.sf_ret'] = event.sf_ret if event and hasattr(event, "sf_ret") else None
        _flat_map['event.sf_type'] = event.sf_type if event else None
        _flat_map['event.type'] = event.type if event else ''
        _flat_map['event.opflags'] = event.type if event else ''
        _flat_map['event.opflags_int'] = event.type if event else ''

        _flat_map['host.id'] = host.id if host else ''
        _flat_map['host.ip'] = host.ip if host else ''

        _flat_map['container.id'] = container.id if container else ''
        _flat_map['container.image.id'] = container.image.id if container else ''
        _flat_map['container.image.name'] = container.image.name if container else ''
        _flat_map['container.name'] = container.name if container else ''
        _flat_map['container.runtime'] = container.runtime if container else ''
        _flat_map['container.privileged'] = container.privileged if container else ''

        _flat_map['pod.ts'] = pod.ts if pod else ''
        _flat_map['pod.id'] = pod.id if pod else ''
        _flat_map['pod.name'] = pod.name if pod else ''
        _flat_map['pod.namespace'] = pod.namespace if pod else ''
        _flat_map['pod.nodename'] = pod.nodename if pod else ''
        _flat_map['pod.hostip'] = pod.hostip if pod else ''
        _flat_map['pod.internalip'] = pod.internalip if pod else ''
        _flat_map['pod.restartcnt'] = pod.restartcnt if pod else None

        _flat_map['file.directory'] = file.directory if file else ''
        _flat_map['file.name'] = file.name if file else ''
        _flat_map['file.path'] = file.path if file else ''
        _flat_map['file.type'] = file.type if file else ''

        _flat_map['file_action.bytes_read'] = file_action.bytes_read if file_action else None
        _flat_map['file_action.read_ops'] = file_action.read_ops if file_action else None
        _flat_map['file_action.bytes_written'] = file_action.bytes_written if file_action else None
        _flat_map['file_action.write_ops'] = file_action.write_ops if file_action else None
        _flat_map['file_action.gap_time'] = file_action.gap_time if file_action else None

        _flat_map['network.bytes'] = network.bytes if network else None
        _flat_map['network.community_id'] = network.community_id if network else ''
        _flat_map['network.protocol'] = network.protocol if network else ''

        _flat_map['source.address'] = source.address if source else ''
        _flat_map['source.bytes'] = source.bytes if source else None
        _flat_map['source.ip'] = source.ip if source else ''
        _flat_map['source.packets'] = source.packets if source else None
        _flat_map['source.port'] = source.port if source else None

        _flat_map['destination.address'] = destination.address if destination else ''
        _flat_map['destination.bytes'] = destination.bytes if destination else None
        _flat_map['destination.ip'] = destination.ip if destination else ''
        _flat_map['destination.packets'] = destination.packets if destination else None
        _flat_map['destination.port'] = destination.port if destination else None       

        _flat_map['process.args'] = process.args if process else ''
        _flat_map['process.command_line'] = process.command_line if process else ''
        _flat_map['process.exe'] = process.exe if process else ''
        _flat_map['process.name'] = process.name if process else ''
        _flat_map['process.aname'] = process.aname if process else ''
        _flat_map['process.tid'] = process.tid if process else ''
        _flat_map['process.start'] = process.start if process else ''
        _flat_map['process.tty'] = process.tty if process else None
        _flat_map['process.oid.hpid'] = process.oid.hpid if process else None
        _flat_map['process.oid.createTS'] = process.oid.createTS if process else None
        _flat_map['process.uid'] = process.uid if process else None
        _flat_map['process.user'] = process.user if process else None
        _flat_map['process.gid'] = process.gid if process else None
        _flat_map['process.group'] = process.group if process else None

        _flat_map['pprocess.args'] = pprocess.args if pprocess else ''
        _flat_map['pprocess.command_line'] = pprocess.command_line if pprocess else ''
        _flat_map['pprocess.exe'] = pprocess.exe if pprocess else ''
        _flat_map['pprocess.name'] = pprocess.name if pprocess else ''
        _flat_map['pprocess.start'] = pprocess.start if pprocess else ''
        _flat_map['pprocess.tty'] = pprocess.tty if pprocess else None
        _flat_map['pprocess.oid.hpid'] = pprocess.oid.hpid if pprocess else None
        _flat_map['pprocess.oid.createTS'] = pprocess.oid.createTS if pprocess else None
        _flat_map['pprocess.uid'] = pprocess.uid if pprocess else None
        _flat_map['pprocess.user'] = pprocess.user if pprocess else None
        _flat_map['pprocess.gid'] = pprocess.gid if pprocess else None
        _flat_map['pprocess.group'] = pprocess.group if pprocess else None

        if not self.allFields and fields:
            od = OrderedDict()
            for k in fields:
                od[k] = _flat_map[k] if k in _flat_map else ''
            return od

        return _flat_map

    def _nest(self, objtype, event, host, container, pod, file, sf_file_action, network, source, destination, process, pprocess, fields):
        d = dotty()
        r = self._flatten(objtype, event, host, container, pod, file, sf_file_action, network, source, destination, process, pprocess, fields)
        for k, v in r.items():
            d[k] = v
        return d.to_dict()

    def _obj_to_dict(self, obj):
        if isinstance(obj, list):
            ret = list(map(self._obj_to_dict, obj))
        elif isinstance(obj, NestedNamespace):
            ret = {key: self._obj_to_dict(getattr(obj, key)) for key in vars(obj)}
            # need to handle the special case of 'clusterIP's in the service dict in order to convert back Int to string with IP address
            # if 'clusterIP' in ret:
            #     ret['clusterIP'] = list(map(utils.getIpIntStr, ret['clusterIP']))
        elif isinstance(obj, str) or isinstance(obj, int):
            ret = obj
        else:
            print(f'ERROR: Cannot handle type {type(obj)} for {obj}')
            ret = None
        return ret
