#!/usr/bin/env python3

import logging
import hashlib, json
from sysflow.objtypes import ObjectTypes, OBJ_NAME_MAP
from types import SimpleNamespace

class NestedNamespace(SimpleNamespace):
    @staticmethod
    def mapEntry(entry):
        if isinstance(entry, dict):
            return NestedNamespace(**entry)
        return entry

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        for key, val in kwargs.items():
            if isinstance(val, dict):
                setattr(self, key, NestedNamespace(**val))
            elif isinstance(val, list):
                setattr(self, key, list(map(self.mapEntry, val)))
            elif isinstance(val, tuple):
                if len(val) == 2:
                    obj = val[1]
                    if isinstance(obj, dict):
                        setattr(self, key, NestedNamespace(**obj))
                    else:
                        setattr(self, key, obj)
                else:
                    setattr(self, key, tuple(map(self.mapEntry, val)))


def hashDeal(o):
    return int(hashlib.md5(json.dumps(o).encode('utf-8')).hexdigest(), 16)

class SFReader(object):
    def __init__(self, filename):
        self.filename = filename
        self.fh = open(filename, "r", encoding="utf-8")
        self.rdr = iter(self.fh.readlines())

    def __iter__(self):
        return self

    def next(self):
        record = eval(next(self.rdr))
        name = record["event"]["sf_type"]
        o = NestedNamespace(**record)
        return OBJ_NAME_MAP[name], o

    def __next__(self):
        return self.next()

    def close(self):
        self.fh.close()


class FlattenedSFReader(SFReader):
    def __init__(self, filename, retEntities=False):
        super().__init__(filename)
        self.processes = dict()
        self.files = dict()
        self.containers = dict()
        self.pods = dict()
        self.retEntities = retEntities

    def getProcess(self, oid):
        """Returns a Process Object given a process object id.

        :param oid: the object id of the Process Object requested
        :type oid: sysflow.type.OID

        :rtype: sysflow.entity.Process
        :return: the desired process object or None if no process object is available.
        """
        key = self.getProcessKey(oid)
        if key in self.processes:
            return self.processes[key]
        else:
            return None

    def getProcessKey(self, oid):
        hpid = oid.hpid
        createTS = oid.createTS
        key = hpid.to_bytes((hpid.bit_length() + 7) // 8, byteorder='little')
        key += createTS.to_bytes((createTS.bit_length() + 7) // 8, byteorder='little')
        return key
    
    def getFileKey(self, cid, path):
        key = hashDeal(cid + path)
        return key

    def __next__(self):
        while True:
            objtype, rec = super().next()
            pod = None
            container = None
            file = None

            if hasattr(rec, "pod"):
                key = rec.pod.id
                pod = rec.pod
                self.pods[key] = rec.pod
            if hasattr(rec, "container"):
                key = rec.container.id
                container = rec.container
                self.containers[key] = rec.container
            if hasattr(rec, "process"):
                process = rec.process
                key = self.getProcessKey(rec.process.oid)
                self.processes[key] = rec.process
            if hasattr(rec, "pprocess"):
                pprocess = rec.pprocess
                key = self.getProcessKey(rec.pprocess.oid)
                if key not in self.processes:
                    self.processes[key] = rec.pprocess


            if hasattr(rec, "file"):
                file = rec.file
                key = ""
                if hasattr(file, "path"):
                    key = self.getFileKey(rec.container.id, rec.file.path)
                else:
                    key = self.getFileKey(rec.container.id, rec.file.newpath)
                self.files[key] = rec
            head = rec.head if hasattr(rec, "head") else None
            event = rec.event if hasattr(rec, "event") else None
            host = rec.host if hasattr(rec, "host") else None
            file_action = rec.file_action if hasattr(rec, "file_action") else None
            network = rec.network if hasattr(rec, "network") else None
            source = rec.source if hasattr(rec, "source") else None
            destination = rec.destination if hasattr(rec, "destination") else None
            return (objtype, head, event, host, container, pod, file, file_action, network, source, destination, process, pprocess)
