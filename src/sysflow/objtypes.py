#!/usr/bin/env python3

from enum import Enum

"""
.. module:: sysflow.objtypes
   :synopsis: This module represents each entity/flow/event class as a ID, and maps those ids to strings.
.. moduleauthor:: Frederico Araujo, Teryl Taylor
"""


class ObjectTypes(Enum):
    """
    **ObjectTypes**

    Enumeration representing each of the object types:
       HEADER = 0,
       CONT = 1,
       PROC = 2,
       FILE = 3,
       PROC_EVT = 4,
       NET_FLOW = 5,
       FILE_FLOW = 6,
       FILE_EVT = 7
       PROC_FLOW = 8
       POD = 9
       K8S_EVT = 10

    """

    HEADER = 0
    CONT = 1
    PROC = 2
    FILE = 3
    PROC_EVT = 4
    NET_FLOW = 5
    FILE_FLOW = 6
    FILE_EVT = 7
    NET_EVT = 8
    PROC_FLOW = 9
    POD = 10
    K8S_EVT = 11


OBJECT_MAP = {
    ObjectTypes.HEADER: "H",
    ObjectTypes.CONT: "C",
    ObjectTypes.PROC: "P",
    ObjectTypes.FILE: "F",
    ObjectTypes.PROC_EVT: "PE",
    ObjectTypes.NET_FLOW: "NF",
    ObjectTypes.FILE_FLOW: "FF",
    ObjectTypes.FILE_EVT: "FE",
    ObjectTypes.NET_EVT: "NE",
    ObjectTypes.PROC_FLOW: "PF",
    ObjectTypes.POD: "POD",
    ObjectTypes.K8S_EVT: "KE",
}

OBJ_NAME_MAP = {
    "H": ObjectTypes.HEADER,
    "C": ObjectTypes.CONT,
    "P": ObjectTypes.PROC,
    "F": ObjectTypes.FILE,
    "PE": ObjectTypes.PROC_EVT,
    "FE": ObjectTypes.FILE_EVT,
    "NF": ObjectTypes.NET_FLOW,
    "FF": ObjectTypes.FILE_FLOW,
    "NE": ObjectTypes.NET_EVT,
    "PF": ObjectTypes.PROC_FLOW,
    "POD": ObjectTypes.POD,
    "KE": ObjectTypes.K8S_EVT,
}
