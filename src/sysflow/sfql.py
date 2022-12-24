#!/usr/bin/env python3

import os
from functools import reduce, partial
from typing import Callable, Generic, TypeVar
from frozendict import frozendict
from antlr4 import CommonTokenStream, FileStream, InputStream, ParseTreeWalker
from sysflow.grammar.sfqlLexer import sfqlLexer
from sysflow.grammar.sfqlListener import sfqlListener
from sysflow.grammar.sfqlParser import sfqlParser
from sysflow.objtypes import ObjectTypes, OBJECT_MAP
import sysflow.utils as utils

"""
.. module:: sysflow.sfql
   :synopsis: Query interpreter for SysFlow query language.
.. moduleauthor:: Frederico Araujo, Teryl Taylor
"""

T = TypeVar('T')


class SfqlInterpreter(sfqlListener, Generic[T]):
    """
    **SfqlInterpreter**

    This class takes a sfql expression (and optionally a file containining a library of
    lists and macros) and produces a predicate expression that can be matched against
    sysflow records.
    Example Usage::

         # using 'filter' to filter the input stream
         reader = FlattenedSFReader('trace.sf')
         interpreter = SfqlInterpreter()
         query = '- sfql: type = FF'
         for r in interpreter.filter(reader, query):
             print(r)

    :param interpreter: An interpreter for executing sfql expressions.
    :type interpreter: sysflow.SfqlInterpreter
    """

    _rules = {}
    _macros = {}
    _lists = {}
    _criteria = None

    def __init__(self, query: str = None, paths: list = [], inputs: list = []):
        """Create a sfql interpreter and optionally pre-compiles input expressions.

        :param query: sfql query.
        :type query: str

        :param paths: a list of paths to file containing sfql list and macro definitions.
        :type paths: list

        :param inputs: a list of input streams from where to read sfql list and macro definitions.
        :type inputs: list
        """
        super().__init__()
        self.mapper = SfqlMapper()
        self.compile(query, paths, inputs)

    def compile(self, query: str = None, paths: list = [], inputs: list = []):
        """Compile sfql into a predicate expression to match sysflow records.

        :param query: sfql query.
        :type query: str

        :param paths: a list of paths to file containing sfql list and macro definitions.
        :type paths: list

        :param inputs: a list of input streams from where to read sfql list and macro definitions.
        :type inputs: list
        """
        inputs.extend([FileStream(f) for f in paths])
        if query:
            input_stream = InputStream('- sfql: ' + query)
            inputs.append(input_stream)
        walker = ParseTreeWalker()
        for input_stream in filter(None, inputs):
            lexer = sfqlLexer(input_stream)
            stream = CommonTokenStream(lexer)
            parser = sfqlParser(stream)
            tree = parser.definitions()
            walker.walk(self, tree)

    def evaluate(self, t: T, query: str = None, paths: list = []) -> bool:
        """Evaluate sfql expression against flattened sysflow record t.

        :param reader: individual sysflow record
        :type t: flatttened record (as obtained from FlattenedSFReader)

        :param query: sfql query.
        :type query: str

        :param paths: a list of paths to file containing sfql list and macro definitions.
        :type paths: list
        """
        if query:
            self.compile(query, paths)
            return self._criteria(t)
        if not self._criteria:
            return True
        return self._criteria(t)

    def filter(self, reader, query: str = None, paths: list = []):
        """Filter iterable reader according to sfql expression.

        :param reader: sysflow reader
        :type reader: FlattenedSFReader

        :param query: sfql query.
        :type query: str

        :param paths: a list of paths to file containing sfql list and macro definitions.
        :type paths: list
        """
        if query:
            self.compile(query, paths)
        if not self._criteria:
            return reader
        return filter(lambda t: self._criteria(t), reader)

    def enrich(self, t: T):
        """Process flattened sysflow record t based on policies."""
        tags = ()  # ([], set(), 0))
        for n, r in self._rules.items():
            if r.criteria(t):
                t0 = tags[0] if tags else []
                t1 = tags[1] if tags else set()
                t2 = tags[2] if tags else 0
                tags = (t0 + [r.name], t1.union(set(r.tags)), max(t2, r.getPriorityValue()))
        return tags

    def getAttributes(self):
        """Return list of attributes supported by sfql."""
        return dict(self.mapper._mapper)

    def exitF_query(self, ctx: sfqlParser.F_queryContext):
        self._criteria = self.visitExpression(ctx.expression())

    def exitF_rule(self, ctx: sfqlParser.F_ruleContext):
        self._rules[ctx.text(0).getText()] = Rule(
            ctx.text(0).getText(),
            ctx.text(1).getText(),
            self.visitExpression(ctx.expression()),
            self._getItems(ctx.items(0).getText()),
            ctx.SEVERITY().getText(),
            self._getItems(ctx.items(1).getText()),
        )

    def exitF_macro(self, ctx: sfqlParser.F_macroContext):
        self._macros[ctx.ID().getText()] = ctx.expression()

    def exitF_list(self, ctx: sfqlParser.F_listContext):
        self._lists[ctx.ID().getText()] = [item.getText().strip('\"') for item in ctx.items().atom()]

    def _all(self, preds: Callable[[T], bool]):
        return lambda t: all(p(t) for p in preds)

    def _any(self, preds: Callable[[T], bool]):
        return lambda t: any(p(t) for p in preds)

    def _getAttr(self, t: T, attr: str):
        return self.mapper.getAttr(t, attr)

    def _evalPred(self, t: T, lop: str, pred: Callable[[str], bool]):
        return any(pred(s) for s in str(self._getAttr(t, lop)).split(','))

    def visitExpression(self, ctx: sfqlParser.ExpressionContext) -> Callable[[T], bool]:
        or_expression = ctx.getChild(0)
        or_preds = []
        if or_expression.getChildCount() > 0:
            for and_expression in or_expression.getChildren():
                if and_expression.getChildCount() > 0:
                    and_preds = []
                    for term in and_expression.getChildren():
                        if isinstance(term, sfqlParser.TermContext):
                            and_preds.append(self.visitTerm(term))
                    or_preds.append(self._all(and_preds))
        return self._any(or_preds)

    def visitTerm(self, ctx: sfqlParser.TermContext) -> Callable[[T], bool]:
        if ctx.var():
            var = ctx.var().getText()
            if var in self._macros:
                return self.visitExpression(self._macros[var])
            else:
                raise Exception('SFQL error: unrecognized reference {0}'.format(var))
        elif ctx.NOT():
            return lambda t: not self.visitTerm(ctx.getChild(1))(t)
        elif ctx.unary_operator():
            lop = ctx.getChild(0).getText()
            if ctx.unary_operator().EXISTS():
                return lambda t: not not self._getAttr(t, lop)
            else:
                raise Exception('SFQL syntax error: unrecognized term {0}'.format(ctx.getText()))
        elif ctx.binary_operator():
            lop = ctx.atom(0).getText()
            rop = lambda t: self.mapper.getAttr(t, ctx.atom(1).getText())
            if ctx.binary_operator().CONTAINS():
                return lambda t: self._evalPred(t, lop, lambda s: str(rop(t)) in s)
            elif ctx.binary_operator().ICONTAINS():
                return lambda t: self._evalPred(t, lop, lambda s: str(rop(t)).lower() in s.lower())
            elif ctx.binary_operator().STARTSWITH():
                return lambda t: self._evalPred(t, lop, lambda s: s.startswith(str(rop(t))))
            elif ctx.binary_operator().EQ():
                return lambda t: self._evalPred(t, lop, lambda s: s == str(rop(t)))
            elif ctx.binary_operator().NEQ():
                return lambda t: self._evalPred(t, lop, lambda s: s != str(rop(t)))
            elif ctx.binary_operator().GT():
                return lambda t: self._evalPred(t, lop, lambda s: int(s) > int(rop(t)))
            elif ctx.binary_operator().GE():
                return lambda t: self._evalPred(t, lop, lambda s: int(s) >= int(rop(t)))
            elif ctx.binary_operator().LT():
                return lambda t: self._evalPred(t, lop, lambda s: int(s) < int(rop(t)))
            elif ctx.binary_operator().LE():
                return lambda t: self._evalPred(t, lop, lambda s: int(s) >= int(rop(t)))
            else:
                raise Exception('SFQL syntax error: unrecognized term {0}'.format(ctx.getText()))
        elif ctx.expression():
            return self.visitExpression(ctx.expression())
        elif ctx.IN():
            lop = ctx.atom(0).getText()
            rop = self._getList(ctx)
            return lambda t: self._evalPred(t, lop, lambda s: s in rop)
        elif ctx.PMATCH():
            lop = ctx.atom(0).getText()
            rop = self._getList(ctx)
            return lambda t: any(self._evalPred(t, lop, lambda s: e in s) for e in rop)
        else:
            raise Exception('SFQL syntax error: unrecognized term {0}'.format(ctx.getText()))
        return lambda t: False

    def _getItems(self, l: str) -> list:
        return l[1:-1].split(',')

    def _getList(self, ctx: sfqlParser.TermContext) -> list:
        lst = []
        for item in ctx.atom()[1:]:
            lst.extend(self._reduceList(item.getText().strip('\"')))
        return lst

    def _reduceList(self, l: str) -> list:
        lst = []
        if l in self._lists:
            for item in self._lists.get(l):
                lst.extend(self._reduceList(item))
        else:
            lst.append(l)
        return lst


class SfqlMapper(Generic[T]):

    _ptree = {}

    @staticmethod
    def _rgetattr(obj, attr, *args):
        def _getattr(obj, attr):
            return getattr(obj, attr, *args) if obj else None

        return reduce(_getattr, [obj] + attr.split('.'))

    @staticmethod
    def _getPathBasename(path: str):
        return os.path.basename(os.path.normpath(path))

    @staticmethod
    def _getObjType(t: T, attr: str = None):
        return OBJECT_MAP.get(t[0], '?')
    
    @staticmethod
    def _getHeadAttr(t: T, attr: str):
        head = t[1]
        if not head:
            return None
        return SfqlMapper._rgetattr(head, attr)

    @staticmethod
    def _getEventAttr(t: T, attr: str):
        event = t[2]
        if not event:
            return None
        return SfqlMapper._rgetattr(event, attr)

    @staticmethod
    def _getHostAttr(t: T, attr: str):
        host = t[3]
        if not host:
            return None
        return SfqlMapper._rgetattr(host, attr)

    @staticmethod
    def _getContainerAttr(t: T, attr: str):
        container = t[4]
        if not container:
            return None
        return SfqlMapper._rgetattr(container, attr)
    
    @staticmethod
    def _getPodAttr(t: T, attr: str):
        pod = t[5]
        if not pod:
            return None
        return SfqlMapper._rgetattr(pod, attr)

    @staticmethod
    def _getFileAttr(t: T, attr: str):
        file = t[6]
        if not file:
            return None
        return SfqlMapper._rgetattr(file, attr)

    @staticmethod
    def _getFileActionAttr(t: T, attr: str):
        sf_file_action = t[7]
        if not sf_file_action:
            return None
        return SfqlMapper._rgetattr(sf_file_action, attr)    

    @staticmethod
    def _getNetworkAttr(t: T, attr: str):
        network = t[8]
        if not network:
            return None
        return SfqlMapper._rgetattr(network, attr)   

    @staticmethod
    def _getSourceAttr(t: T, attr: str):
        source = t[9]
        if not source:
            return None
        return SfqlMapper._rgetattr(source, attr)   

    @staticmethod
    def _getDestinationAttr(t: T, attr: str):
        destination = t[10]
        if not destination:
            return None
        return SfqlMapper._rgetattr(destination, attr)   
    
    @staticmethod
    def _getProcessAttr(t: T, attr: str):
        process = t[11]
        if not process:
            return None
        return SfqlMapper._rgetattr(process, attr)   

    @staticmethod
    def _getParentAttr(t: T, attr: str):
        parent = t[12]
        if not parent:
            return None
        return SfqlMapper._rgetattr(parent, attr)   

    @staticmethod
    def _getUserAttr(t: T, attr: str):
        user = t[13]
        if not user:
            return None
        return SfqlMapper._rgetattr(user, attr)   

    _mapper = {
        'head.ts': partial(_getHeadAttr.__func__, attr='ts'),
        'head.endts': partial(_getHeadAttr.__func__, attr='endts'),
        'head.type': partial(_getHeadAttr.__func__, attr='type'),

        'event.action': partial(_getEventAttr.__func__, attr='action'),
        'event.category': partial(_getEventAttr.__func__, attr='category'),
        'event.kind': partial(_getEventAttr.__func__, attr='kind'),
        'event.sf_ret': partial(_getEventAttr.__func__, attr='sf_ret'),
        'event.sf_type': partial(_getEventAttr.__func__, attr='sf_type'),
        'event.type': partial(_getEventAttr.__func__, attr='type'),
        'event.opflags': partial(_getEventAttr.__func__, attr="opflags"),
        'event.opflags_int': partial(_getEventAttr.__func__, attr="opflags_int"),

        'host.id': partial(_getHostAttr.__func__, attr='id'),
        'host.ip': partial(_getHostAttr.__func__, attr='ip'),

        'container.id': partial(_getContainerAttr.__func__, attr='id'),
        'container.image.id': partial(_getContainerAttr.__func__, attr='image.id'),
        'container.image.name': partial(_getContainerAttr.__func__, attr='image.name'),
        'container.name': partial(_getContainerAttr.__func__, attr='name'),
        'container.runtime': partial(_getContainerAttr.__func__, attr='runtime'),
        'container.privileged': partial(_getContainerAttr.__func__, attr='privileged'),

        'pod.ts': partial(_getPodAttr.__func__, attr='ts'),
        'pod.id': partial(_getPodAttr.__func__, attr='id'),
        'pod.name': partial(_getPodAttr.__func__, attr='name'),
        'pod.namespace': partial(_getPodAttr.__func__, attr='namespace'),
        'pod.nodename': partial(_getPodAttr.__func__, attr='nodename'),
        'pod.hostip': partial(_getPodAttr.__func__, attr='hostip'),
        'pod.internalip': partial(_getPodAttr.__func__, attr='internalip'),
        'pod.restartcnt': partial(_getPodAttr.__func__, attr='restartcnt'),

        'file.directory': partial(_getFileAttr.__func__, attr='directory'),
        'file.name': partial(_getFileAttr.__func__, attr='name'),
        'file.oid': partial(_getFileAttr.__func__, attr="oid"),
        'file.path': partial(_getFileAttr.__func__, attr='path'),
        'file.type': partial(_getFileAttr.__func__, attr='type'),

        'file_action.bytes_read': partial(_getFileActionAttr.__func__, attr='bytes_read'),
        'file_action.read_ops': partial(_getFileActionAttr.__func__, attr='read_ops'),
        'file_action.bytes_written': partial(_getFileActionAttr.__func__, attr='bytes_written'),
        'file_action.write_ops': partial(_getFileActionAttr.__func__, attr='write_ops'),
        'file_action.gap_time': partial(_getFileActionAttr.__func__, attr='write_time'),

        'network.bytes': partial(_getNetworkAttr.__func__, attr="bytes"),
        'network.community_id': partial(_getNetworkAttr.__func__, attr="community_id"),
        'network.protocol': partial(_getNetworkAttr.__func__, attr="protocol"),

        'source.address': partial(_getSourceAttr.__func__, attr='address'),
        'source.bytes': partial(_getSourceAttr.__func__, attr='bytes'),
        'source.ip': partial(_getSourceAttr.__func__, attr='ip'),
        'source.packets': partial(_getSourceAttr.__func__, attr='packets'),
        'source.port': partial(_getSourceAttr.__func__, attr='port'),

        'destination.address': partial(_getDestinationAttr.__func__, attr='address'),
        'destination.bytes': partial(_getDestinationAttr.__func__, attr='bytes'),
        'destination.ip': partial(_getDestinationAttr.__func__, attr='ip'),
        'destination.packets': partial(_getDestinationAttr.__func__, attr='packets'),
        'destination.port': partial(_getDestinationAttr.__func__, attr='port'),

        'process.args': partial(_getProcessAttr.__func__, attr='args'),
        'process.command_line': partial(_getProcessAttr.__func__, attr='command_line'),
        'process.exe': partial(_getProcessAttr.__func__, attr='exe'),
        'process.name': partial(_getProcessAttr.__func__, attr='name'),
        'process.aname': partial(_getProcessAttr.__func__, attr='aname'),
        'process.tid': partial(_getProcessAttr.__func__, attr='tid'),
        'process.start': partial(_getProcessAttr.__func__, attr='start'),
        'process.tty': partial(_getProcessAttr.__func__, attr='tty'),
        'process.oid.hpid': partial(_getProcessAttr.__func__, attr='oid.hpid'),
        'process.oid.createTS': partial(_getProcessAttr.__func__, attr='oid.createTS'),
        'process.uid': partial(_getProcessAttr.__func__, attr='uid'),
        'process.user': partial(_getProcessAttr.__func__, attr='user'),
        'process.gid': partial(_getProcessAttr.__func__, attr='gid'),
        'process.group': partial(_getProcessAttr.__func__, attr='group'),

        'pprocess.args': partial(_getProcessAttr.__func__, attr='args'),
        'pprocess.command_line': partial(_getProcessAttr.__func__, attr='command_line'),
        'pprocess.exe': partial(_getProcessAttr.__func__, attr='exe'),
        'pprocess.name': partial(_getProcessAttr.__func__, attr='name'),
        'pprocess.start': partial(_getProcessAttr.__func__, attr='start'),
        'pprocess.tty': partial(_getProcessAttr.__func__, attr='tty'),
        'pprocess.oid.hpid': partial(_getProcessAttr.__func__, attr='oid.hpid'),
        'pprocess.oid.createTS': partial(_getProcessAttr.__func__, attr='oid.createTS'),
        'pprocess.uid': partial(_getProcessAttr.__func__, attr='uid'),
        'pprocess.user': partial(_getProcessAttr.__func__, attr='user'),
        'pprocess.gid': partial(_getProcessAttr.__func__, attr='gid'),
        'pprocess.group': partial(_getProcessAttr.__func__, attr='group'),

        'user.group.id': partial(_getUserAttr.__func__, attr='group.id'),
        'user.group.name': partial(_getUserAttr.__func__, attr='group.name'),
        'user.id': partial(_getUserAttr.__func__, attr='id'),
        'user.name': partial(_getUserAttr.__func__, attr='name'),
    }

    def __init__(self):
        super().__init__()

    def hasAttr(self, attr: str):
        return attr in self._mapper

    def getAttr(self, t: T, attr: str):
        if self.hasAttr(attr):
            return self._mapper[attr](t)
        else:
            return attr.strip('\"')


class Rule:
    def __init__(self, name, desc, criteria, actions, priority, tags):
        self.name = name
        self.desc = desc
        self.criteria = criteria
        self.actions = actions
        self.priority = priority
        self.tags = tags

    def getPriorityValue(self):
        return {'none': 0, 'low': 1, 'medium': 2, 'high': 3}[self.priority]
