import os
import json
import time
from datetime import datetime
from elasticsearch import Elasticsearch
from elasticsearch import helpers
from elasticsearch.helpers import bulk


def setSearchOptional(beginTime="2022-12-12T12:12:12", endTime=datetime.now().strftime("%Y-%m-%dT%H:%M:%S")):
    esSearchOptions = {
        "query": {
            "range":{
                "timestamp":{
                    "gte":beginTime,
                    "lte":endTime,
                }
            }
        }
    }
    return esSearchOptions


def getResult(esResult, index):
    with open(outputDir + '/' + index + '.log', 'w+') as f:
        for item in esResult:
            source = item['_source']
            if 'process' in source and 'aname' in source['process']:
                source['process']['aname'] = source['process']['aname'].split(',')
            if 'event' in source and 'opflags' in source['event']:
                source['event']['opflags'] = source['event']['opflags'].split()
            f.write(str(item['_source'])+'\n')


def getSearchResult(esSearchOptions, scroll='5m', index='events', timeout="1m"):
    esResult = helpers.scan(
        client=client,
        query=esSearchOptions,
        scroll=scroll,
        index=index,
        timeout=timeout
    )
    return esResult


def search(index):
    esSearchOptions = setSearchOptional()
    esResult = getSearchResult(esSearchOptions)
    getResult(esResult, index)


if __name__ == "__main__":
    index = "events"
    outputDir = "events"
    os.system("mkdir -p %s" % outputDir)

    t1 = time.time()
    client = Elasticsearch("http://localhost:9200")
    search(index)

    t2 = time.time()
    print("---------Done!--------", t2-t1)