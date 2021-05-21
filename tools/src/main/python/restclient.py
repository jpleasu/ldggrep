#!/usr/bin/env python3
'''
demo client to restgrep server

  from the root project directory, build restgrep with
    mvn appassembler:assemble
  start the server with
    ./tools/target/appassembler/bin/restgrep -port 8321 -showmatch
  run this script
    ./tools/src/main/python/restclient.py

'''

import sys
import pydot
import networkx as nx
import requests
import json

baseurl='http://localhost:8321/restgrep'

def nx2json(nxgraph):
  jsong={
    'vertices':[{'id':str(n), 'props':nxgraph.nodes[n]} for n in nxgraph.nodes],
    'edges':[{'id':str(e), 'srcid':e[0], 'dstid':e[1], 'props':nxgraph.edges[e]} for e in nxgraph.edges]
  }
  return jsong

def dot2json(dotfilepath):
  dotg=pydot.graph_from_dot_file(dotfilepath)[0]
  return nx2json(nx.drawing.nx_pydot.from_pydot(dotg))


def basicgraph():
  g=nx.MultiDiGraph()
  #w='abcdefghijklmnop'
  w='abcde'
  for i,n in enumerate(w):
    g.add_node(n)
    g.nodes[n]['label']=n
    g.nodes[n]['index']=i
  for d in [-1,3]:
    if d<0:
      lb,ub=-d,len(w)
    else:
      lb,ub=0,len(w)-d
    for i in range(lb,ub):
      src=w[i]
      dst=w[i+d]
      key=g.add_edge(src,dst)
      g[src][dst][key]['label']=d
  return g


def printj(msg,j):
  print(msg)
  print('  %s' % '\n  '.join(json.dumps(j,indent=2).split('\n')))

# e.g.  clang -S -emit-llvm test.c -o - | opt  -analyze -dot-callgraph 
#gj=dot2json('./callgraph.dot')
gj=nx2json(basicgraph())

printj('Setting graph to:',gj)

r=requests.post(baseurl+'/setGraph', json=gj)
if not r.ok:
  print('Setgraph Failed: %s' % (r.reason))
  sys.exit()



#for q in ['</4/> <[print(typeof(x.props)),true]>']:
#for q in ['<[print(x)]>']:
for q in ['.{2}', '.{3}', r'[label==3] <[label=="e"]>']:
  print('Sending query: %s' % q)
  r=requests.post(baseurl+'/query', json={'query':q, 'minimum':False})
  if r.ok:
    rj=r.json()
    printj('Received:',rj)
  else:
    print('Query Failed: %s' % (r.reason))
    break
