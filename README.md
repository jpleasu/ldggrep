# LDGGrep

A path query tool for program analysis.

<!-- vim-markdown-toc GFM -->

- [LDGGrep](#ldggrep)
  - [Overview](#overview)
  - [Ghidra extension](#ghidra-extension)
    - [Usage](#usage)
    - [Building the Ghidra extension (on Linux)](#building-the-ghidra-extension-on-linux)
  - [LDGGrep tools](#ldggrep-tools)
    - [Building tools](#building-tools)
    - [`javagrep`](#javagrep)
    - [`gfgrep`](#gfgrep)
    - [`restgrep`](#restgrep)
  - [Introduction to LDGGrep queries](#introduction-to-ldggrep-queries)
    - [from regular expressions](#from-regular-expressions)
    - [predicates](#predicates)
    - [node predicates](#node-predicates)
    - [grammar](#grammar)
  - [LDGGrep changelog](#ldggrep-changelog)

<!-- vim-markdown-toc -->

## Overview

Given a [labelled](https://en.wikipedia.org/wiki/Graph_labeling) [directed graph](https://en.wikipedia.org/wiki/Directed_graph) and a [query expression](#introduction-to-ldggrep-queries), LDGGrep computes the minimal graph
representing all matching paths.

With experience, LDGGrep can be used to quickly reduce large, unwieldy graphs
to minimal, problem-focused graphs for further analysis and visualization.

## Ghidra extension

[Download a release](/../../releases)

The Ghidra extension includes graph models built from program data, a query
dialog with basic documentation, and a graph viewer.

- `RefGrep` uses the graph of Ghidra references. Nodes are addresses and edges
  are references like function calls and data indirections.
  ([example queries](ghidra/extension/ghidra_scripts/RefGrepExamples.txt))

- `RefGrepExt` demonstrates extending `RefGrep` with extra predicates.
  ([example queries](ghidra/extension/ghidra_scripts/RefGrepExtExamples.txt))

- `RefGrepWithDataStarts` is `RefGrep` except all reference sources, and not
  just functions, are added to the set of starting nodes.  That can be a large
  set, so queries should start with a selective first predicate.
  ([example queries](ghidra/extension/ghidra_scripts/RefGrepWithDataStartsExamples.txt))

- `RefGrepWithTypes` is `RefGrep` with extra references to Structure fields.
  Note, the first time a function is visited, it's decompiled - subsequent
  visits will be faster.
  ([example queries](ghidra/extension/ghidra_scripts/RefGrepWithTypesExamples.txt))

- `BlockGrep` extends `RefGrep` with basic blocks for control flow graph
  queries.
  ([example queries](ghidra/extension/ghidra_scripts/BlockGrepExamples.txt))

- `BaseGhidraGrep` is the abstract `GhidraScript` that all of the above inherit
  from.  It provides a query dialog with history and all the wiring to the
  engine, just add a model.

### Usage

Install the extension and restart Ghidra. (alternatively, add the bundle and
ghidra_scripts directory via the Bundle Manager)

From the script manager, select the LDGGrep category.

Running each script displays a dialog with a query textbox and a help window.
Clicking on a query expression in the help window populates the query box.

Clicking the "graph" button or pressing enter will submit the graph query.  If
parsing fails, an error message will show in Ghidra's console.  On success,
either no match is found and "no match" is written to Ghidra's console, or a
graph window will open containing the minimized graph of matching paths.

In the graph window, clicking on a node or edge jumps to the corresponding
location in the open program.  Selecting a set of nodes will highlight the
corresponding locations in the code browser.

Clicking the "mem" button in the query dialog will perform the same query, but
the stored nodes are presented in a table.  If the `sto` predicate doesn't
appear in the query expression, the table will be empty.

### Building the Ghidra extension (on Linux)

```bash
mvn package -Dghidra.version=11.4.2
ls -l ./ghidra/extension/target/ghidra_*_LDGGrep.zip
```

(Maven calls the Bash script [`ghidra/extension/build.sh`](ghidra/extension/build.sh), so for now building
the extension depends on Bash)

## LDGGrep tools

Tools that use LDGGrep and support classes for the development of new ones.

### Building tools

```bash
mvn package
ls -l ./tools/target/appassembler/bin
```

### `javagrep`

Disassemble jars and classes to generate a graph of references, then query it
from a repl.

e.g.  to find all call paths from LDGGrep's primary match method to the
`dk.brics` API:

```bash
./tools/target/appassembler/bin/javagrep ./ldggrep/target/ldggrep-*.jar
> </LDGMatcher::match/> (callx </jpleasu/>)* callx </dk\.brics/>
```

### `gfgrep`

A graph file grep built from the jgrapht-io parsers.

```bash
./tools/target/appassembler/bin/gfgrep ./tools/src/test/resources/test.dot
> /x/ </b/>
```

### `restgrep`

`restgrep` is a web service for querying graphs and
[`restclient.py`](tools/src/main/python/restclient.py) is a sample client.

```bash
# start the server w/ "showmatch" so that every matched graph shows in a window
./tools/target/appassembler/bin/restgrep -showmatch

# install client dependencies
pip3 install pydot networkx requests

# send a graph and do some queries
./tools/src/main/python/restclient.py
```

To change the listening port, use the `-port #` option to `restgrep`, and
change the URL in `restclient.py`.

## Introduction to LDGGrep queries

If the subject of "regular expressions" provokes you, LDGGrep is not for you.

Query expressions in LDGGrep are like [regular
expressions](https://en.wikipedia.org/wiki/Regular_expression), except instead
of matching a string composed of a sequence of a characters, we're matching
a [walk](https://en.wikipedia.org/wiki/Path_(graph_theory)#Directed_walk,_trail,_path)
in a directed graph composed of a sequence of nodes and edges.

### from regular expressions

LDGGrep uses `.`, `|`, `+`, `?`, `*`, `()`, and `{#,#}` in the exact same way
as regular expressions, but to go from characters to objects we need some more
syntax.

First, recall that in regular expressions (most) characters are matched with an
identical literal - so `a` matches `a`. For more power matching a character, we
have [character
classes](https://en.wikipedia.org/wiki/Regular_expression#Character_classes),
e.g. `[:alpha:]` matches `a` but not `1`.

With just a tiny bit of imagination, we might allow any
[predicate](https://en.wikipedia.org/wiki/Predicate_(mathematical_logic)) to
take the place of `[:alpha:]`.  With a stateless predicate, the semantics of
regular expressions are unchanged.  We could even replace each literal, like
`b`, with a predicate, like `[:is_b:]`.  It's predicates all the way down!

In LDGGrep, this idea of using predicates lets us generalize from characters to
objects.  (note: LDGGrep uses square brackets entirely differently, only the
idea is shared!)

### predicates

As noted above, `.` does the same thing in LDGGrep as in regular expressions -
it matches anything. E.g. the LDGGrep query `.{2,4}` matches all walks with
length from 2 to 4.

We often want to match objects by their name, so  there are two kinds of
predicates to match strings.  The _model_ of an graph provides the conversion
function to make strings of objects.

String literal predicates are enclosed in double quotes and regex predicates
are enclosed in forward slashes.  E.g. the LDGGrep query `"a" /b/` matches
walks of length 2 whose first edge is named `a` and second edge has a name that
contains `b`.

For direct access to objects in a predicate, there are Iverson
bracketed JavaScript expressions.  The object to be tested is named `x` in the
expression, and the expression is executed in the `with(x)` scope for more
succinct access to its members.

Iverson bracket predicates are enclosed in square brackets. E.g the LDGGrep
query `[x.fieldA]`, or equivalently `[fieldA]`, matches edges whose "fieldA"
member is (convertible to) true.

Finally, the model of a graph can provide "bareword" predicate _methods_,
annotated methods of the model that take an object and return true or false.
They're referred to as "bareword" because they're distinguished from the other
predicates by _not_ being enclosed in anything in particular.

### node predicates

In LDGGrep, node predicates are different from edge predicates because they _do
not advance_ in the graph during matching, they only filter.

Node predicates are enclosed in angle brackets.  What's inside the angle
brackets is a predicate as in the previous section. For example, the LDGGrep
query `<"x"> "b"` matches all walks of length one that start on a node with
name "x" and continue to an edge with name "b".

### grammar

```bnf
expr  ::= alt (";" alt)*
alt   ::= cat ("|" cat)*
cat   ::= atom atom*
atom  ::= "(" expr ")" | rep
rep   ::= pred ("{" NUMBER?, NUMBER? "}" | "*" | "+" )?
pred  ::= node_pred | edge_pred
edge_pred ::= pred_expr
node_pred ::= "<" pred_expr ">"
pred_expr ::= "!" pred_expr | DOUBLE_QUOTE STRING DOUBLE_QUOTE | "/" REGEX "/" | IDENTIFIER | "[" JAVASCRIPT "]" 
```

see [ldgpat.jj](dggrep/src/main/javacc/ldgpat.jj) for more detail.

## LDGGrep changelog

- ldggrep-1.2
  - update dependencies
  - add changes to build on mac
  - tweak grammar
  - remove graph variants
  - bump max nodes to 50000
- ldggrep-1.1
  - added start generators
  - added Ghidra script RefGrepWithTypes
- ldggrep-1.0
  - initial release
